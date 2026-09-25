'use strict';

const { EventEmitter } = require('events');
const DefaultWebSocket = require('ws');
const { computeBackoff } = require('./backoff');
const { verifyPeerOrDestroy } = require('./httpsClient');
const { normalizeFingerprints } = require('./fingerprint');
const { PROTOCOL_VERSION } = require('./protocol');

// Derives the WebSocket URL from the HTTP server URL (http->ws, https->wss).
function toWsUrl(serverUrl, wsPath) {
  const url = new URL(serverUrl);
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  url.pathname = wsPath;
  url.search = '';
  return url.toString();
}

// Manages the live WebSocket to /ws/agent:
//   - sends the token in the Authorization header at connect,
//   - keeps the connection alive with an application-level heartbeat AND a
//     WebSocket ping, and re-dials when nothing comes back (see below),
//   - emits 'command' for server -> agent commands,
//   - reconnects with exponential backoff on a dropped connection, rotating
//     through `serverUrls` so one dead DNS name or proxy is not the end of it,
//   - on a 401 (token rejected) it stops reporting and re-dials on a long,
//     quiet timer (`authRetryMs`) — it never re-enrolls by itself. With
//     authRetryMs = 0 a 401 is terminal, as it used to be.
//
// Liveness is the part that is easy to get wrong. The heartbeat below is a
// SEND, and a send says nothing about whether anything is still listening: a
// half-open connection (a NAT entry that expired, a firewall that stopped
// forwarding, a load balancer that went away) accepts writes into a void until
// the kernel gives up retransmitting, which on Linux is 10-15 minutes. So every
// heartbeat also sends a WebSocket ping — the server's ws answers it without
// any application code — and anything arriving from the server (pong, ping,
// frame) refreshes a deadline. Nothing for `staleConnectionMs` means the
// connection is gone whatever the socket thinks, and we terminate it and
// re-dial through the normal backoff.
//
// Events: 'open', 'connected', 'command', 'close', 'stale', 'auth-rejected',
// 'server-url', 'fatal'.
function createAgentClient({
  serverUrl,
  serverUrls = [],
  token,
  logger,
  wsPath = '/ws/agent',
  heartbeatMs = 15000,
  backoff = {},
  WebSocketImpl = DefaultWebSocket,
  certFingerprint = '',
  // Nothing heard from the server for this long on an open socket = dead.
  // Defaults to three heartbeats (and at least 30 s), so one lost packet is
  // never enough. 0 disables the check.
  staleConnectionMs = 0,
  // TCP keepalive on the underlying socket. 0 disables it.
  socketKeepAliveMs = 30000,
  // How long to wait before re-dialling after the server rejected the token.
  // 0 = treat a 401 as terminal.
  authRetryMs = 0,
}) {
  const pins = normalizeFingerprints(certFingerprint);
  const emitter = new EventEmitter();
  // Every way in to the same server, in order. The first is what enrollment and
  // the pins mean by "the server"; the rest are alternatives tried only when a
  // connection cannot be established.
  const urls = [];
  for (const candidate of [serverUrl, ...(Array.isArray(serverUrls) ? serverUrls : [serverUrls])]) {
    const url = String(candidate || '').trim().replace(/\/+$/, '');
    if (url && !urls.includes(url)) urls.push(url);
  }
  if (!urls.length) throw new Error('createAgentClient requires a serverUrl');
  const staleMs = staleConnectionMs > 0 ? staleConnectionMs : 0;

  let ws = null;
  let heartbeatTimer = null;
  let reconnectTimer = null;
  let staleTimer = null;
  let attempts = 0;
  let stopped = false;
  let fatal = false;
  // Index into `urls`. Sticky: a URL that worked is kept until it stops
  // working, so a fleet does not drift onto the spare ingress and stay there.
  let urlIndex = 0;

  function activeServerUrl() {
    return urls[urlIndex % urls.length];
  }

  function startHeartbeat() {
    stopHeartbeat();
    heartbeatTimer = setInterval(() => {
      if (ws && ws.readyState === ws.OPEN) {
        try {
          ws.send(JSON.stringify({ type: 'heartbeat', ts: Date.now() }));
        } catch {
          /* will be handled by error/close */
        }
        // The protocol-level ping the stale check listens for the answer to.
        // `ws` replies to it in the server's socket layer, so it works whatever
        // the application is doing.
        try {
          if (typeof ws.ping === 'function') ws.ping();
        } catch {
          /* same */
        }
      }
    }, heartbeatMs);
  }

  function stopHeartbeat() {
    if (heartbeatTimer) {
      clearInterval(heartbeatTimer);
      heartbeatTimer = null;
    }
  }

  // Refreshed by anything arriving from the server. Firing means the socket is
  // open but the peer is gone.
  function markAlive() {
    if (!staleMs || stopped || fatal) return;
    if (staleTimer) clearTimeout(staleTimer);
    staleTimer = setTimeout(() => {
      staleTimer = null;
      const seconds = Math.round(staleMs / 1000);
      logger.warn(`Nothing heard from the server in ${seconds}s on an open connection; treating it as dead and re-dialling.`);
      emitter.emit('stale', { staleMs, serverUrl: activeServerUrl() });
      // terminate(), not close(): a close handshake needs the peer to answer,
      // and the whole point is that it no longer does.
      try {
        if (ws) ws.terminate();
      } catch {
        /* ignore */
      }
    }, staleMs);
    if (staleTimer.unref) staleTimer.unref();
  }

  function stopStaleCheck() {
    if (staleTimer) {
      clearTimeout(staleTimer);
      staleTimer = null;
    }
  }

  function scheduleReconnect(delayMs) {
    attempts += 1;
    const delay = Number.isFinite(delayMs) && delayMs > 0 ? delayMs : computeBackoff(attempts, backoff);
    logger.info(`WebSocket reconnect in ${delay}ms (attempt ${attempts}).`);
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      connect();
    }, delay);
    if (reconnectTimer.unref) reconnectTimer.unref();
  }

  // Moves to the next way in to the server. Only called when a connection could
  // not be ESTABLISHED — a connection that opened and later dropped says nothing
  // bad about the URL it used.
  function rotateServerUrl() {
    if (urls.length < 2) return;
    urlIndex = (urlIndex + 1) % urls.length;
    const next = activeServerUrl();
    logger.warn(`Trying the next configured server URL: ${next}.`);
    emitter.emit('server-url', next);
  }

  function failFatal(reason) {
    fatal = true;
    stopHeartbeat();
    stopStaleCheck();
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    logger.error(
      `Fatal: ${reason}. The agent will NOT reconnect or re-enroll automatically; manual intervention required.`
    );
    try {
      if (ws) ws.terminate();
    } catch {
      /* ignore */
    }
    emitter.emit('fatal', reason);
  }

  // The token was refused. Terminal only when no retry interval is configured:
  // a revoked token deserves to stay down, but the same 401 arrives from a
  // server restored from backup or one whose tokens were re-provisioned, and
  // that must not cost the whole fleet its way back. We never re-enroll here —
  // only re-dial, quietly, until someone fixes the token or revokes the agent
  // for good.
  function rejectAuth(reason) {
    stopHeartbeat();
    stopStaleCheck();
    if (authRetryMs <= 0) {
      failFatal(reason);
      return false;
    }
    logger.error(
      `${reason}. Not re-enrolling; retrying in ${Math.round(authRetryMs / 1000)}s in case the server's view of this token changes.`
    );
    emitter.emit('auth-rejected', { reason, retryInMs: authRetryMs });
    return true;
  }

  function connect() {
    if (stopped || fatal) return;

    const base = activeServerUrl();
    const wsUrl = toWsUrl(base, wsPath);
    // Did this attempt ever reach an open socket? Decides whether a failure is
    // the URL's fault (rotate) or just a drop (re-dial the same one).
    let opened = false;
    let settled = false;
    const ended = (shouldReconnect, delayMs) => {
      if (settled) return;
      settled = true;
      stopHeartbeat();
      stopStaleCheck();
      if (!opened) rotateServerUrl();
      if (!stopped && !fatal && shouldReconnect) scheduleReconnect(delayMs);
    };

    logger.info(`Connecting to ${wsUrl} ...`);
    // Declare our wire-contract version so the server can detect a mismatch. The
    // server echoes its own in the `connected` frame; neither side treats a
    // mismatch as fatal.
    // Cap inbound frames at 1 MB. `ws` defaults to 100 MB, which a malicious or
    // compromised server could use to push a huge frame straight into JSON.parse
    // below and pressure the agent's memory. Server commands are tiny, so 1 MB is
    // generous. (The server enforces the same cap on the agent->server direction.)
    const wsOpts = {
      headers: { Authorization: `Bearer ${token}`, 'X-BlueEye-Protocol': String(PROTOCOL_VERSION) },
      maxPayload: 1024 * 1024,
    };
    const pinning = pins.length && wsUrl.startsWith('wss:');
    // Pin by verifying the exact leaf cert on secureConnect (Node skips
    // checkServerIdentity when rejectUnauthorized is false), before the upgrade
    // request — which carries the token — is sent. Several pins may be
    // configured (certificate renewal); any of them is accepted.
    if (pinning) wsOpts.rejectUnauthorized = false;
    ws = new WebSocketImpl(wsUrl, wsOpts);
    if (pinning) {
      // We disabled the default chain check to pin the exact leaf on
      // secureConnect. If we can't attach that verifier (e.g. the ws internals
      // changed in a future version), fail CLOSED — running with
      // rejectUnauthorized:false and no pin would mean no TLS validation at all.
      if (ws._req && typeof ws._req.on === 'function') {
        ws._req.on('socket', (socket) => socket.on('secureConnect', () => verifyPeerOrDestroy(socket, pins)));
      } else {
        try { ws.terminate(); } catch { /* ignore */ }
        failFatal('cannot attach certificate pin verifier (ws internals changed); refusing to connect unpinned');
        return;
      }
    }

    ws.on('open', () => {
      opened = true;
      attempts = 0;
      logger.info('WebSocket connection established.');
      // Let the kernel notice a dead path too. Independent of the stale check
      // above, and cheap.
      if (socketKeepAliveMs > 0 && ws._socket && typeof ws._socket.setKeepAlive === 'function') {
        try { ws._socket.setKeepAlive(true, socketKeepAliveMs); } catch { /* ignore */ }
      }
      startHeartbeat();
      markAlive();
      emitter.emit('open');
    });

    // Anything from the peer proves it is still there.
    ws.on('pong', markAlive);
    ws.on('ping', markAlive);

    ws.on('message', (data) => {
      markAlive();
      let msg;
      try {
        msg = JSON.parse(data.toString());
      } catch {
        return;
      }
      if (msg && msg.type === 'command') {
        emitter.emit('command', msg.command);
      } else if (msg && msg.type === 'transaction_config') {
        // Server-pushed transaction-test config (active tests for this agent).
        emitter.emit('transaction-config', Array.isArray(msg.tests) ? msg.tests : []);
      } else if (msg && msg.type === 'connected') {
        // Protocol-version check: warn (never fail) if the server speaks a
        // different wire-contract version than we do.
        const serverProtocol = Number(msg.protocolVersion) || 1;
        if (serverProtocol !== PROTOCOL_VERSION) {
          logger.warn(`Server protocol v${serverProtocol} != agent v${PROTOCOL_VERSION}; continuing (the server stays backward-compatible).`);
        }
        emitter.emit('connected', msg);
      }
    });

    // Handshake rejected by the server (e.g. invalid token -> 401).
    ws.on('unexpected-response', (_req, res) => {
      const status = res && res.statusCode;
      if (status === 401) {
        // A 401 is an ANSWER: this URL reaches the server, it just does not like
        // the token. Rotating away from it would only hide that.
        opened = true;
        const retrying = rejectAuth('WebSocket authentication rejected (HTTP 401)');
        ended(retrying, authRetryMs);
      } else {
        logger.warn(`WebSocket handshake failed: HTTP ${status}.`);
        // Same reasoning: an HTTP status came back, so the URL is not the problem.
        opened = true;
        ended(true);
      }
    });

    ws.on('error', (err) => {
      logger.warn(`WebSocket error: ${err.message}`);
      ended(true);
    });

    ws.on('close', (code) => {
      logger.info(`WebSocket closed (code ${code}).`);
      emitter.emit('close', code);
      ended(true);
    });
  }

  return {
    start() {
      stopped = false;
      fatal = false;
      attempts = 0;
      connect();
    },
    stop() {
      stopped = true;
      stopHeartbeat();
      stopStaleCheck();
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      if (ws) {
        try {
          ws.close();
        } catch {
          /* ignore */
        }
      }
    },
    send(obj) {
      if (ws && ws.readyState === ws.OPEN) {
        ws.send(JSON.stringify(obj));
        return true;
      }
      return false;
    },
    // Is the socket open right now? What send() checks before it writes, so a
    // caller can skip work whose only output would be dropped (and so the
    // evidence snapshot can say "connected: yes" instead of "unknown").
    isConnected() {
      return !!(ws && ws.readyState === ws.OPEN);
    },
    // Which of the configured URLs the agent is using right now, so REST calls
    // follow the live channel instead of talking to a name that stopped working.
    activeServerUrl,
    serverUrls: urls.slice(),
    on: emitter.on.bind(emitter),
    once: emitter.once.bind(emitter),
    get isFatal() {
      return fatal;
    },
  };
}

module.exports = { createAgentClient, toWsUrl };
