'use strict';

const { EventEmitter } = require('events');
const DefaultWebSocket = require('ws');
const { computeBackoff } = require('./backoff');
const { verifyPeerOrDestroy } = require('./httpsClient');
const { normalizeFingerprint } = require('./fingerprint');
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
//   - keeps the connection alive with an application-level heartbeat,
//   - emits 'command' for server -> agent commands,
//   - reconnects with exponential backoff on a dropped connection,
//   - on a 401 (token rejected) it fails HARD and does NOT reconnect or
//     re-enroll — it emits 'fatal' and stays down until restarted.
//
// Events: 'open', 'connected', 'command', 'close', 'fatal'.
function createAgentClient({
  serverUrl,
  token,
  logger,
  wsPath = '/ws/agent',
  heartbeatMs = 15000,
  backoff = {},
  WebSocketImpl = DefaultWebSocket,
  certFingerprint = '',
}) {
  const wsUrl = toWsUrl(serverUrl, wsPath);
  const pin = normalizeFingerprint(certFingerprint);
  const emitter = new EventEmitter();

  let ws = null;
  let heartbeatTimer = null;
  let reconnectTimer = null;
  let attempts = 0;
  let stopped = false;
  let fatal = false;

  function startHeartbeat() {
    stopHeartbeat();
    heartbeatTimer = setInterval(() => {
      if (ws && ws.readyState === ws.OPEN) {
        try {
          ws.send(JSON.stringify({ type: 'heartbeat', ts: Date.now() }));
        } catch {
          /* will be handled by error/close */
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

  function scheduleReconnect() {
    attempts += 1;
    const delay = computeBackoff(attempts, backoff);
    logger.info(`WebSocket reconnect in ${delay}ms (attempt ${attempts}).`);
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      connect();
    }, delay);
  }

  function failFatal(reason) {
    fatal = true;
    stopHeartbeat();
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

  function connect() {
    if (stopped || fatal) return;

    let settled = false;
    const ended = (shouldReconnect) => {
      if (settled) return;
      settled = true;
      stopHeartbeat();
      if (!stopped && !fatal && shouldReconnect) scheduleReconnect();
    };

    logger.info(`Connecting to ${wsUrl} ...`);
    // Declare our wire-contract version so the server can detect a mismatch. The
    // server echoes its own in the `connected` frame; neither side treats a
    // mismatch as fatal.
    const wsOpts = { headers: { Authorization: `Bearer ${token}`, 'X-BlueEye-Protocol': String(PROTOCOL_VERSION) } };
    const pinning = pin && wsUrl.startsWith('wss:');
    // Pin by verifying the exact leaf cert on secureConnect (Node skips
    // checkServerIdentity when rejectUnauthorized is false), before the upgrade
    // request — which carries the token — is sent.
    if (pinning) wsOpts.rejectUnauthorized = false;
    ws = new WebSocketImpl(wsUrl, wsOpts);
    if (pinning) {
      // We disabled the default chain check to pin the exact leaf on
      // secureConnect. If we can't attach that verifier (e.g. the ws internals
      // changed in a future version), fail CLOSED — running with
      // rejectUnauthorized:false and no pin would mean no TLS validation at all.
      if (ws._req && typeof ws._req.on === 'function') {
        ws._req.on('socket', (socket) => socket.on('secureConnect', () => verifyPeerOrDestroy(socket, pin)));
      } else {
        try { ws.terminate(); } catch { /* ignore */ }
        failFatal('cannot attach certificate pin verifier (ws internals changed); refusing to connect unpinned');
        return;
      }
    }

    ws.on('open', () => {
      attempts = 0;
      logger.info('WebSocket connection established.');
      startHeartbeat();
      emitter.emit('open');
    });

    ws.on('message', (data) => {
      let msg;
      try {
        msg = JSON.parse(data.toString());
      } catch {
        return;
      }
      if (msg && msg.type === 'command') {
        emitter.emit('command', msg.command);
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
        failFatal('WebSocket authentication rejected (HTTP 401)');
        ended(false);
      } else {
        logger.warn(`WebSocket handshake failed: HTTP ${status}.`);
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
    on: emitter.on.bind(emitter),
    once: emitter.once.bind(emitter),
    get isFatal() {
      return fatal;
    },
  };
}

module.exports = { createAgentClient, toWsUrl };
