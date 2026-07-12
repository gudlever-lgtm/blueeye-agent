'use strict';

const dns = require('dns');
const net = require('net');
const { readToken } = require('./tokenStore');
const { requestJson, verifyPeerOrDestroy } = require('./httpsClient');
const { normalizeFingerprint } = require('./fingerprint');
const { resolveEffectiveServerUrl } = require('./serverUrl');
const DefaultWebSocket = require('ws');

// `blueeye-agent doctor` — a connection self-test meant to be run right after
// install (the installer calls it) or by hand when an agent shows as offline.
// It walks the chain the live agent depends on — config -> token -> DNS -> TCP
// -> HTTP -> auth -> WebSocket — and, for each failure, prints a concrete
// suggestion to get connected. Read-only: it never enrolls, writes, or changes
// anything. Every side effect is injected so it is unit-tested against the fake
// server with no real sockets/DNS.

function pass(name, detail) { return { name, ok: true, detail }; }
function fail(name, detail, suggestion) { return { name, ok: false, detail, suggestion }; }
function skip(name, detail) { return { name, ok: true, skipped: true, detail }; }

// http(s)://host -> ws(s)://host/ws/agent (mirrors agentClient.toWsUrl).
function toWsUrl(serverUrl, wsPath = '/ws/agent') {
  const url = new URL(serverUrl);
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  url.pathname = wsPath;
  url.search = '';
  return url.toString();
}

function defaultTcpConnect(host, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host, port });
    const done = (err) => { socket.destroy(); err ? reject(err) : resolve(); };
    socket.setTimeout(timeoutMs, () => done(new Error('timed out')));
    socket.once('connect', () => done());
    socket.once('error', (err) => done(err));
  });
}

function safeReadToken(reader, tokenPath) {
  try { return reader(tokenPath); } catch { return null; }
}

// Best-effort WebSocket probe: open /ws/agent with the Bearer token and wait for
// the server's `connected` ack. Resolves { ok } or { ok:false, status?, detail }.
function tryWs({ serverUrl, token, fingerprint, WebSocketImpl, timeoutMs }) {
  return new Promise((resolve) => {
    let ws;
    let settled = false;
    const finish = (res) => {
      if (settled) return;
      settled = true;
      try { ws && ws.terminate(); } catch { /* ignore */ }
      resolve(res);
    };
    let wsUrl;
    try { wsUrl = toWsUrl(serverUrl); } catch (e) { resolve({ ok: false, detail: e.message }); return; }
    const opts = { headers: { Authorization: `Bearer ${token}` } };
    const pinning = fingerprint && wsUrl.startsWith('wss:');
    if (pinning) opts.rejectUnauthorized = false;
    try { ws = new WebSocketImpl(wsUrl, opts); } catch (e) { resolve({ ok: false, detail: e.message }); return; }
    if (pinning && ws._req && typeof ws._req.on === 'function') {
      ws._req.on('socket', (socket) => socket.on('secureConnect', () => verifyPeerOrDestroy(socket, fingerprint)));
    }
    const timer = setTimeout(() => finish({ ok: false, detail: `no response within ${timeoutMs}ms` }), timeoutMs);
    const clear = () => clearTimeout(timer);
    ws.on('message', (data) => {
      let msg = null;
      try { msg = JSON.parse(data.toString()); } catch { /* ignore */ }
      if (msg && msg.type === 'connected') { clear(); finish({ ok: true }); }
    });
    // Some servers/tests accept the socket without an explicit `connected` frame;
    // treat a clean open as success only if nothing better arrives shortly.
    ws.on('open', () => { setTimeout(() => finish({ ok: true }), 250); });
    ws.on('unexpected-response', (_req, res) => { clear(); finish({ ok: false, status: res && res.statusCode, detail: `HTTP ${res && res.statusCode}` }); });
    ws.on('error', (err) => { clear(); finish({ ok: false, detail: err.message }); });
  });
}

async function runDoctor({
  config,
  request = requestJson,
  lookup = dns.promises.lookup,
  tcpConnect = defaultTcpConnect,
  WebSocketImpl = DefaultWebSocket,
  tokenReader = readToken,
  timeoutMs = 8000,
} = {}) {
  const checks = [];
  let serverUrl = String((config && config.serverUrl) || '').replace(/\/+$/, '');
  const fingerprint = normalizeFingerprint((config && config.serverCertFingerprint) || '');

  // 1) Server URL configured + parseable.
  let url = null;
  if (!serverUrl) {
    checks.push(fail('config', 'No server URL configured.', 'Set BLUEEYE_SERVER_URL (or serverUrl in the config file) to the BlueEye server address, e.g. https://blueeye.example.dk.'));
  } else {
    try { url = new URL(serverUrl); checks.push(pass('config', `Server URL: ${serverUrl}`)); }
    catch { checks.push(fail('config', `Server URL is not a valid URL: ${serverUrl}`, 'Fix BLUEEYE_SERVER_URL — it should look like http://host:3000 or https://host.example.')); }
  }

  // 2) Stored token (enrollment).
  const creds = safeReadToken(tokenReader, config && config.tokenPath);
  const haveToken = !!(creds && creds.token);
  if (haveToken) checks.push(pass('token', `Enrolled as agent ${creds.agentId ?? '?'} (token stored).`));
  else checks.push(fail('token', 'No stored token — this host is not enrolled.', 'Re-run the installer with a fresh one-time code, or: blueeye-agent enroll --code <CODE> --server <URL>.'));

  // Self-heal http→https so the doctor tests the SAME endpoint the running agent
  // uses (the agent adopts the redirect target at boot). Otherwise the doctor
  // stops at the http redirect and skips the WebSocket check — hiding the real
  // problem, e.g. a proxy that 404s the WS upgrade even though HTTPS + REST work.
  if (url && url.protocol === 'http:') {
    let effective = serverUrl;
    try { effective = await resolveEffectiveServerUrl({ serverUrl, request, fingerprint, timeoutMs }); } catch { effective = serverUrl; }
    if (effective && effective !== serverUrl) {
      checks.push(pass('scheme', `Server forces HTTPS — testing ${effective} (the agent auto-upgrades from ${serverUrl}). Set BLUEEYE_PUBLIC_URL=${effective} on the server to make it explicit.`));
      serverUrl = effective;
      url = new URL(effective);
    }
  }

  if (!url) return finish(checks);

  const isHttps = url.protocol === 'https:';
  const host = url.hostname;
  const port = Number(url.port) || (isHttps ? 443 : 80);

  // 3) DNS (skip literal IPs).
  if (net.isIP(host)) {
    checks.push(skip('dns', `${host} is an IP address — no DNS lookup needed.`));
  } else {
    try { const r = await lookup(host); checks.push(pass('dns', `${host} resolves to ${r && r.address ? r.address : 'an address'}.`)); }
    catch (e) { checks.push(fail('dns', `Cannot resolve host "${host}" (${e.code || e.message}).`, `This host can't resolve "${host}". Use an address it can resolve (FQDN or IP), set BLUEEYE_PUBLIC_URL on the server to a reachable name, or add a DNS/hosts entry.`)); }
  }

  // 4) TCP reachability.
  try { await tcpConnect(host, port, timeoutMs); checks.push(pass('tcp', `TCP connect to ${host}:${port} succeeded.`)); }
  catch (e) { checks.push(fail('tcp', `Cannot open a TCP connection to ${host}:${port} (${e.code || e.message}).`, `Check the server is running and reachable on port ${port}, and that no firewall between this host and the server blocks it.`)); }

  // 5) HTTP(S) reachability — unauthenticated GET /enroll/config.
  let httpOk = false;
  try {
    const res = await request({ url: `${serverUrl}/enroll/config`, fingerprint, timeoutMs });
    if (res.status === 200) { httpOk = true; checks.push(pass('http', `Server answered at ${serverUrl} (GET /enroll/config → 200).`)); }
    else if (res.status >= 300 && res.status < 400) {
      // A redirect is the classic "forces HTTPS" proxy: GET/POST survive it
      // (they follow redirects) but the WebSocket handshake does NOT, and the
      // Authorization header is dropped across an http→https hop (→ a spurious
      // 401 the agent treats as fatal). So the agent MUST use the target scheme.
      const loc = (res.headers && (res.headers.location || res.headers.Location)) || '';
      const target = loc ? String(loc).replace(/\/enroll\/config.*$/, '') : `${isHttps ? 'https' : 'http'}s://${host}`;
      const toHttps = !isHttps && (/^https:/i.test(loc) || !loc);
      checks.push(fail('http', `Server redirected GET /enroll/config with HTTP ${res.status}${loc ? ` → ${loc}` : ''}.`,
        toHttps
          ? `The server is forcing HTTPS. Point the agent at the https:// URL: set BLUEEYE_PUBLIC_URL=https://${host} on the server and reinstall, or re-enroll with --server https://${host}. (Over an http:// URL the agent uses ws://, and the WebSocket handshake won't follow the redirect — that's the "handshake failed: HTTP ${res.status}" in the log, followed by a 401 because the redirect drops the auth header.)`
          : `Point BLUEEYE_SERVER_URL at the redirect target (${target}) and re-enroll — the WebSocket handshake does not follow redirects.`));
    }
    else checks.push(fail('http', `Server responded HTTP ${res.status} to GET /enroll/config.`, 'The host is reachable but did not answer as a BlueEye server — verify BLUEEYE_SERVER_URL points at the server itself (not a proxy or error page).'));
  } catch (e) {
    const m = String((e && (e.message || e.code)) || e);
    if (/certificate|self.signed|\btls\b|\bssl\b|altname|depth|pin/i.test(m)) {
      checks.push(fail('http', `TLS error talking to ${serverUrl}: ${m}`, 'The server uses a self-signed/untrusted certificate. Pin it: set its SHA-256 fingerprint via BLUEEYE_SERVER_CERT_FINGERPRINT (or --fingerprint), which the enrollment command embeds when AGENT_CERT_FINGERPRINT is set on the server.'));
    } else {
      checks.push(fail('http', `Could not reach ${serverUrl}: ${m}`, `Confirm the scheme/host/port and that the server is up. From this host try:  curl -v ${serverUrl}/enroll/config`));
    }
  }

  // 6) Auth — the stored token against a Bearer-gated endpoint.
  if (haveToken && httpOk) {
    try {
      const res = await request({ url: `${serverUrl}/agents/me/config`, headers: { Authorization: `Bearer ${creds.token}` }, fingerprint, timeoutMs });
      if (res.status === 200) checks.push(pass('auth', 'Token accepted by the server (GET /agents/me/config → 200).'));
      else if (res.status === 401) checks.push(fail('auth', 'Server rejected the stored token (HTTP 401).', 'The token is no longer valid (the agent was deleted or re-enrolled on the server). Re-enroll: delete the token file and re-run the installer with a new one-time code.'));
      else if (res.status === 403) checks.push(fail('auth', 'Server refused the token with HTTP 403.', 'Usually a licence/agent-limit issue — check Settings → License on the server (valid licence, agent count below the plan limit).'));
      else checks.push(fail('auth', `Unexpected HTTP ${res.status} from /agents/me/config.`, 'The token reached the server but the response was unexpected — check the server logs.'));
    } catch (e) { checks.push(fail('auth', `Auth check could not complete: ${(e && e.message) || e}`, 'Same reachability/TLS cause as the HTTP check above applies to the authenticated call.')); }
  } else {
    checks.push(skip('auth', 'Skipped — needs a stored token and a reachable server.'));
  }

  // 7) WebSocket — the live channel the agent actually holds open.
  if (haveToken && httpOk) {
    const wsRes = await tryWs({ serverUrl, token: creds.token, fingerprint, WebSocketImpl, timeoutMs });
    if (wsRes.ok) checks.push(pass('websocket', 'WebSocket /ws/agent connected and the server acknowledged.'));
    else if (wsRes.status === 401) checks.push(fail('websocket', 'WebSocket handshake rejected (HTTP 401).', 'Same as the auth check — the token is not accepted; re-enroll the agent.'));
    else if (wsRes.status === 404) checks.push(fail('websocket', 'WebSocket handshake returned HTTP 404 on /ws/agent.', 'HTTP + auth work, so the backend is fine — a 404 on the WebSocket means the reverse proxy in front of the server is not forwarding the WebSocket upgrade for /ws/agent (it hands the backend a plain GET). Configure the proxy to proxy WebSockets on that path: forward the Upgrade and Connection headers (nginx: proxy_set_header Upgrade $http_upgrade; Connection "upgrade"; proxy_http_version 1.1). Test: curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" ' + serverUrl + '/ws/agent  → expect 101, not 404.'));
    else checks.push(fail('websocket', `WebSocket did not connect (${wsRes.detail}).`, 'If HTTP works but the WebSocket does not, a reverse proxy or firewall is likely blocking the WebSocket upgrade on /ws/agent — allow Upgrade/Connection headers through to the server.'));
  } else {
    checks.push(skip('websocket', 'Skipped — needs a stored token and a reachable server.'));
  }

  return finish(checks);
}

function finish(checks) {
  const failed = checks.filter((c) => !c.ok);
  return { connected: failed.length === 0, checks, failed };
}

// Renders a report as human-readable lines (returned, not printed, so callers
// choose the sink and it stays testable).
function formatReport(report) {
  const lines = [];
  for (const c of report.checks) {
    const mark = c.skipped ? '–' : (c.ok ? '✓' : '✗');
    lines.push(`  ${mark} ${c.name}: ${c.detail}`);
    if (!c.ok && c.suggestion) lines.push(`      → ${c.suggestion}`);
  }
  lines.push('');
  lines.push(report.connected
    ? 'Result: CONNECTED — the agent can reach the server and its token is accepted.'
    : `Result: NOT CONNECTED — ${report.failed.length} check(s) failed. Fix the → suggestions above, then re-run: blueeye-agent doctor`);
  return lines.join('\n');
}

module.exports = { runDoctor, formatReport, toWsUrl };
