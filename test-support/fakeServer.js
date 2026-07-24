'use strict';

// A minimal, contract-compatible stand-in for blueeye-server, used by the
// agent's integration tests. It mirrors the real endpoints from prompts 4-5:
//   POST /agents/enroll        -> { agentId, token } | 401
//   POST /agents/results       -> 201 { inserted }   | 401 (Bearer token)
//   WS   /ws/agent             -> Bearer/query token; rejects with 401
// The real server needs MySQL, which isn't available here, so the agent is
// exercised against this faithful stub.

const http = require('http');
const https = require('https');
const { WebSocketServer } = require('ws');

function readJson(req) {
  return new Promise((resolve) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
    });
    req.on('end', () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        resolve({});
      }
    });
  });
}

function bearer(req, url) {
  const header = req.headers.authorization || '';
  if (header.startsWith('Bearer ')) return header.slice(7);
  return url ? url.searchParams.get('token') : null;
}

function startFakeServer(options = {}) {
  const acceptCode = options.acceptCode || 'good-code';
  const issuedToken = options.issuedToken || 'enrolled-token';
  const issuedAgentId = options.issuedAgentId ?? 101;
  // Tokens the server accepts for authenticated calls.
  const validTokens = new Set(options.validTokens || [issuedToken]);

  const enrollments = [];
  const receivedResults = [];
  const receivedCapabilities = [];
  const receivedDiscovery = [];
  const receivedSpeedtests = [];
  const monitorConfig = options.monitorConfig || { source: 'proc' };
  const sockets = new Set();

  // Agent -> server WebSocket frames (acks, heartbeats), so tests can assert the
  // agent replied to a command. waitForWsMessage resolves for the first match.
  const receivedWsMessages = [];
  const wsWaiters = [];
  function pushWsMessage(msg) {
    receivedWsMessages.push(msg);
    for (let i = wsWaiters.length - 1; i >= 0; i -= 1) {
      if (wsWaiters[i].pred(msg)) {
        wsWaiters[i].resolve(msg);
        wsWaiters.splice(i, 1);
      }
    }
  }
  function waitForWsMessage(pred) {
    const found = receivedWsMessages.find(pred);
    if (found) return Promise.resolve(found);
    return new Promise((resolve) => wsWaiters.push({ pred, resolve }));
  }

  const requestHandler = async (req, res) => {
    // Companion config (used by the agent to discover URL + fingerprint).
    if (req.method === 'GET' && req.url === '/enroll/config') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ serverUrl: options.publicUrl || '', certFingerprint: options.certFingerprint || null }));
      return;
    }

    // Self-update downloads (unauthenticated, like the real server): the legacy
    // source bundle, and the signed release with its verification headers.
    // Provide the bytes via options.agentSource (Buffer) / options.agentRelease
    // ({ buffer, version, signature, manifestB64 }); 404 when unset.
    if (req.method === 'GET' && req.url === '/enroll/agent-source.tgz') {
      const src = options.agentSource;
      if (!src) { res.writeHead(404, { 'content-type': 'application/json' }); res.end(JSON.stringify({ error: 'No agent source' })); return; }
      res.writeHead(200, { 'content-type': 'application/gzip', 'content-length': String(src.length) });
      res.end(src);
      return;
    }
    if (req.method === 'GET' && req.url === '/enroll/agent-release.tgz') {
      const rel = options.agentRelease;
      if (!rel) { res.writeHead(404, { 'content-type': 'application/json' }); res.end(JSON.stringify({ error: 'No signed release' })); return; }
      res.writeHead(200, {
        'content-type': 'application/gzip',
        'content-length': String(rel.buffer.length),
        'x-release-version': rel.version,
        'x-release-signature': rel.signature,
        'x-release-manifest': rel.manifestB64,
      });
      res.end(rel.buffer);
      return;
    }
    if (req.method === 'POST' && req.url === '/agents/enroll') {
      const body = await readJson(req);
      enrollments.push(body);
      if (body.code !== acceptCode) {
        res.writeHead(401, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid enrollment code' }));
        return;
      }
      validTokens.add(issuedToken);
      res.writeHead(201, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ agentId: issuedAgentId, token: issuedToken }));
      return;
    }

    if (req.method === 'POST' && req.url === '/agents/results') {
      const token = bearer(req);
      if (!token || !validTokens.has(token)) {
        res.writeHead(401, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid agent token' }));
        return;
      }
      const body = await readJson(req);
      receivedResults.push({ token, results: body.results });
      res.writeHead(201, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ inserted: Array.isArray(body.results) ? body.results.length : 0 }));
      return;
    }

    if (req.method === 'GET' && req.url === '/agents/me/config') {
      const token = bearer(req);
      if (!token || !validTokens.has(token)) {
        res.writeHead(401, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid agent token' }));
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ agentId: issuedAgentId, monitorConfig }));
      return;
    }

    if (req.method === 'POST' && req.url === '/agents/me/capabilities') {
      const token = bearer(req);
      if (!token || !validTokens.has(token)) {
        res.writeHead(401, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid agent token' }));
        return;
      }
      const body = await readJson(req);
      receivedCapabilities.push(body.capabilities);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ agentId: issuedAgentId, capabilities: body.capabilities }));
      return;
    }

    if (req.method === 'POST' && req.url === '/agents/discovery-results') {
      const token = bearer(req);
      if (!token || !validTokens.has(token)) {
        res.writeHead(401, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid agent token' }));
        return;
      }
      const body = await readJson(req);
      receivedDiscovery.push({ token, body });
      res.writeHead(202, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, ingested: Array.isArray(body.candidates) ? body.candidates.length : 0 }));
      return;
    }

    // Speed-test bandwidth + result endpoints (agent token).
    if (req.method === 'GET' && req.url.startsWith('/speedtest/download')) {
      const u = new URL(req.url, 'http://localhost');
      const token = bearer(req, u);
      if (!token || !validTokens.has(token)) { res.writeHead(401); res.end(); return; }
      const bytes = Math.min(Number(u.searchParams.get('bytes')) || 1024, 4 * 1024 * 1024);
      res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': String(bytes) });
      res.end(Buffer.alloc(bytes, 0));
      return;
    }
    if (req.method === 'POST' && req.url === '/speedtest/upload') {
      const token = bearer(req);
      if (!token || !validTokens.has(token)) { res.writeHead(401); res.end(); return; }
      let received = 0;
      req.on('data', (c) => { received += c.length; });
      req.on('end', () => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ bytes: received })); });
      return;
    }
    if (req.method === 'POST' && req.url === '/speedtest/results') {
      const token = bearer(req);
      if (!token || !validTokens.has(token)) { res.writeHead(401); res.end(); return; }
      const body = await readJson(req);
      receivedSpeedtests.push(body.result);
      res.writeHead(201, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ id: receivedSpeedtests.length }));
      return;
    }

    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not Found' }));
  };

  const server = options.tls
    ? https.createServer(options.tls, requestHandler)
    : http.createServer(requestHandler);

  const wss = new WebSocketServer({ noServer: true });
  server.on('upgrade', (req, socket, head) => {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname !== '/ws/agent') {
      socket.destroy();
      return;
    }
    const token = bearer(req, url);
    if (!token || !validTokens.has(token)) {
      socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      sockets.add(ws);
      ws.on('close', () => sockets.delete(ws));
      ws.on('message', (data) => {
        let msg;
        try { msg = JSON.parse(data.toString()); } catch { return; }
        pushWsMessage(msg);
      });
      ws.send(JSON.stringify({ type: 'connected', agentId: issuedAgentId }));
    });
  });

  function sendCommandToAll(command) {
    let sent = 0;
    for (const ws of sockets) {
      if (ws.readyState === ws.OPEN) {
        ws.send(JSON.stringify({ type: 'command', command }));
        sent += 1;
      }
    }
    return sent;
  }

  function dropAllSockets() {
    for (const ws of sockets) ws.terminate();
  }

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({
        port,
        url: `${options.tls ? 'https' : 'http'}://127.0.0.1:${port}`,
        enrollments,
        receivedResults,
        receivedCapabilities,
        receivedDiscovery,
        receivedSpeedtests,
        socketCount: () => sockets.size,
        sendCommandToAll,
        dropAllSockets,
        receivedWsMessages,
        waitForWsMessage,
        addValidToken: (t) => validTokens.add(t),
        close: () =>
          new Promise((done) => {
            dropAllSockets();
            wss.close();
            // Force-close any lingering connections (e.g. undici keep-alive
            // sockets from the agent's fetch calls) so server.close() resolves
            // instead of waiting them out — otherwise `node --test` hangs.
            if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
            server.close(done);
          }),
      });
    });
  });
}

module.exports = { startFakeServer };
