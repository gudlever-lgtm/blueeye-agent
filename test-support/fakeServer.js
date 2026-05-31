'use strict';

// A minimal, contract-compatible stand-in for blueeye-server, used by the
// agent's integration tests. It mirrors the real endpoints from prompts 4-5:
//   POST /agents/enroll        -> { agentId, token } | 401
//   POST /agents/results       -> 201 { inserted }   | 401 (Bearer token)
//   WS   /ws/agent             -> Bearer/query token; rejects with 401
// The real server needs MySQL, which isn't available here, so the agent is
// exercised against this faithful stub.

const http = require('http');
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
  const sockets = new Set();

  const server = http.createServer(async (req, res) => {
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

    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not Found' }));
  });

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
        url: `http://127.0.0.1:${port}`,
        enrollments,
        receivedResults,
        receivedCapabilities,
        socketCount: () => sockets.size,
        sendCommandToAll,
        dropAllSockets,
        addValidToken: (t) => validTokens.add(t),
        close: () =>
          new Promise((done) => {
            dropAllSockets();
            wss.close();
            server.close(done);
          }),
      });
    });
  });
}

module.exports = { startFakeServer };
