'use strict';

// The three ways an agent loses its server and cannot get it back on its own:
// a connection that is open but dead, a token the server refuses, and one way in
// that stopped working. Each is tested here against the real client with a fake
// socket, because every one of them ends with a fleet nobody can reach.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('events');

const { createAgentClient } = require('../src/agentClient');

// Stand-in for the `ws` client. Records pings and terminate() so a test can see
// what the liveness logic did, and exposes a fake socket for the keepalive.
class FakeWS extends EventEmitter {
  constructor(url, opts) {
    super();
    this.url = url;
    this.opts = opts;
    this.readyState = 1;
    this.OPEN = 1;
    this.pings = 0;
    this.terminated = 0;
    this.closed = 0;
    this.keepAlive = null;
    this._socket = {
      setKeepAlive: (on, ms) => { this.keepAlive = { on, ms }; },
    };
    FakeWS.last = this;
    FakeWS.urls.push(url);
  }
  send() {}
  ping() { this.pings += 1; }
  close() { this.closed += 1; }
  terminate() { this.terminated += 1; }
}
FakeWS.urls = [];

const quietLogger = () => {
  const lines = [];
  return {
    lines,
    logger: {
      info: (m) => lines.push(m),
      warn: (m) => lines.push(m),
      error: (m) => lines.push(m),
    },
  };
};

const tick = () => new Promise((resolve) => setTimeout(resolve, 5));

test('an open connection the server stopped answering is terminated and re-dialled', async () => {
  FakeWS.urls = [];
  const { logger, lines } = quietLogger();
  const client = createAgentClient({
    serverUrl: 'http://server.test',
    token: 'tok',
    logger,
    WebSocketImpl: FakeWS,
    heartbeatMs: 10,
    staleConnectionMs: 40,
    backoff: { baseMs: 5, maxMs: 5 },
  });
  const stale = [];
  client.on('stale', (info) => stale.push(info));
  client.start();
  try {
    const first = FakeWS.last;
    first.emit('open');
    // The heartbeat pings, so the check has something to wait for an answer to.
    await new Promise((resolve) => setTimeout(resolve, 30));
    assert.ok(first.pings > 0, 'the heartbeat also sends a WebSocket ping');
    assert.equal(first.terminated, 0, 'not yet stale');
    // Nothing comes back at all.
    await new Promise((resolve) => setTimeout(resolve, 60));
    assert.equal(first.terminated, 1, 'a socket nobody answers is terminated');
    assert.equal(stale.length, 1);
    assert.equal(stale[0].staleMs, 40);
    assert.ok(lines.some((l) => /Nothing heard from the server/.test(l)));
  } finally {
    client.stop();
  }
});

test('a pong keeps the connection alive', async () => {
  FakeWS.urls = [];
  const { logger } = quietLogger();
  const client = createAgentClient({
    serverUrl: 'http://server.test',
    token: 'tok',
    logger,
    WebSocketImpl: FakeWS,
    heartbeatMs: 10,
    staleConnectionMs: 40,
  });
  client.start();
  try {
    const ws = FakeWS.last;
    ws.emit('open');
    for (let i = 0; i < 6; i += 1) {
      await new Promise((resolve) => setTimeout(resolve, 15));
      ws.emit('pong'); // the server's socket layer answering our ping
    }
    assert.equal(ws.terminated, 0, 'a peer that answers is never called dead');
  } finally {
    client.stop();
  }
});

test('TCP keepalive is set on the socket when it opens', () => {
  FakeWS.urls = [];
  const { logger } = quietLogger();
  const client = createAgentClient({
    serverUrl: 'http://server.test',
    token: 'tok',
    logger,
    WebSocketImpl: FakeWS,
    heartbeatMs: 100000,
    socketKeepAliveMs: 7000,
  });
  client.start();
  try {
    FakeWS.last.emit('open');
    assert.deepEqual(FakeWS.last.keepAlive, { on: true, ms: 7000 });
  } finally {
    client.stop();
  }
});

test('a 401 retries on the auth timer instead of killing the agent', async () => {
  FakeWS.urls = [];
  const { logger } = quietLogger();
  const client = createAgentClient({
    serverUrl: 'http://server.test',
    token: 'tok',
    logger,
    WebSocketImpl: FakeWS,
    heartbeatMs: 100000,
    authRetryMs: 30,
  });
  const rejected = [];
  client.on('auth-rejected', (info) => rejected.push(info));
  client.start();
  try {
    FakeWS.last.emit('unexpected-response', {}, { statusCode: 401 });
    assert.equal(client.isFatal, false, 'a refused token is not the end of the agent');
    assert.equal(rejected.length, 1);
    assert.equal(rejected[0].retryInMs, 30);
    await new Promise((resolve) => setTimeout(resolve, 80));
    assert.ok(FakeWS.urls.length >= 2, 'it dialled again');
  } finally {
    client.stop();
  }
});

test('with no auth retry configured a 401 is still terminal', () => {
  FakeWS.urls = [];
  const { logger } = quietLogger();
  const client = createAgentClient({
    serverUrl: 'http://server.test',
    token: 'tok',
    logger,
    WebSocketImpl: FakeWS,
    heartbeatMs: 100000,
    authRetryMs: 0,
  });
  const fatals = [];
  client.on('fatal', (r) => fatals.push(r));
  client.start();
  try {
    FakeWS.last.emit('unexpected-response', {}, { statusCode: 401 });
    assert.equal(client.isFatal, true);
    assert.equal(fatals.length, 1);
  } finally {
    client.stop();
  }
});

test('a URL that cannot be connected to rotates to the next one', async () => {
  FakeWS.urls = [];
  const { logger } = quietLogger();
  const client = createAgentClient({
    serverUrl: 'http://primary.test',
    serverUrls: ['http://spare.test'],
    token: 'tok',
    logger,
    WebSocketImpl: FakeWS,
    heartbeatMs: 100000,
    backoff: { baseMs: 5, maxMs: 5 },
  });
  client.start();
  try {
    assert.equal(client.activeServerUrl(), 'http://primary.test');
    FakeWS.last.emit('error', new Error('ECONNREFUSED'));
    await tick();
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(client.activeServerUrl(), 'http://spare.test');
    assert.ok(FakeWS.urls.some((u) => u.startsWith('ws://spare.test')), 'it dialled the spare');
  } finally {
    client.stop();
  }
});

test('a 401 does not rotate away from a URL that is plainly reaching the server', async () => {
  FakeWS.urls = [];
  const { logger } = quietLogger();
  const client = createAgentClient({
    serverUrl: 'http://primary.test',
    serverUrls: ['http://spare.test'],
    token: 'tok',
    logger,
    WebSocketImpl: FakeWS,
    heartbeatMs: 100000,
    authRetryMs: 20,
  });
  client.start();
  try {
    FakeWS.last.emit('unexpected-response', {}, { statusCode: 401 });
    await new Promise((resolve) => setTimeout(resolve, 60));
    assert.equal(client.activeServerUrl(), 'http://primary.test');
  } finally {
    client.stop();
  }
});

test('a connection that opened and then dropped keeps the same URL', async () => {
  FakeWS.urls = [];
  const { logger } = quietLogger();
  const client = createAgentClient({
    serverUrl: 'http://primary.test',
    serverUrls: ['http://spare.test'],
    token: 'tok',
    logger,
    WebSocketImpl: FakeWS,
    heartbeatMs: 100000,
    backoff: { baseMs: 5, maxMs: 5 },
  });
  client.start();
  try {
    FakeWS.last.emit('open');
    FakeWS.last.emit('close', 1006);
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(client.activeServerUrl(), 'http://primary.test', 'a drop is not the URL being wrong');
  } finally {
    client.stop();
  }
});

// ---- A redirect on the handshake ------------------------------------------
// Seen in the field: an agent enrolled against http:// while the server moved
// to https. The WebSocket handshake does not follow redirects (and an
// http→https hop drops the Authorization header anyway), so the agent logged
// "WebSocket handshake failed: HTTP 301" 342 times in a row — none of the 342
// lines saying what to change. The condition cannot clear by itself, so the
// remedy goes out once and the rest stay short.
// ...and when the redirect is one the agent can answer itself — the same host,
// over https — it answers it. The startup scheme probe was supposed to catch
// this, but it runs once, and a service that starts at boot before the network
// is up gets nothing from it and then speaks ws:// for the life of the process.
// That is what a day of 301s on an unattended host looks like.
test('a 301 to https on the same host is adopted, not just reported', async () => {
  FakeWS.urls = [];
  const { logger, lines } = quietLogger();
  const client = createAgentClient({
    serverUrl: 'http://server.test',
    token: 'tok',
    logger,
    WebSocketImpl: FakeWS,
    heartbeatMs: 100000,
    backoff: { baseMs: 5, maxMs: 5 },
  });
  const seen = [];
  client.on('server-url', (u) => seen.push(u));
  client.start();
  try {
    assert.match(FakeWS.urls[0], /^ws:\/\//, 'it starts out where it was pointed');
    FakeWS.last.emit('unexpected-response', {}, { statusCode: 301, headers: { location: 'https://server.test/ws/agent' } });

    await new Promise((resolve) => setTimeout(resolve, 40));
    assert.match(FakeWS.urls[1], /^wss:\/\/server\.test\/ws\/agent$/, `it did not re-dial over wss: ${FakeWS.urls.join(', ')}`);
    assert.deepEqual(seen, ['https://server.test'], 'the new URL was not announced');

    const line = lines.find((l) => /switching to https:\/\/server\.test/.test(l));
    assert.ok(line, `no line about the switch: ${lines.join(' | ')}`);
    assert.match(line, /BLUEEYE_SERVER_URL|re-enroll/, 'and it still says to fix the stored URL');

    // An https server that still redirects must not start a loop: there is no
    // scheme left to upgrade, so it falls back to being reported.
    FakeWS.last.emit('unexpected-response', {}, { statusCode: 301, headers: { location: 'https://server.test/ws/agent' } });
    await new Promise((resolve) => setTimeout(resolve, 40));
    assert.equal(seen.length, 1, 'it kept re-adopting the same URL');
  } finally {
    client.stop();
  }
});

// A redirect to ANOTHER host is not the agent's to follow: that is the shape an
// open redirect takes, and the certificate pins cover the host it was enrolled
// against, not whatever the answer names.
test('a 301 to another host is reported, never adopted', async () => {
  FakeWS.urls = [];
  const { logger, lines } = quietLogger();
  const client = createAgentClient({
    serverUrl: 'http://server.test',
    token: 'tok',
    logger,
    WebSocketImpl: FakeWS,
    heartbeatMs: 100000,
    backoff: { baseMs: 5, maxMs: 5 },
  });
  const seen = [];
  client.on('server-url', (u) => seen.push(u));
  client.start();
  try {
    FakeWS.last.emit('unexpected-response', {}, { statusCode: 301, headers: { location: 'https://elsewhere.example/ws/agent' } });
    await new Promise((resolve) => setTimeout(resolve, 40));
    assert.deepEqual(seen, [], 'it followed a redirect off its own host');
    assert.ok(FakeWS.urls.every((u) => /server\.test/.test(u)), `it dialled elsewhere: ${FakeWS.urls.join(', ')}`);
    assert.ok(lines.some((l) => /does not follow redirects/.test(l)), 'and it said why it will not clear');
  } finally {
    client.stop();
  }
});

test('a 301 on the handshake says what to change, once, and keeps retrying', async () => {
  FakeWS.urls = [];
  const { logger, lines } = quietLogger();
  const client = createAgentClient({
    // Already https, so there is no scheme left to upgrade: this is the redirect
    // that can only be explained, which is what this case is about.
    serverUrl: 'https://server.test',
    token: 'tok',
    logger,
    WebSocketImpl: FakeWS,
    heartbeatMs: 100000,
    backoff: { baseMs: 5, maxMs: 5 },
  });
  client.start();
  try {
    FakeWS.last.emit('unexpected-response', {}, {
      statusCode: 301,
      headers: { location: 'https://server.test/elsewhere' },
    });
    const first = lines.find((l) => /redirect/i.test(l));
    assert.ok(first, `no redirect line: ${lines.join(' | ')}`);
    assert.match(first, /https:\/\/server\.test/, 'the remedy names where to point it');
    assert.match(first, /BLUEEYE_SERVER_URL|re-enroll/, 'the remedy names how to change it');
    assert.match(first, /does not follow redirects/, 'and why it will not fix itself');

    // It still re-dials — the server may be fixed while the agent runs.
    await new Promise((resolve) => setTimeout(resolve, 40));
    assert.ok(FakeWS.urls.length >= 2, 'it stopped trying');

    // The second 301 does not repeat the whole explanation.
    FakeWS.last.emit('unexpected-response', {}, { statusCode: 301, headers: { location: 'https://server.test/ws/agent' } });
    const explained = lines.filter((l) => /does not follow redirects/.test(l));
    assert.equal(explained.length, 1, 'the explanation was logged more than once');
  } finally {
    client.stop();
  }
});
