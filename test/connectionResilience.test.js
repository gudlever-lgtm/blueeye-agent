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
