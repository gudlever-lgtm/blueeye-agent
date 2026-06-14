'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('events');

const { createAgentClient } = require('../src/agentClient');
const { PROTOCOL_VERSION } = require('../src/protocol');

// Minimal stand-in for the `ws` client: records the constructor opts (so we can
// inspect the upgrade headers) and lets the test drive open/message events.
class FakeWS extends EventEmitter {
  constructor(url, opts) {
    super();
    this.url = url;
    this.opts = opts;
    this.readyState = 1;
    this.OPEN = 1;
    FakeWS.last = this;
  }
  send() {}
  close() {}
  terminate() {}
}

function recordingLogger() {
  const warns = [];
  return { logger: { info() {}, warn: (m) => warns.push(m), error() {} }, warns };
}

test('agent declares X-BlueEye-Protocol on the WS upgrade', () => {
  const { logger } = recordingLogger();
  const client = createAgentClient({
    serverUrl: 'http://server.test', token: 'tok', logger,
    WebSocketImpl: FakeWS, heartbeatMs: 100000,
  });
  client.start();
  try {
    assert.equal(FakeWS.last.opts.headers['X-BlueEye-Protocol'], String(PROTOCOL_VERSION));
    assert.equal(FakeWS.last.opts.headers.Authorization, 'Bearer tok');
  } finally {
    client.stop();
  }
});

test('agent warns (but does not fail) on a mismatched server protocol version', () => {
  const { logger, warns } = recordingLogger();
  const client = createAgentClient({
    serverUrl: 'http://server.test', token: 'tok', logger,
    WebSocketImpl: FakeWS, heartbeatMs: 100000,
  });
  client.start();
  try {
    FakeWS.last.emit('open');
    FakeWS.last.emit('message', JSON.stringify({ type: 'connected', agentId: 1, protocolVersion: 999 }));
    assert.ok(warns.some((w) => /protocol/i.test(w)), 'a protocol-mismatch warning was logged');
    assert.equal(client.isFatal, false); // never fatal
  } finally {
    client.stop();
  }
});

test('agent stays quiet when the server protocol version matches', () => {
  const { logger, warns } = recordingLogger();
  const client = createAgentClient({
    serverUrl: 'http://server.test', token: 'tok', logger,
    WebSocketImpl: FakeWS, heartbeatMs: 100000,
  });
  client.start();
  try {
    FakeWS.last.emit('open');
    FakeWS.last.emit('message', JSON.stringify({ type: 'connected', agentId: 1, protocolVersion: PROTOCOL_VERSION }));
    assert.equal(warns.some((w) => /protocol/i.test(w)), false);
  } finally {
    client.stop();
  }
});
