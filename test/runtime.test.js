'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { startFakeServer } = require('../test-support/fakeServer');
const { createAgentRuntime } = require('../src/runtime');
const { silentLogger } = require('../src/logger');

function withTimeout(promise, ms, message) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(message || `timeout after ${ms}ms`)), ms);
    timer.unref();
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

const onceEvent = (emitter, name) => new Promise((resolve) => emitter.once(name, resolve));

// Small backoff so the reconnect test is fast.
const makeConfig = (server) => ({
  serverUrl: server.url,
  heartbeatMs: 10000,
  backoff: { baseMs: 30, maxMs: 120, factor: 2 },
});

test('WS connects with a valid token', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const runtime = createAgentRuntime({
    config: makeConfig(server),
    token: 'valid',
    agentId: 1,
    logger: silentLogger,
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'open'), 4000, 'did not open');
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('an invalid token causes a fatal state and no reconnect', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const runtime = createAgentRuntime({
    config: makeConfig(server),
    token: 'WRONG',
    agentId: 1,
    logger: silentLogger,
  });
  let opened = false;
  runtime.on('open', () => {
    opened = true;
  });
  try {
    runtime.start();
    const reason = await withTimeout(onceEvent(runtime, 'fatal'), 4000, 'no fatal emitted');
    assert.ok(reason);
    assert.equal(opened, false);
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('runs a test and submits results on a run-test command', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const runtime = createAgentRuntime({
    config: makeConfig(server),
    token: 'valid',
    agentId: 1,
    logger: silentLogger,
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'connected'), 4000, 'no connected message');

    const submitted = onceEvent(runtime, 'results-submitted');
    const sent = server.sendCommandToAll({ name: 'run-test', id: 3, intervalMs: 10 });
    assert.equal(sent, 1);

    const { result } = await withTimeout(submitted, 4000, 'results not submitted');
    assert.equal(result.name, 'run-test');
    assert.equal(server.receivedResults.length, 1);
    assert.equal(server.receivedResults[0].token, 'valid'); // Bearer token forwarded
    assert.equal(server.receivedResults[0].results.length, 1);
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('scheduled probes resolve targets and submit them as one batch', async () => {
  const posts = [];
  const fetchImpl = async (url, opts) => {
    if (String(url).endsWith('/agents/probe-results')) { posts.push(JSON.parse(opts.body)); return { ok: true, status: 200, json: async () => ({ inserted: 1 }) }; }
    return { ok: true, status: 200, json: async () => ({}) };
  };
  const runtime = createAgentRuntime({
    config: { serverUrl: 'http://x', heartbeatMs: 10000, backoff: { baseMs: 30, maxMs: 120, factor: 2 }, probeIntervalMs: 0, probeCount: 2, probeAutoGateway: true, probeAutoDns: true, probeTargets: [] },
    token: 'valid', agentId: 1, logger: silentLogger, fetchImpl,
    resolveTargets: async () => [{ type: 'ping', host: '192.168.0.1', count: 2 }, { type: 'tcp', host: 'h', port: 443, count: 2 }],
    probeRunner: async (spec) => ({ type: spec.type, target: spec.host, ok: true, rttMs: 5, ts: new Date().toISOString() }),
  });
  try {
    const ok = await runtime.runScheduledProbesNow();
    assert.equal(ok, true);
    assert.equal(posts.length, 1); // one batched POST
    assert.equal(posts[0].results.length, 2);
    assert.equal(posts[0].results[0].target, '192.168.0.1');
  } finally {
    runtime.stop();
  }
});

test('a 401 while submitting scheduled probes is fatal', async () => {
  const fetchImpl = async () => ({ ok: false, status: 401, json: async () => ({}) });
  const runtime = createAgentRuntime({
    config: { serverUrl: 'http://x', heartbeatMs: 10000, backoff: { baseMs: 30, maxMs: 120, factor: 2 }, probeIntervalMs: 0, probeCount: 1, probeAutoGateway: false, probeAutoDns: false, probeTargets: [] },
    token: 'x', agentId: 1, logger: silentLogger, fetchImpl,
    resolveTargets: async () => [{ type: 'ping', host: '1.1.1.1' }],
    probeRunner: async (s) => ({ type: 'ping', target: s.host, ok: true }),
  });
  try {
    const fatalEvent = onceEvent(runtime, 'fatal');
    const ok = await runtime.runScheduledProbesNow();
    assert.equal(ok, false);
    await withTimeout(fatalEvent, 1000, 'no fatal emitted');
  } finally {
    runtime.stop();
  }
});

test('reconnects after a dropped connection (exponential backoff)', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const runtime = createAgentRuntime({
    config: makeConfig(server),
    token: 'valid',
    agentId: 1,
    logger: silentLogger,
  });
  let opens = 0;
  runtime.on('open', () => {
    opens += 1;
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'open'), 4000, 'first open failed');

    const reconnected = onceEvent(runtime, 'open');
    server.dropAllSockets(); // simulate a lost connection
    await withTimeout(reconnected, 4000, 'did not reconnect');

    assert.ok(opens >= 2, `expected at least 2 opens, got ${opens}`);
  } finally {
    runtime.stop();
    await server.close();
  }
});
