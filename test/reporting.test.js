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
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const reportingConfig = (server) => ({
  serverUrl: server.url,
  heartbeatMs: 10000,
  backoff: { baseMs: 30, maxMs: 120, factor: 2 },
  reportIntervalMs: 50,
  reportSampleMs: 10,
});

test('agent reports traffic continuously on the configured interval', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const runtime = createAgentRuntime({
    config: reportingConfig(server),
    token: 'valid',
    agentId: 1,
    logger: silentLogger,
  });
  try {
    runtime.start();
    const { source } = await withTimeout(onceEvent(runtime, 'results-submitted'), 4000, 'no auto report');
    assert.equal(source, 'auto'); // submitted without any server command
    await sleep(140); // allow a couple more ticks
    assert.ok(server.receivedResults.length >= 2, `expected >=2 reports, got ${server.receivedResults.length}`);
    assert.equal(server.receivedResults[0].token, 'valid');
    assert.ok(server.receivedResults[0].results[0].traffic, 'report carries traffic');
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('stop() halts continuous reporting', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const runtime = createAgentRuntime({
    config: reportingConfig(server),
    token: 'valid',
    agentId: 1,
    logger: silentLogger,
  });
  runtime.start();
  await withTimeout(onceEvent(runtime, 'results-submitted'), 4000, 'no auto report');
  runtime.stop();
  const countAfterStop = server.receivedResults.length;
  await sleep(160);
  assert.ok(
    server.receivedResults.length <= countAfterStop + 1,
    `reporting kept going after stop: ${countAfterStop} -> ${server.receivedResults.length}`
  );
  await server.close();
});

test('reportIntervalMs <= 0 disables continuous reporting', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const runtime = createAgentRuntime({
    config: { ...reportingConfig(server), reportIntervalMs: 0 },
    token: 'valid',
    agentId: 1,
    logger: silentLogger,
  });
  try {
    runtime.start();
    await sleep(160);
    assert.equal(server.receivedResults.length, 0); // nothing auto-submitted
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('a 401 while submitting a report is fatal (REST path, no WS)', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  // Use reportNow() WITHOUT start() so the WebSocket never connects — this
  // isolates the REST results path. The token is wrong, so the POST returns 401.
  const runtime = createAgentRuntime({
    config: reportingConfig(server),
    token: 'WRONG-TOKEN',
    agentId: 1,
    logger: silentLogger,
  });
  try {
    const fatal = onceEvent(runtime, 'fatal');
    const ok = await runtime.reportNow();
    assert.equal(ok, false);
    const reason = await withTimeout(fatal, 4000, 'no fatal emitted');
    assert.equal(reason, 'rest-token-rejected');
    assert.equal(server.receivedResults.length, 0); // nothing stored
  } finally {
    runtime.stop();
    await server.close();
  }
});
