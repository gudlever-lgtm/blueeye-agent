'use strict';

// A server command whose handler throws must cost that command, not the agent.
//
// The dispatcher in src/runtime.js is `async`, and an async listener on an
// EventEmitter has nowhere to put a rejection — it escapes as an unhandled
// rejection, which on a bare Node process is an exit. The agent runs on hosts
// nobody is watching, so the only symptom would be a gap in the data. These
// assert the wrapper that contains it.

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { startFakeServer } = require('../test-support/fakeServer');
const { createAgentRuntime } = require('../src/runtime');
const { silentLogger } = require('../src/logger');

function withTimeout(promise, ms, message) {
  let timer;
  const timeout = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message || `timeout after ${ms}ms`)), ms); timer.unref(); });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}
const onceEvent = (emitter, name) => new Promise((resolve) => emitter.once(name, resolve));
const makeConfig = (server) => ({ serverUrl: server.url, heartbeatMs: 10000, backoff: { baseMs: 30, maxMs: 120, factor: 2 } });
const noopHsflowd = { enable: async () => ({ state: 'active' }), disable: async () => ({ state: 'inactive' }), status: async () => ({ state: 'unknown' }) };

// The `stop-burst` branch of the dispatcher calls burst.cancel() directly,
// outside any try/catch of its own — so a runner that throws there is a real
// unguarded path, not a contrived one. (Most handlers already catch internally;
// this is the shape the wrapper exists for.) burstRunner is injectable.
// `armed` exists because runtime.stop() calls the SAME cancel() during
// teardown — a runner that always throws would break the test's own cleanup
// rather than the thing under test. Disarm before stopping.
function makeExplodingBurst() {
  return {
    armed: true,
    cancel() { if (this.armed) throw new Error('burst runner exploded'); return false; },
    run: async () => ({ ok: true }),
    isRunning: () => false,
    planBurst: () => ({}),
  };
}

test('a handler that throws emits command-failed and never becomes an unhandled rejection', async () => {
  const server = await startFakeServer({ validTokens: ['valid'], monitorConfig: { source: 'proc' } });
  const burst = makeExplodingBurst();
  const runtime = createAgentRuntime({
    config: makeConfig(server), token: 'valid', agentId: 1,
    logger: silentLogger, hsflowdManager: noopHsflowd,
    burstRunner: burst,
  });

  // If the wrapper is missing, THIS is what fires — and in production it would
  // be a process exit rather than a test failure, so assert on it directly.
  const rejections = [];
  const onRejection = (reason) => rejections.push(reason);
  process.on('unhandledRejection', onRejection);

  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config loaded');

    const failed = onceEvent(runtime, 'command-failed');
    server.sendCommandToAll({ name: 'stop-burst', id: 'd1' });
    const ev = await withTimeout(failed, 4000, 'the throw was swallowed without a command-failed event');

    assert.match(ev.error.message, /burst runner exploded/);
    // Give any stray rejection a turn of the loop to surface before we check.
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(rejections, [], 'a handler throw must not escape as an unhandled rejection');

    // And the agent is still alive and answering.
    const pong = server.waitForWsMessage((m) => m.type === 'ack' && m.id === 'p1');
    server.sendCommandToAll({ name: 'ping', id: 'p1' });
    const ack = await withTimeout(pong, 4000, 'the agent stopped answering after a failed command');
    assert.equal(ack.id, 'p1');
  } finally {
    process.removeListener('unhandledRejection', onRejection);
    burst.armed = false;
    runtime.stop();
    await server.close();
  }
});

test('the failing command gets an explicit error reply rather than silence', async () => {
  const server = await startFakeServer({ validTokens: ['valid'], monitorConfig: { source: 'proc' } });
  const burst = makeExplodingBurst();
  const runtime = createAgentRuntime({
    config: makeConfig(server), token: 'valid', agentId: 1,
    logger: silentLogger, hsflowdManager: noopHsflowd,
    burstRunner: burst,
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config loaded');

    const reply = server.waitForWsMessage((m) => m.type === 'command-result' && m.id === 'd2');
    server.sendCommandToAll({ name: 'stop-burst', id: 'd2' });
    const msg = await withTimeout(reply, 4000, 'no command-result for the failed command');

    assert.equal(msg.ok, false);
    assert.match(msg.error, /handler failed/);
    assert.match(msg.error, /burst runner exploded/);
  } finally {
    burst.armed = false;
    runtime.stop();
    await server.close();
  }
});

test('an auditId on the failing command is completed, so the dashboard shows a failed action', async () => {
  const server = await startFakeServer({ validTokens: ['valid'], monitorConfig: { source: 'proc' } });
  const burst = makeExplodingBurst();
  const runtime = createAgentRuntime({
    config: makeConfig(server), token: 'valid', agentId: 1,
    logger: silentLogger, hsflowdManager: noopHsflowd,
    burstRunner: burst,
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config loaded');

    const reply = server.waitForWsMessage((m) => m.type === 'action-result' && m.auditId === 99);
    server.sendCommandToAll({ name: 'stop-burst', id: 'd3', auditId: 99 });
    const msg = await withTimeout(reply, 4000, 'the audit row would have been left pending for ever');

    assert.equal(msg.ok, false);
    assert.match(msg.detail, /handler failed/);
  } finally {
    burst.armed = false;
    runtime.stop();
    await server.close();
  }
});
