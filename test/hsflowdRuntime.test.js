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
const makeConfig = (server) => ({ serverUrl: server.url, heartbeatMs: 10000, backoff: { baseMs: 30, maxMs: 120, factor: 2 } });

// Records what the runtime asks of hsflowd, so we can assert the reconciliation
// without touching a real daemon.
function fakeManager(state = { state: 'active', detail: null }) {
  const calls = { enable: [], disable: 0 };
  return {
    enable: async (opts) => { calls.enable.push(opts); return state; },
    disable: async () => { calls.disable += 1; return { state: 'inactive', detail: null }; },
    status: async () => state,
    calls,
  };
}

test('a sflow+hsflowd monitor config makes the agent provision the local exporter', async () => {
  const server = await startFakeServer({
    validTokens: ['valid'],
    monitorConfig: { source: 'sflow', sflow: { port: 6343, hsflowd: { samplingRate: 512, device: 'ens5' } } },
  });
  const mgr = fakeManager();
  const runtime = createAgentRuntime({
    config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger, hsflowdManager: mgr,
  });
  try {
    const reconciled = onceEvent(runtime, 'hsflowd');
    runtime.start();
    const r = await withTimeout(reconciled, 4000, 'hsflowd never reconciled');
    assert.equal(r.state, 'active');
    assert.equal(mgr.calls.enable.length, 1);
    assert.deepEqual(mgr.calls.enable[0], { collectorPort: 6343, samplingRate: 512, pollingSecs: undefined, device: 'ens5' });
    assert.deepEqual(runtime.getHsflowdState(), { state: 'active', detail: null });
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('a plain proc config never touches hsflowd', async () => {
  const server = await startFakeServer({ validTokens: ['valid'], monitorConfig: { source: 'proc' } });
  const mgr = fakeManager();
  const runtime = createAgentRuntime({
    config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger, hsflowdManager: mgr,
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config loaded');
    assert.equal(mgr.calls.enable.length, 0);
    assert.equal(mgr.calls.disable, 0);
    assert.equal(runtime.getHsflowdState(), null);
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('sflow without the hsflowd flag does not provision an exporter (external-source case)', async () => {
  const server = await startFakeServer({
    validTokens: ['valid'],
    monitorConfig: { source: 'sflow', sflow: { port: 6343 } }, // receives from an external switch
  });
  const mgr = fakeManager();
  const runtime = createAgentRuntime({
    config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger, hsflowdManager: mgr,
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config loaded');
    assert.equal(mgr.calls.enable.length, 0);
  } finally {
    runtime.stop();
    await server.close();
  }
});
