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

// A sampler stand-in carrying the diagnostic surface (kind + stats) the runtime
// reads, so the test asserts the wiring without binding a real UDP collector.
function stubSflowSampler(stats) {
  const sampler = async () => ({ source: 'sflow', byPort: [], byProtocol: [], topTalkers: [], totals: { bytes: 0 } });
  sampler.kind = 'sflow';
  sampler.stats = () => stats;
  return sampler;
}

// hsflowd is irrelevant here (no `sflow.hsflowd` in the config), but inject a
// no-op manager so construction never touches the OS.
const noopHsflowd = {
  enable: async () => ({ state: 'active', detail: null }),
  disable: async () => ({ state: 'inactive', detail: null }),
  status: async () => ({ state: 'unknown', detail: null }),
};

test('a "diagnose" command makes the agent report its flow-pipeline snapshot', async () => {
  const server = await startFakeServer({
    validTokens: ['valid'],
    monitorConfig: { source: 'sflow', sflow: { port: 6343 } },
  });
  const stats = { listening: true, datagrams: 4, dropped: 1, decodedFlows: 7, bufferedFlows: 7, lastDatagramAt: new Date().toISOString() };
  const runtime = createAgentRuntime({
    config: makeConfig(server),
    token: 'valid',
    agentId: 1,
    logger: silentLogger,
    hsflowdManager: noopHsflowd,
    samplerFactory: () => stubSflowSampler(stats),
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config loaded');

    const reply = server.waitForWsMessage((m) => m.type === 'command-result' && m.id === 'd1');
    server.sendCommandToAll({ name: 'diagnose', id: 'd1' });
    const msg = await withTimeout(reply, 4000, 'no diagnose reply');

    assert.equal(msg.ok, true);
    const d = msg.diagnostic;
    assert.equal(d.source, 'sflow');
    assert.equal(typeof d.agentVersion, 'string');
    assert.equal(d.collector.kind, 'sflow');
    assert.equal(d.collector.listening, true);
    assert.equal(d.collector.datagrams, 4);
    assert.equal(d.collector.decodedFlows, 7);
    // getDiagnostic() returns the same live snapshot.
    assert.equal(runtime.getDiagnostic().collector.decodedFlows, 7);
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('diagnose on a proc agent reports no collector (so the dashboard says "switch to sflow")', async () => {
  const server = await startFakeServer({ validTokens: ['valid'], monitorConfig: { source: 'proc' } });
  const runtime = createAgentRuntime({
    config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger, hsflowdManager: noopHsflowd,
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config loaded');
    const d = runtime.getDiagnostic();
    assert.equal(d.source, 'proc');
    assert.equal(d.collector, null);
    assert.equal(d.hsflowd, null);
  } finally {
    runtime.stop();
    await server.close();
  }
});
