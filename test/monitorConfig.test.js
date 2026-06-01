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

const baseConfig = (server) => ({
  serverUrl: server.url,
  heartbeatMs: 10000,
  backoff: { baseMs: 30, maxMs: 120, factor: 2 },
  reportIntervalMs: 50,
  reportSampleMs: 10,
});

const fixedCaps = { sources: ['proc', 'snmp'], agentVersion: 'test' };

test('agent reports its capabilities to the server on start', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const runtime = createAgentRuntime({
    config: baseConfig(server),
    token: 'valid',
    agentId: 1,
    logger: silentLogger,
    capabilities: fixedCaps,
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config event');
    assert.equal(server.receivedCapabilities.length >= 1, true);
    assert.deepEqual(server.receivedCapabilities[0].sources, ['proc', 'snmp']);
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('agent uses the SNMP sampler when the server assigns source snmp', async () => {
  const server = await startFakeServer({
    validTokens: ['valid'],
    monitorConfig: { source: 'snmp', snmp: { host: '10.0.0.1' } },
  });

  // Inject a sampler factory so we can observe which source was selected without
  // needing net-snmp or a device.
  let usedSource = null;
  const samplerFactory = (mc) => {
    usedSource = mc.source;
    return async ({ intervalMs }) => ({
      source: mc.source,
      intervalMs,
      elapsedSec: intervalMs / 1000,
      interfaces: [{ iface: 'Gi0/0', rxBytes: 10, txBytes: 20, rxBytesPerSec: 10, txBytesPerSec: 20 }],
      totals: { rxBytes: 10, txBytes: 20, rxBytesPerSec: 10, txBytesPerSec: 20 },
    });
  };

  const runtime = createAgentRuntime({
    config: baseConfig(server),
    token: 'valid',
    agentId: 1,
    logger: silentLogger,
    capabilities: fixedCaps,
    samplerFactory,
  });
  try {
    runtime.start();
    const { result } = await withTimeout(onceEvent(runtime, 'results-submitted'), 4000, 'no report');
    assert.equal(usedSource, 'snmp'); // selected from the server config
    assert.equal(result.traffic.source, 'snmp'); // and the submitted payload reflects it
    assert.equal(runtime.getMonitorConfig().source, 'snmp');
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('a 401 while reporting capabilities/config is fatal (no re-enroll)', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const runtime = createAgentRuntime({
    config: baseConfig(server),
    token: 'WRONG', // server rejects -> 401 on capabilities/config
    agentId: 1,
    logger: silentLogger,
    capabilities: fixedCaps,
  });
  try {
    const fatalP = onceEvent(runtime, 'fatal');
    runtime.start();
    const reason = await withTimeout(fatalP, 4000, 'no fatal emitted');
    assert.ok(reason);
    assert.equal(server.receivedResults.length, 0); // nothing reported
  } finally {
    runtime.stop();
    await server.close();
  }
});
