'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { startFakeServer } = require('../test-support/fakeServer');
const { createAgentRuntime } = require('../src/runtime');
const { silentLogger } = require('../src/logger');
const { isRunDiscoveryCommand } = require('../src/command');
const { DiscoveryScopeError } = require('../src/discovery/scanner');

function withTimeout(promise, ms, message) {
  let timer;
  const timeout = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message || `timeout ${ms}ms`)), ms); timer.unref(); });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}
const onceEvent = (emitter, name) => new Promise((resolve) => emitter.once(name, resolve));
const makeConfig = (server) => ({ serverUrl: server.url, heartbeatMs: 10000, backoff: { baseMs: 30, maxMs: 120, factor: 2 } });

test('isRunDiscoveryCommand recognises the command shape', () => {
  assert.equal(isRunDiscoveryCommand({ name: 'run-discovery', discovery: { cidrs: [] } }), true);
  assert.equal(isRunDiscoveryCommand({ name: 'run_discovery', discovery: {} }), true);
  assert.equal(isRunDiscoveryCommand({ name: 'run-discovery' }), false); // no discovery object
  assert.equal(isRunDiscoveryCommand({ name: 'run-probe', probe: {} }), false);
});

test('runs a discovery sweep from an explicit scope and submits candidates', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  let scanArgs = null;
  const discoveryScanner = { scan: async (a) => { scanArgs = a; return { addresses: 256, probed: ['10.0.0.2'], candidates: [{ ip: '10.0.0.2', hostname: 'h2', openPorts: [22], icmp: false }] }; } };
  const runtime = createAgentRuntime({ config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger, discoveryScanner, collectCidrs: () => ['192.168.9.0/24'] });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'connected'), 4000, 'no connected');
    const submitted = onceEvent(runtime, 'discovery-submitted');
    server.sendCommandToAll({ name: 'run-discovery', discovery: { cidrs: ['10.0.0.0/24'], requestId: 'r1' } });
    const payload = await withTimeout(submitted, 4000, 'discovery not submitted');
    assert.deepEqual(scanArgs.cidrs, ['10.0.0.0/24']); // explicit scope used
    assert.equal(payload.derivedFromSelf, false);
    assert.equal(server.receivedDiscovery.length, 1);
    assert.equal(server.receivedDiscovery[0].token, 'valid');
    assert.equal(server.receivedDiscovery[0].body.requestId, 'r1');
    assert.equal(server.receivedDiscovery[0].body.candidates.length, 1);
  } finally { runtime.stop(); await server.close(); }
});

test('empty scope falls back to the agent own subnet (derivedFromSelf)', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  let scanArgs = null;
  const discoveryScanner = { scan: async (a) => { scanArgs = a; return { addresses: 256, probed: [], candidates: [] }; } };
  const runtime = createAgentRuntime({ config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger, discoveryScanner, collectCidrs: () => ['192.168.9.0/24'] });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'connected'), 4000, 'no connected');
    const submitted = onceEvent(runtime, 'discovery-submitted');
    server.sendCommandToAll({ name: 'run-discovery', discovery: { requestId: 'r2' } }); // no cidrs
    const payload = await withTimeout(submitted, 4000, 'discovery not submitted');
    assert.deepEqual(scanArgs.cidrs, ['192.168.9.0/24']); // own subnet substituted
    assert.equal(payload.derivedFromSelf, true);
  } finally { runtime.stop(); await server.close(); }
});

test('a scope refusal is reported as refused, not a crash', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const discoveryScanner = { scan: async () => { throw new DiscoveryScopeError('scope_too_large', 'too big'); } };
  const runtime = createAgentRuntime({ config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger, discoveryScanner, collectCidrs: () => [] });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'connected'), 4000, 'no connected');
    const refused = onceEvent(runtime, 'discovery-refused');
    server.sendCommandToAll({ name: 'run-discovery', discovery: { cidrs: ['10.0.0.0/8'], requestId: 'r3' } });
    const info = await withTimeout(refused, 4000, 'no refusal');
    assert.equal(info.reason, 'scope_too_large');
    assert.equal(server.receivedDiscovery[0].body.refused, true);
    assert.equal(server.receivedDiscovery[0].body.reason, 'scope_too_large');
  } finally { runtime.stop(); await server.close(); }
});
