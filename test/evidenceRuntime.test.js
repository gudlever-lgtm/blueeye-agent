'use strict';

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

test('an "evidence" command collects allowlisted read-only items and refuses a write-class one', async () => {
  const server = await startFakeServer({ validTokens: ['valid'], monitorConfig: { source: 'proc' } });
  const runtime = createAgentRuntime({ config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger, hsflowdManager: noopHsflowd });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config loaded');

    const reply = server.waitForWsMessage((m) => m.type === 'command-result' && m.id === 'e1');
    // Request one allowlisted item + one write-class item — the agent must refuse the latter.
    server.sendCommandToAll({ name: 'evidence', id: 'e1', snapshotId: 7, clusterId: 5, commandSetVersion: 'evidence-v1', items: ['agent.state', 'reboot'] });
    const msg = await withTimeout(reply, 4000, 'no evidence reply');

    assert.equal(msg.ok, true);
    assert.equal(msg.evidence.commandSetVersion, 'evidence-v1');
    const byName = Object.fromEntries(msg.evidence.items.map((i) => [i.name, i]));
    assert.equal(byName['agent.state'].status, 'ok');       // read-only, collected
    assert.match(byName['agent.state'].payload, /agentVersion/);
    assert.equal(byName.reboot.status, 'refused');           // write-class hard-refused agent-side
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('a signed evidence command with a bad signature is refused when a release key is configured', async () => {
  const server = await startFakeServer({ validTokens: ['valid'], monitorConfig: { source: 'proc' } });
  // Inject a configured release public key so signature verification is enforced.
  const { publicKey } = require('crypto').generateKeyPairSync('ed25519');
  const pem = publicKey.export({ type: 'spki', format: 'pem' });
  const runtime = createAgentRuntime({
    config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger, hsflowdManager: noopHsflowd,
    releasePublicKey: pem,
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config loaded');
    const reply = server.waitForWsMessage((m) => m.type === 'command-result' && m.id === 'e2');
    server.sendCommandToAll({ name: 'evidence', id: 'e2', snapshotId: 8, clusterId: 5, commandSetVersion: 'evidence-v1', items: ['agent.state'], signature: 'bm90LWEtcmVhbC1zaWc=' });
    const msg = await withTimeout(reply, 4000, 'no evidence reply');
    assert.equal(msg.ok, false);
    assert.match(msg.error, /signature/);
  } finally {
    runtime.stop();
    await server.close();
  }
});
