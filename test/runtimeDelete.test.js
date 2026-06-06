'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { startFakeServer } = require('../test-support/fakeServer');
const { createAgentRuntime } = require('../src/runtime');
const { silentLogger } = require('../src/logger');

function withTimeout(promise, ms, message) {
  let timer;
  const timeout = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message || `timeout ${ms}ms`)), ms); timer.unref(); });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}
const onceEvent = (emitter, name) => new Promise((resolve) => emitter.once(name, resolve));
const makeConfig = (server) => ({ serverUrl: server.url, heartbeatMs: 10000, backoff: { baseMs: 30, maxMs: 120, factor: 2 } });
const noopHsflowd = { enable: async () => ({ state: 'active' }), disable: async () => ({ state: 'inactive' }), status: async () => ({ state: 'unknown' }) };
const systemd = { sources: ['proc'], agentVersion: '0.2.0', managed: 'systemd' };

test('a delete command wipes the token, removes the agent, and reports completed with the audit id', async () => {
  const server = await startFakeServer({ validTokens: ['valid'], monitorConfig: { source: 'proc' } });
  const calls = { wipe: 0, remove: 0 };
  const selfDeleter = { wipeToken: () => { calls.wipe += 1; }, remove: () => { calls.remove += 1; } };
  const runtime = createAgentRuntime({
    config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger,
    hsflowdManager: noopHsflowd, selfDeleter, capabilities: systemd,
  });
  try {
    const reported = server.waitForWsMessage((m) => m.type === 'action-result' && m.action === 'delete');
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config');
    server.sendCommandToAll({ name: 'delete', id: 'd1', auditId: 77 });
    const msg = await withTimeout(reported, 4000, 'no delete action-result');
    assert.equal(msg.ok, true);
    assert.equal(msg.auditId, 77);
    assert.equal(calls.wipe, 1);
    assert.equal(calls.remove, 1);
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('a docker-managed agent declines delete (the host removes it)', async () => {
  const server = await startFakeServer({ validTokens: ['valid'], monitorConfig: { source: 'proc' } });
  const calls = { wipe: 0, remove: 0 };
  const selfDeleter = { wipeToken: () => { calls.wipe += 1; }, remove: () => { calls.remove += 1; } };
  const runtime = createAgentRuntime({
    config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger,
    hsflowdManager: noopHsflowd, selfDeleter, capabilities: { ...systemd, managed: 'docker' },
  });
  try {
    const reported = server.waitForWsMessage((m) => m.type === 'action-result' && m.action === 'delete');
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config');
    server.sendCommandToAll({ name: 'delete', id: 'd1', auditId: 5 });
    const msg = await withTimeout(reported, 4000, 'no delete action-result');
    assert.equal(msg.ok, false);
    assert.equal(msg.detail, 'docker-managed');
    assert.equal(calls.remove, 0); // never touched the host
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('a signed update reports completed (with the audit id + version) before restarting', async () => {
  const server = await startFakeServer({ validTokens: ['valid'], monitorConfig: { source: 'proc' } });
  let restarted = 0;
  const selfUpdater = { update: async () => ({ ok: true, sha: 'x' }), restart: () => { restarted += 1; } };
  const runtime = createAgentRuntime({
    config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger,
    hsflowdManager: noopHsflowd, selfUpdater, capabilities: systemd,
  });
  try {
    const reported = server.waitForWsMessage((m) => m.type === 'action-result' && m.action === 'upgrade');
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config');
    server.sendCommandToAll({ name: 'update', id: 'u1', auditId: 88, version: '0.3.0', sha256: 'abc', signature: 'sig' });
    const msg = await withTimeout(reported, 4000, 'no upgrade action-result');
    assert.equal(msg.ok, true);
    assert.equal(msg.auditId, 88);
    assert.equal(msg.version, '0.3.0');
    assert.equal(restarted, 1);
  } finally {
    runtime.stop();
    await server.close();
  }
});
