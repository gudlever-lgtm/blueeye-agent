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

test('install-tool installs the tool and reports completed with the audit id + tool', async () => {
  const server = await startFakeServer({ validTokens: ['valid'], monitorConfig: { source: 'proc' } });
  let asked = null;
  const toolInstaller = { installTool: async ({ tool }) => { asked = tool; return { ok: true, installed: true, tool, manager: 'apt', package: 'traceroute' }; } };
  const runtime = createAgentRuntime({
    config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger,
    hsflowdManager: noopHsflowd, toolInstaller, capabilities: systemd,
  });
  try {
    const reported = server.waitForWsMessage((m) => m.type === 'action-result' && m.action === 'install-tool');
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config');
    server.sendCommandToAll({ name: 'install-tool', id: 'i1', auditId: 91, tool: 'traceroute' });
    const msg = await withTimeout(reported, 4000, 'no install-tool action-result');
    assert.equal(msg.ok, true);
    assert.equal(msg.auditId, 91);
    assert.equal(msg.tool, 'traceroute');
    assert.equal(msg.package, 'traceroute');
    assert.equal(asked, 'traceroute');
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('install-tool reports failed (with the reason) when the install fails', async () => {
  const server = await startFakeServer({ validTokens: ['valid'], monitorConfig: { source: 'proc' } });
  const toolInstaller = { installTool: async ({ tool }) => ({ ok: false, installed: false, tool, detail: 'apt-get install requires root' }) };
  const runtime = createAgentRuntime({
    config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger,
    hsflowdManager: noopHsflowd, toolInstaller, capabilities: systemd,
  });
  try {
    const reported = server.waitForWsMessage((m) => m.type === 'action-result' && m.action === 'install-tool');
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config');
    server.sendCommandToAll({ name: 'install-tool', id: 'i2', auditId: 92, tool: 'traceroute' });
    const msg = await withTimeout(reported, 4000, 'no install-tool action-result');
    assert.equal(msg.ok, false);
    assert.equal(msg.auditId, 92);
    assert.match(msg.detail, /requires root/);
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('a docker-managed agent declines install-tool (the image owns its packages)', async () => {
  const server = await startFakeServer({ validTokens: ['valid'], monitorConfig: { source: 'proc' } });
  let called = 0;
  const toolInstaller = { installTool: async () => { called += 1; return { ok: true }; } };
  const runtime = createAgentRuntime({
    config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger,
    hsflowdManager: noopHsflowd, toolInstaller, capabilities: { ...systemd, managed: 'docker' },
  });
  try {
    const reported = server.waitForWsMessage((m) => m.type === 'action-result' && m.action === 'install-tool');
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config');
    server.sendCommandToAll({ name: 'install-tool', id: 'i3', auditId: 93, tool: 'traceroute' });
    const msg = await withTimeout(reported, 4000, 'no install-tool action-result');
    assert.equal(msg.ok, false);
    assert.equal(msg.detail, 'docker-managed');
    assert.equal(called, 0); // never attempted an install
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('an install-tool command without a tool is ignored (not recognised)', async () => {
  const server = await startFakeServer({ validTokens: ['valid'], monitorConfig: { source: 'proc' } });
  const runtime = createAgentRuntime({
    config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger,
    hsflowdManager: noopHsflowd, capabilities: systemd,
  });
  try {
    const ignored = onceEvent(runtime, 'command-ignored');
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config');
    server.sendCommandToAll({ name: 'install-tool', id: 'i4', auditId: 94 });
    const cmd = await withTimeout(ignored, 4000, 'expected the tool-less command to be ignored');
    assert.equal(cmd.name, 'install-tool');
  } finally {
    runtime.stop();
    await server.close();
  }
});
