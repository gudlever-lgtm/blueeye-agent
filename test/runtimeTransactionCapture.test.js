'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const fs = require('fs');
const os = require('os');
const path = require('path');

const { startFakeServer } = require('../test-support/fakeServer');
const { createAgentRuntime } = require('../src/runtime');
const { silentLogger } = require('../src/logger');

// The transaction config store persists to disk. Without an explicit path it
// resolves relative to the token path — i.e. the repo root when a test does not
// set one — so every run left a transactions.json behind. One temp dir per run.
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'blueeye-tx-'));

function withTimeout(promise, ms, message) {
  let timer;
  const timeout = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message || `timeout ${ms}ms`)), ms); timer.unref(); });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}
const onceEvent = (emitter, name) => new Promise((resolve) => emitter.once(name, resolve));
const makeConfig = (server) => ({
  serverUrl: server.url,
  heartbeatMs: 10000,
  backoff: { baseMs: 30, maxMs: 120, factor: 2 },
  transactionConfigPath: path.join(TMP, `transactions-${Math.random().toString(36).slice(2)}.json`),
});
const noopHsflowd = { enable: async () => ({ state: 'active' }), disable: async () => ({ state: 'inactive' }), status: async () => ({ state: 'unknown' }) };
const systemd = { sources: ['proc'], agentVersion: '0.2.0', managed: 'systemd' };

const TEST_DEF = {
  id: 42,
  name: 'Login',
  type: 'tcp',
  target: '10.20.1.40',
  interval_sec: 3600,
  enabled: true,
  capture: 'on_fault',
  config: { port: 443 },
};

// A capture runner that never spawns anything: it hands back the packets it was
// constructed with, and records what it was asked to do.
function fakeCaptureRunner(packets) {
  const calls = { started: 0, stopped: [] };
  return {
    calls,
    async start() {
      calls.started += 1;
      return {
        ok: true,
        session: {
          async stop(opts) {
            calls.stopped.push(opts);
            if (!opts.keep) return { kept: false, packets: [], durationMs: 5 };
            return {
              kept: true, packets, durationMs: 5, iface: 'eth0',
              filter: '(host 10.20.1.40 and tcp port 443)', snaplen: 96,
              observed: packets.length, dropped: 0, foreign: 0, truncated: false,
            };
          },
        },
      };
    },
    async cancel() { return true; },
  };
}

// A connect() that fails, so the run is a fault and the capture is kept.
function refusingConnect() {
  const { EventEmitter } = require('events');
  return () => {
    const socket = new EventEmitter();
    socket.setTimeout = () => {};
    socket.destroy = () => {};
    setImmediate(() => { const e = new Error('refused'); e.code = 'ECONNREFUSED'; socket.emit('error', e); });
    return socket;
  };
}

test('run-transaction runs an assigned test now and replies with the result', async () => {
  const server = await startFakeServer({ validTokens: ['valid'], monitorConfig: { source: 'proc' } });
  const capture = fakeCaptureRunner([{ t: 0, flags: 'S', sport: 51234, dport: 443 }]);
  const runtime = createAgentRuntime({
    config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger,
    hsflowdManager: noopHsflowd, capabilities: systemd, captureRunner: capture,
    transactionExecutorDeps: { connect: refusingConnect() },
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config');
    server.sendToAll({ type: 'transaction_config', tests: [TEST_DEF] });
    await new Promise((r) => setTimeout(r, 100));

    const replied = server.waitForWsMessage((m) => m.type === 'command-result' && m.transaction);
    server.sendCommandToAll({ name: 'run-transaction', id: 't1', testId: 42, capture: true });
    const msg = await withTimeout(replied, 4000, 'no command-result for run-transaction');
    assert.equal(msg.ok, true);
    assert.equal(msg.transaction.result.test_id, 42);
    assert.equal(msg.transaction.result.status, 'fail');
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('run-transaction refuses a test this agent is not assigned', async () => {
  const server = await startFakeServer({ validTokens: ['valid'], monitorConfig: { source: 'proc' } });
  const runtime = createAgentRuntime({
    config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger,
    hsflowdManager: noopHsflowd, capabilities: systemd, captureRunner: fakeCaptureRunner([]),
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config');
    const replied = server.waitForWsMessage((m) => m.type === 'command-result' && m.transaction);
    server.sendCommandToAll({ name: 'run-transaction', id: 't2', testId: 999 });
    const msg = await withTimeout(replied, 4000, 'no command-result');
    assert.equal(msg.ok, false);
    assert.match(msg.transaction.error, /not assigned/);
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('a failing scheduled run ships its capture as its own frame', async () => {
  const server = await startFakeServer({ validTokens: ['valid'], monitorConfig: { source: 'proc' } });
  const capture = fakeCaptureRunner([{ t: 0, flags: 'S', sport: 51234, dport: 443 }, { t: 1.2, flags: 'R', sport: 443, dport: 51234 }]);
  const runtime = createAgentRuntime({
    config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger,
    hsflowdManager: noopHsflowd, capabilities: systemd, captureRunner: capture,
    transactionExecutorDeps: { connect: refusingConnect() },
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config');
    server.sendToAll({ type: 'transaction_config', tests: [TEST_DEF] });
    await new Promise((r) => setTimeout(r, 100));

    const captured = server.waitForWsMessage((m) => m.type === 'transaction_capture');
    server.sendCommandToAll({ name: 'run-transaction', id: 't3', testId: 42 });
    const frame = await withTimeout(captured, 4000, 'no transaction_capture frame');
    assert.equal(frame.test_id, 42);
    assert.equal(frame.capture.packets.length, 2);
    assert.equal(frame.capture.filter, '(host 10.20.1.40 and tcp port 443)');
    assert.equal(frame.capture.snaplen, 96);
    assert.match(frame.capture.reason, /^status:fail$/);
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('capabilities report whether this host can capture, and why not when it cannot', async () => {
  const server = await startFakeServer({ validTokens: ['valid'], monitorConfig: { source: 'proc' } });
  const runtime = createAgentRuntime({
    config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger,
    hsflowdManager: noopHsflowd, capabilities: systemd, captureRunner: fakeCaptureRunner([]),
    captureSupport: async () => ({ available: false, reason: 'tcpdump is not installed' }),
  });
  try {
    runtime.start();
    const payload = await withTimeout(onceEvent(runtime, 'capabilities-reported'), 4000, 'no capabilities');
    assert.equal(payload.capture, undefined);
    assert.equal(payload.unavailable.capture, 'tcpdump is not installed');
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('a host that can capture says so', async () => {
  const server = await startFakeServer({ validTokens: ['valid'], monitorConfig: { source: 'proc' } });
  const runtime = createAgentRuntime({
    config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger,
    hsflowdManager: noopHsflowd, capabilities: systemd, captureRunner: fakeCaptureRunner([]),
    captureSupport: async () => ({ available: true, reason: null }),
  });
  try {
    runtime.start();
    const payload = await withTimeout(onceEvent(runtime, 'capabilities-reported'), 4000, 'no capabilities');
    assert.equal(payload.capture, true);
    assert.ok(!payload.unavailable || !payload.unavailable.capture);
  } finally {
    runtime.stop();
    await server.close();
  }
});
