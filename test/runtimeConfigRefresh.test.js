'use strict';

// A running agent picks up server-side config changes without a reconnect:
//
//   * poll-snmp ("Poll now") re-reads GET /agents/me/config BEFORE it polls, so
//     a switch assigned a moment ago is polled — it used to poll the list read
//     at connect time, often nothing, while the server had already said 202 —
//     and its command-result says how many devices it polled;
//   * that re-read is bounded and error-tolerant: a hung or failing config call
//     costs the command a deadline, never the poll;
//   * the config is re-read on a cadence (configRefreshIntervalMs), and an
//     UNCHANGED config is a no-op: no sampler restart, no hsflowd reconcile.

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { startFakeServer } = require('../test-support/fakeServer');
const { createAgentRuntime } = require('../src/runtime');
const { createSnmpPoller } = require('../src/snmpPoller');
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
const delay = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(pred, ms, message) {
  const until = Date.now() + ms;
  while (!pred()) {
    if (Date.now() > until) throw new Error(message);
    // eslint-disable-next-line no-await-in-loop
    await delay(10);
  }
}

function countingHsflowd() {
  const calls = { enable: 0, disable: 0 };
  return {
    calls,
    enable: async () => { calls.enable += 1; return { state: 'active', detail: null }; },
    disable: async () => { calls.disable += 1; return { state: 'inactive', detail: null }; },
    status: async () => ({ state: 'unknown', detail: null }),
  };
}
const makeConfig = (server, extra = {}) => ({
  serverUrl: server.url,
  heartbeatMs: 10000,
  backoff: { baseMs: 30, maxMs: 120, factor: 2 },
  reportIntervalMs: 0,
  probeIntervalMs: 0,
  capabilitiesIntervalMs: 0,
  configRefreshIntervalMs: 0,
  syslogEnabled: false,
  ...extra,
});
const noLldp = async () => ({ unavailable: 'test' });

const TARGET = (over = {}) => ({ deviceId: 7, host: '10.14.0.11', community: 'public', collect: ['if'], intervalSec: 300, ...over });
const RESULT = (deviceId) => ({ deviceId, interfaces: [{ ifIndex: 1, ifName: 'Gi0/1' }], fdb: [], neighbours: [], vlans: [], supported: ['if'] });

// A real poller over a fake device reader, with its timers left unstarted.
function fakePoller(server, polledIds) {
  const real = createSnmpPoller({
    submit: (p) => server.postSnmpTopology(p),
    submitCounters: (p) => server.postSnmpCounters(p),
    poll: async ({ device }) => { polledIds.push(device.deviceId); return RESULT(device.deviceId); },
    pollCounters: async ({ device }) => ({ deviceId: device.deviceId, interfaces: [] }),
  });
  return { ...real, start: () => {}, startCounters: () => {} };
}

async function startedRuntime(server, extra = {}, deps = {}) {
  const polled = [];
  const runtime = createAgentRuntime({
    config: makeConfig(server, extra),
    token: 'valid', agentId: 1, logger: silentLogger, collectLldp: noLldp,
    hsflowdManager: countingHsflowd(),
    snmpPoller: fakePoller(server, polled),
    ...deps,
  });
  const connected = onceEvent(runtime, 'connected');
  runtime.start();
  await withTimeout(connected, 4000, 'never connected');
  // Bootstrap load + reconnect load both done.
  await waitFor(() => server.configFetchCount() >= 2, 4000, 'config never loaded');
  await delay(50);
  return { runtime, polled };
}

async function pollNow(server, command) {
  const reply = server.waitForWsMessage((m) => m.type === 'command-result' && m.id === command.id);
  server.sendCommandToAll(command);
  return withTimeout(reply, 4000, 'no poll-snmp reply');
}

// ------------------------------------------------------------ poll-snmp
test('poll-snmp re-reads the assignment first, so a device added after connect IS polled', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const { runtime, polled } = await startedRuntime(server);
  try {
    const before = server.configFetchCount();
    // The operator adds a switch and presses "Poll now" — no reconnect.
    server.setSnmpTargets([TARGET({ deviceId: 7 })]);
    const msg = await pollNow(server, { name: 'poll-snmp', id: 'p1', deviceId: 7 });

    assert.equal(server.configFetchCount(), before + 1, 'config re-read once');
    assert.deepEqual(polled, [7], 'the NEW device was polled');
    assert.equal(msg.ok, true);
    assert.equal(msg.devices, 1);
    assert.equal(msg.polled, 1);
    assert.equal(msg.failed, 0);
    assert.equal(msg.deviceAssigned, true);
    assert.equal(msg.configRefreshed, true);
    assert.equal(msg.detail, undefined);
    assert.equal(server.receivedSnmpTopology.length, 1);
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('poll-snmp with nothing assigned says so instead of a silent success', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const { runtime, polled } = await startedRuntime(server);
  try {
    const msg = await pollNow(server, { name: 'poll-snmp', id: 'p2', deviceId: 9 });
    assert.deepEqual(polled, []);
    assert.equal(msg.devices, 0);
    assert.equal(msg.polled, 0);
    assert.equal(msg.deviceAssigned, false);
    assert.match(msg.detail, /no SNMP devices are assigned/);
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('poll-snmp names a requested device that is not this agent\'s', async () => {
  const server = await startFakeServer({ validTokens: ['valid'], snmpTargets: [TARGET({ deviceId: 7 })] });
  const { runtime } = await startedRuntime(server);
  try {
    const msg = await pollNow(server, { name: 'poll-snmp', id: 'p3', deviceId: 8 });
    assert.equal(msg.devices, 1);
    assert.equal(msg.polled, 1);
    assert.equal(msg.deviceAssigned, false);
    assert.match(msg.detail, /device 8 is not assigned/);
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('a hung config call costs poll-snmp its deadline, not the poll', async () => {
  const server = await startFakeServer({ validTokens: ['valid'], snmpTargets: [TARGET({ deviceId: 7 })] });
  const { runtime, polled } = await startedRuntime(server, { pollConfigTimeoutMs: 100 });
  try {
    server.setConfigDelayMs(1500);
    const t0 = Date.now();
    const msg = await pollNow(server, { name: 'poll-snmp', id: 'p4' });
    assert.ok(Date.now() - t0 < 1200, `answered in ${Date.now() - t0} ms`);
    assert.equal(msg.configRefreshed, false);
    assert.deepEqual(polled, [7], 'polled with the assignment it already had');
    assert.equal(msg.polled, 1);
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('a failing config call is tolerated: poll-snmp still polls and answers', async () => {
  const server = await startFakeServer({ validTokens: ['valid'], snmpTargets: [TARGET({ deviceId: 7 })] });
  let failConfig = false;
  const fetchImpl = (url, opts) => (failConfig && String(url).endsWith('/agents/me/config')
    ? Promise.reject(Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' }))
    : fetch(url, opts));
  const { runtime, polled } = await startedRuntime(server, {}, { fetchImpl });
  try {
    failConfig = true;
    const msg = await pollNow(server, { name: 'poll-snmp', id: 'p5', deviceId: 7 });
    assert.equal(msg.ok, true);
    assert.equal(msg.configRefreshed, false);
    assert.equal(msg.devices, 1);
    assert.deepEqual(polled, [7]);
  } finally {
    runtime.stop();
    await server.close();
  }
});

// ------------------------------------------------------ periodic refresh
test('periodic refresh: an unchanged config is a no-op, a changed one applies without a reconnect', async () => {
  const server = await startFakeServer({
    validTokens: ['valid'],
    monitorConfig: { source: 'sflow', sflow: { port: 6343, hsflowd: { samplingRate: 400 } } },
  });
  const hsflowd = countingHsflowd();
  let samplers = 0;
  let stopped = 0;
  const samplerFactory = () => {
    samplers += 1;
    const s = async () => ({ totals: {} });
    s.stop = () => { stopped += 1; };
    return s;
  };
  const { runtime, polled } = await startedRuntime(server, { configRefreshIntervalMs: 40 }, {
    samplerFactory, hsflowdManager: hsflowd,
  });
  try {
    const connections = server.socketCount();
    const samplersAtStart = samplers;
    const enablesAtStart = hsflowd.calls.enable;
    const fetchesAtStart = server.configFetchCount();
    assert.ok(enablesAtStart >= 1, 'the exporter was reconciled at start');

    // Several refreshes over an unchanged config.
    await waitFor(() => server.configFetchCount() >= fetchesAtStart + 3, 4000, 'no periodic refresh');
    await delay(20);
    assert.equal(samplers, samplersAtStart, 'no sampler rebuilt for an unchanged config');
    assert.equal(hsflowd.calls.enable, enablesAtStart, 'no hsflowd reconcile churn');

    // Same config with its keys in another order is still unchanged.
    server.setMonitorConfig({ sflow: { hsflowd: { samplingRate: 400 }, port: 6343 }, source: 'sflow' });
    const f1 = server.configFetchCount();
    await waitFor(() => server.configFetchCount() >= f1 + 2, 4000, 'no periodic refresh');
    assert.equal(samplers, samplersAtStart, 'key order is not a change');

    // A switch assigned to the running agent is polled on the next cycle.
    server.setSnmpTargets([TARGET({ deviceId: 11 })]);
    const f2 = server.configFetchCount();
    await waitFor(() => server.configFetchCount() >= f2 + 2, 4000, 'no periodic refresh');
    await runtime.runSnmpCycleNow();
    assert.deepEqual(polled, [11]);
    assert.equal(samplers, samplersAtStart, 'a target change does not touch the sampler');

    // A changed traffic source rebuilds the sampler and turns the exporter off.
    const changed = onceEvent(runtime, 'config');
    server.setMonitorConfig({ source: 'proc' });
    const mc = await withTimeout(changed, 4000, 'changed config never applied');
    assert.equal(mc.source, 'proc');
    assert.equal(samplers, samplersAtStart + 1);
    assert.ok(stopped >= 1, 'the old sampler was stopped');
    await waitFor(() => hsflowd.calls.disable === 1, 2000, 'exporter not disabled');

    assert.equal(server.socketCount(), connections, 'all of it without a reconnect');
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('periodic refresh is off at 0 and skipped while disconnected', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const { runtime } = await startedRuntime(server, { configRefreshIntervalMs: 0 });
  try {
    const n = server.configFetchCount();
    await delay(150);
    assert.equal(server.configFetchCount(), n, 'no refresh when disabled');
  } finally {
    runtime.stop();
    await server.close();
  }

  // Disconnected: the WS is down (the server refuses the upgrade path) while
  // REST would answer — the refresh must wait for the reconnect's own load.
  const server2 = await startFakeServer({ validTokens: ['valid'] });
  const runtime2 = createAgentRuntime({
    config: makeConfig(server2, { configRefreshIntervalMs: 30 }),
    token: 'valid', agentId: 1, logger: silentLogger, collectLldp: noLldp,
    hsflowdManager: countingHsflowd(), snmpPoller: fakePoller(server2, []),
    WebSocketImpl: class NeverOpens extends require('events').EventEmitter {
      constructor() { super(); this.readyState = 0; }
      send() {}
      close() {}
      terminate() {}
      ping() {}
    },
  });
  try {
    runtime2.start();
    await waitFor(() => server2.configFetchCount() >= 1, 4000, 'bootstrap load never ran');
    const n = server2.configFetchCount();
    await delay(200);
    assert.equal(server2.configFetchCount(), n, 'no refresh while disconnected');
  } finally {
    runtime2.stop();
    await server2.close();
  }
});
