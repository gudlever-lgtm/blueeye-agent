'use strict';

// Tests for the SNMP poller (src/snmpPoller.js) and its wiring into the runtime.
//
// The poller is what breaks the 1:1 binding — one agent, many switches,
// alongside its own traffic sampling. What has to hold:
//
//   * one device failing costs that device's turn and nothing else;
//   * the per-device interval is respected and floored, so nobody can configure
//     a tight loop against a production switch;
//   * a stale poll result is never re-sent, because a forwarding table is a
//     snapshot and a late one claims a device is somewhere it has left.

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { startFakeServer } = require('../test-support/fakeServer');
const { createAgentRuntime } = require('../src/runtime');
const { silentLogger } = require('../src/logger');
const { createSnmpPoller, MIN_INTERVAL_SEC } = require('../src/snmpPoller');

function withTimeout(promise, ms, message) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(message || `timeout after ${ms}ms`)), ms);
    timer.unref();
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}
const onceEvent = (emitter, name) => new Promise((resolve) => emitter.once(name, resolve));

const TARGET = (over = {}) => ({
  deviceId: 7, host: '10.14.0.11', port: 161, version: '2c',
  community: 'public', collect: ['if', 'fdb'], intervalSec: 300, ...over,
});

const RESULT = (deviceId = 7) => ({
  deviceId,
  interfaces: [{ ifIndex: 10002, ifName: 'GigabitEthernet0/2', ifAlias: null }],
  fdb: [{ mac: '00:1b:44:11:3a:b7', vlan: 20, bridgePort: 2, ifIndex: 10002, ifName: 'GigabitEthernet0/2', status: 'learned', portMacCount: 1 }],
  fdbTruncated: false, fdbTotal: 1, neighbours: [], vlans: [{ vlan: 20, name: 'Kontor' }],
  supported: ['if', 'fdb', 'vlan'],
});

// ------------------------------------------------------------------ scheduling
test('a device is polled once and then waits out its interval', async () => {
  let clock = 1_000_000;
  const polls = [];
  const submits = [];
  const p = createSnmpPoller({
    submit: async (payload) => { submits.push(payload); },
    poll: async ({ device }) => { polls.push(device.deviceId); return RESULT(device.deviceId); },
    now: () => clock,
  });
  p.setTargets([TARGET({ intervalSec: 300 })]);

  assert.deepEqual(await p.runCycle(), { polled: 1, failed: 0 });
  assert.deepEqual(await p.runCycle(), { polled: 0, failed: 0 }, 'not due yet');
  assert.equal(submits.length, 1, 'and nothing is submitted for an empty cycle');

  clock += 300_000;
  assert.deepEqual(await p.runCycle(), { polled: 1, failed: 0 });
  assert.equal(polls.length, 2);
});

test('the interval is floored, so nobody can configure a tight loop', async () => {
  // A full bridge-table walk is the expensive call on this path; a one-second
  // interval against a production switch is a way to become the outage.
  let clock = 1_000_000;
  const polls = [];
  const p = createSnmpPoller({
    submit: async () => {},
    poll: async ({ device }) => { polls.push(clock); return RESULT(device.deviceId); },
    now: () => clock,
  });
  p.setTargets([TARGET({ intervalSec: 1 })]);

  await p.runCycle();
  clock += 30_000;
  await p.runCycle();
  assert.equal(polls.length, 1, `still inside the ${MIN_INTERVAL_SEC}s floor`);

  clock += 31_000;
  await p.runCycle();
  assert.equal(polls.length, 2);
});

test('force ignores the interval, for a manual "poll now"', async () => {
  const p = createSnmpPoller({ submit: async () => {}, poll: async ({ device }) => RESULT(device.deviceId) });
  p.setTargets([TARGET()]);
  await p.runCycle();
  assert.equal((await p.runCycle({ force: true })).polled, 1);
});

// ------------------------------------------------------------------ isolation
test('one switch failing costs that switch and nothing else', async () => {
  const submits = [];
  const p = createSnmpPoller({
    submit: async (payload) => { submits.push(payload); },
    poll: async ({ device }) => {
      if (device.deviceId === 8) throw Object.assign(new Error('Timeout'), { code: 'SNMP_TIMEOUT' });
      return RESULT(device.deviceId);
    },
  });
  p.setTargets([TARGET({ deviceId: 7 }), TARGET({ deviceId: 8, host: '10.22.0.5' }), TARGET({ deviceId: 9, host: '10.14.0.12' })]);

  const r = await p.runCycle();
  assert.deepEqual(r, { polled: 2, failed: 1 });

  const [batch] = submits;
  assert.deepEqual(batch.devices.map((d) => d.deviceId).sort(), [7, 9]);
  assert.equal(batch.errors.length, 1);
  assert.equal(batch.errors[0].deviceId, 8);
  assert.equal(batch.errors[0].code, 'SNMP_TIMEOUT');
  assert.match(batch.errors[0].error, /Timeout/);
});

test('a device that hangs is abandoned without holding the cycle open', async () => {
  const p = createSnmpPoller({
    submit: async () => {},
    poll: ({ device }) => (device.deviceId === 8
      ? new Promise(() => {}) // never settles
      : Promise.resolve(RESULT(device.deviceId))),
    timeoutMs: 40,
  });
  p.setTargets([TARGET({ deviceId: 8 }), TARGET({ deviceId: 7 })]);
  const r = await withTimeout(p.runCycle(), 3000, 'the cycle hung');
  assert.equal(r.polled, 1);
  assert.equal(r.failed, 1);
});

test('an error message is bounded', async () => {
  const submits = [];
  const p = createSnmpPoller({
    submit: async (payload) => { submits.push(payload); },
    poll: async () => { throw new Error('x'.repeat(5000)); },
  });
  p.setTargets([TARGET()]);
  await p.runCycle();
  assert.ok(submits[0].errors[0].error.length <= 255);
});

// ------------------------------------------------------------------ submitting
test('a failed submit does NOT hold the results for a retry', async () => {
  // A forwarding table is a snapshot of a moment. Re-sending a stale one later
  // would claim a device is somewhere it has since left.
  let submits = 0;
  let polls = 0;
  const p = createSnmpPoller({
    submit: async (payload) => {
      submits += 1;
      // Each attempt must carry exactly ONE device — never a growing backlog.
      assert.equal(payload.devices.length, 1, 'no accumulated backlog');
      throw new Error('server down');
    },
    poll: async ({ device }) => { polls += 1; return RESULT(device.deviceId); },
  });
  p.setTargets([TARGET()]);

  await assert.rejects(() => p.runCycle(), /server down/);
  assert.equal(polls, 1);
  assert.equal(submits, 1);

  // The next cycle is a FRESH poll on its own schedule, not a replay of the
  // one that failed to send.
  await assert.rejects(() => p.runCycle({ force: true }), /server down/);
  assert.equal(polls, 2, 'polled again rather than re-sending stale rows');
  assert.equal(submits, 2);
});

test('an empty target list submits nothing at all', async () => {
  let calls = 0;
  const p = createSnmpPoller({ submit: async () => { calls += 1; }, poll: async () => RESULT() });
  p.setTargets([]);
  assert.deepEqual(await p.runCycle(), { polled: 0, failed: 0 });
  assert.equal(calls, 0);
});

test('re-assigning targets drops the schedule of devices that went away', async () => {
  let clock = 1_000_000;
  const polls = [];
  const p = createSnmpPoller({
    submit: async () => {},
    poll: async ({ device }) => { polls.push(device.deviceId); return RESULT(device.deviceId); },
    now: () => clock,
  });
  p.setTargets([TARGET({ deviceId: 7 })]);
  await p.runCycle();
  assert.deepEqual(polls, [7]);

  // 7 is removed and re-added: it must be polled again immediately rather than
  // inheriting the interval it had already spent.
  p.setTargets([TARGET({ deviceId: 8, host: '10.14.0.12' })]);
  p.setTargets([TARGET({ deviceId: 7 })]);
  await p.runCycle();
  assert.deepEqual(polls, [7, 7]);
});

test('setTargets ignores junk and reports the count it kept', () => {
  const p = createSnmpPoller({ submit: async () => {}, poll: async () => RESULT() });
  assert.equal(p.setTargets([TARGET(), { deviceId: 9 }, null, 'x', { host: '' }]), 1);
  assert.equal(p.setTargets(null), 0);
  assert.equal(p.setTargets('nope'), 0);
});

test('a cycle already running is not started twice', async () => {
  let inFlight = 0;
  let maxInFlight = 0;
  const p = createSnmpPoller({
    submit: async () => {},
    poll: async ({ device }) => {
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((r) => { const t = setTimeout(r, 20); t.unref(); });
      inFlight -= 1;
      return RESULT(device.deviceId);
    },
  });
  p.setTargets([TARGET({ deviceId: 7 }), TARGET({ deviceId: 8, host: '10.14.0.12' })]);

  const [a, b] = await Promise.all([p.runCycle(), p.runCycle()]);
  assert.equal(maxInFlight, 1, 'devices are polled sequentially, not in a burst');
  assert.ok(a.skipped || b.skipped, 'the second overlapping cycle stood down');
});

test('stop is idempotent and safe before start', () => {
  const p = createSnmpPoller({ submit: async () => {}, poll: async () => RESULT() });
  p.stop();
  p.start({ tickMs: 0 });
  p.stop();
  p.stop();
});

// ------------------------------------------------------------------ the runtime
const makeConfig = (server, extra = {}) => ({
  serverUrl: server.url,
  heartbeatMs: 10000,
  backoff: { baseMs: 30, maxMs: 120, factor: 2 },
  reportIntervalMs: 0,
  probeIntervalMs: 0,
  syslogEnabled: false,
  ...extra,
});
const noopHsflowd = {
  enable: async () => ({ state: 'active', detail: null }),
  disable: async () => ({ state: 'inactive', detail: null }),
  status: async () => ({ state: 'unknown', detail: null }),
};

test('the agent picks up the switches the server assigned to it', async () => {
  const server = await startFakeServer({
    validTokens: ['valid'],
    snmpTargets: [TARGET()],
  });
  const runtime = createAgentRuntime({
    config: makeConfig(server),
    token: 'valid',
    agentId: 1,
    logger: silentLogger,
    hsflowdManager: noopHsflowd,
    snmpPoller: createSnmpPoller({
      submit: (payload) => server.postSnmpTopology(payload),
      poll: async ({ device }) => RESULT(device.deviceId),
    }),
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config loaded');

    const r = await runtime.runSnmpCycleNow();
    assert.equal(r.polled, 1);
    assert.equal(server.receivedSnmpTopology.length, 1);
    assert.equal(server.receivedSnmpTopology[0].devices[0].fdb[0].ifName, 'GigabitEthernet0/2');
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('a server that sends no targets makes the agent poll nothing', async () => {
  // An agent talking to a server too old to send the key must do exactly what
  // it did before, not error.
  const server = await startFakeServer({ validTokens: ['valid'] });
  const runtime = createAgentRuntime({
    config: makeConfig(server),
    token: 'valid',
    agentId: 1,
    logger: silentLogger,
    hsflowdManager: noopHsflowd,
    snmpPoller: createSnmpPoller({
      submit: async () => { throw new Error('should not submit'); },
      poll: async () => { throw new Error('should not poll'); },
    }),
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config loaded');
    assert.deepEqual(await runtime.runSnmpCycleNow(), { polled: 0, failed: 0 });
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('the monitor source is untouched by an SNMP assignment', async () => {
  // The 1:1 binding stays exactly as it was: an agent measuring its own /proc
  // keeps doing that while ALSO polling switches.
  const server = await startFakeServer({
    validTokens: ['valid'],
    monitorConfig: { source: 'proc' },
    snmpTargets: [TARGET()],
  });
  const runtime = createAgentRuntime({
    config: makeConfig(server),
    token: 'valid',
    agentId: 1,
    logger: silentLogger,
    hsflowdManager: noopHsflowd,
    snmpPoller: createSnmpPoller({ submit: async () => {}, poll: async ({ device }) => RESULT(device.deviceId) }),
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config loaded');
    assert.equal(runtime.getMonitorConfig().source, 'proc');
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('a rejected token during an SNMP submit is fatal, as everywhere else', async () => {
  const server = await startFakeServer({ validTokens: ['valid'], snmpTargets: [TARGET()] });
  const runtime = createAgentRuntime({
    config: makeConfig(server),
    token: 'valid',
    agentId: 1,
    logger: silentLogger,
    hsflowdManager: noopHsflowd,
    snmpPoller: createSnmpPoller({
      submit: async () => { throw Object.assign(new Error('401'), { code: 'TOKEN_REJECTED' }); },
      poll: async ({ device }) => RESULT(device.deviceId),
    }),
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config loaded');
    const fatal = onceEvent(runtime, 'fatal');
    await runtime.runSnmpCycleNow();
    assert.equal(await withTimeout(fatal, 4000, 'no fatal emitted'), 'rest-token-rejected');
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('the diagnose snapshot says which switches this agent polls', async () => {
  const server = await startFakeServer({ validTokens: ['valid'], snmpTargets: [TARGET()] });
  const runtime = createAgentRuntime({
    config: makeConfig(server),
    token: 'valid',
    agentId: 1,
    logger: silentLogger,
    hsflowdManager: noopHsflowd,
    snmpPoller: createSnmpPoller({ submit: async () => {}, poll: async ({ device }) => RESULT(device.deviceId) }),
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config loaded');

    const reply = server.waitForWsMessage((m) => m.type === 'command-result' && m.id === 's1');
    server.sendCommandToAll({ name: 'diagnose', id: 's1' });
    const msg = await withTimeout(reply, 4000, 'no diagnose reply');

    assert.equal(msg.diagnostic.snmp.targets, 1);
    assert.equal(msg.diagnostic.snmp.devices[0].host, '10.14.0.11');
    assert.equal(msg.diagnostic.snmp.devices[0].intervalSec, 300);
  } finally {
    runtime.stop();
    await server.close();
  }
});

// ------------------------------------------------------- the credential gate
// The server resolves ONE credential per device and an agent may only walk with
// a community assigned to it. A target with none is still sent — so the
// dashboard can say "sw-lager-1: no SNMP community assigned" instead of a
// switch that silently never appears — and the poller must refuse it rather
// than fall back to 'public'.
test('a target with no community is refused, and nothing reaches the wire', async () => {
  const polls = [];
  const submits = [];
  const p = createSnmpPoller({
    submit: async (payload) => { submits.push(payload); },
    poll: async ({ device }) => { polls.push(device.deviceId); return RESULT(device.deviceId); },
  });
  p.setTargets([TARGET({ deviceId: 7, community: null })]);

  assert.deepEqual(await p.runCycle(), { polled: 0, failed: 1 });
  assert.deepEqual(polls, [], 'no session was opened');
  const [err] = submits[0].errors;
  assert.equal(err.deviceId, 7);
  assert.equal(err.code, 'SNMP_NO_CREDENTIAL');
});

test('the refusal says WHICH of the two reasons it is', async () => {
  // "This site has no community" and "this agent is not assigned the one it
  // has" send an admin to two different screens.
  const submits = [];
  const p = createSnmpPoller({
    submit: async (payload) => { submits.push(payload); },
    poll: async () => { throw new Error('must not be reached'); },
  });
  p.setTargets([
    TARGET({ deviceId: 7, community: null, credentialBlocked: true }),
    TARGET({ deviceId: 8, community: null }),
  ]);

  await p.runCycle();
  const [blocked, missing] = submits[0].errors;
  assert.match(blocked.error, /not assigned/);
  assert.match(missing.error, /no SNMP community is configured/i);
});

test('a v3 target with a user needs no community', async () => {
  // v3 authenticates with a user and keys; a community string is a v1/v2c
  // concept and its absence there is not a missing credential.
  const polls = [];
  const p = createSnmpPoller({
    submit: async () => {},
    poll: async ({ device }) => { polls.push(device.deviceId); return RESULT(device.deviceId); },
  });
  p.setTargets([TARGET({ deviceId: 7, version: '3', community: null, v3: { user: 'blueeye' } })]);
  assert.deepEqual(await p.runCycle(), { polled: 1, failed: 0 });
  assert.deepEqual(polls, [7]);
});

// Found end to end: two "Poll now" presses at the same moment — the second
// found a cycle running and answered "0 of 2 polled" with no reason.
test('a forced poll that finds a cycle running waits for it and runs its own; a timer tick still skips', async () => {
  let release;
  const gate = new Promise((r) => { release = r; });
  let calls = 0;
  const p = createSnmpPoller({
    submit: async () => {},
    poll: async ({ device }) => { calls += 1; if (calls === 1) await gate; return RESULT(device.deviceId); },
  });
  p.setTargets([TARGET()]);

  const first = p.runCycle({ force: true });
  await new Promise((r) => setImmediate(r)); // the first cycle is now in flight
  assert.deepEqual(await p.runCycle(), { polled: 0, failed: 0, skipped: true }, 'a tick skips, as before');
  const second = p.runCycle({ force: true, waitIfRunning: true });
  release();
  assert.deepEqual(await first, { polled: 1, failed: 0 });
  assert.deepEqual(await second, { polled: 1, failed: 0 }, 'the waiting poll ran its own cycle');
  assert.equal(calls, 2);
});
