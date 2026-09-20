'use strict';

// Trin 3, agent side: one snapshot of a switch's interface counters.
//
// The shape is deliberately NOT snmpMonitor's. That one reads twice, subtracts,
// and sends rates — right when an agent measures itself at a cadence it owns,
// wrong here for two reasons this file pins:
//
//   * ONE read per cycle, not two. Twenty switches at forty columns is already
//     a lot of walking.
//   * The RAW counter is the evidence. Without it a rate can never be
//     recomputed, a reset can never be recognised after the fact, and a missing
//     cycle cannot be told from a cycle that measured zero.

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { pollSnmpCounters, defaultReadCounters } = require('../src/snmp/counters');
const { createSnmpPoller } = require('../src/snmpPoller');
const { IF_MIB, ETHERLIKE, SYSTEM } = require('../src/snmp/oids');

// A fake net-snmp whose walks answer from a table of { oid: { ifIndex: value } }.
function fakeSnmp(columns, { uptime = 500000, failOids = [] } = {}) {
  return {
    Version1: 0,
    Version2c: 1,
    createSession: () => ({
      subtree(oid, maxRep, feed, done) {
        if (failOids.includes(oid)) return done(new Error('RequestTimedOutError'));
        const col = columns[oid];
        if (!col) return done(null); // a column the device does not implement
        feed(Object.entries(col).map(([idx, value]) => ({ oid: `${oid}.${idx}`, type: 4, value })));
        return done(null);
      },
      get(oids, cb) {
        cb(null, oids.map((o) => ({
          oid: o, type: 4, value: o === SYSTEM.sysUpTime ? uptime : null,
        })));
      },
      close() {},
    }),
  };
}

const HC_TABLE = {
  [IF_MIB.ifHCInOctets]: { 1: 1000, 2: 2000 },
  [IF_MIB.ifHCOutOctets]: { 1: 500, 2: 700 },
  [IF_MIB.ifName]: { 1: 'Gi0/1', 2: 'Gi0/2' },
  [IF_MIB.ifInErrors]: { 1: 0, 2: 4 },
  [IF_MIB.ifInDiscards]: { 1: 0, 2: 0 },
};

// ================================================================= the read
test('a snapshot carries the RAW counters, not a rate', async () => {
  const out = await defaultReadCounters({ host: '10.14.0.11' }, { snmp: fakeSnmp(HC_TABLE) });
  assert.equal(out.interfaces.length, 2);
  const [a, b] = out.interfaces;
  assert.equal(a.ifIndex, 1);
  assert.equal(a.ifName, 'Gi0/1');
  assert.equal(a.inOctets, 1000);
  assert.equal(b.inErrors, 4);
  assert.equal(out.hc, true, 'the 64-bit columns answered');
});

test('the device clock rides along on every read', async () => {
  // Every delta the server computes from this snapshot is only valid if the
  // device did not restart since the last one. This is the field that says.
  const out = await defaultReadCounters({ host: '10.14.0.11' }, { snmp: fakeSnmp(HC_TABLE, { uptime: 987654 }) });
  assert.equal(out.sysUpTimeTicks, 987654);
});

test('a device with no ifXTable falls back to the 32-bit columns, and says so', async () => {
  const narrow = {
    [IF_MIB.ifInOctets]: { 1: 10 },
    [IF_MIB.ifOutOctets]: { 1: 20 },
    [IF_MIB.ifInErrors]: { 1: 1 },
  };
  const out = await defaultReadCounters({ host: '10.14.0.11' }, { snmp: fakeSnmp(narrow) });
  assert.equal(out.hc, false, 'the server needs to know a wrap cannot be reasoned about');
  assert.equal(out.interfaces[0].inOctets, 10);
});

test('a device with BOTH is read once, not twice', async () => {
  // Reading the narrow columns on a device that has the wide ones would double
  // the walk to produce the same numbers less reliably.
  const oids = [];
  const snmp = {
    Version1: 0,
    Version2c: 1,
    createSession: () => ({
      subtree(oid, maxRep, feed, done) {
        oids.push(oid);
        const col = { ...HC_TABLE, [IF_MIB.ifInOctets]: { 1: 99 } }[oid];
        if (col) feed(Object.entries(col).map(([i, v]) => ({ oid: `${oid}.${i}`, type: 4, value: v })));
        done(null);
      },
      get(o, cb) { cb(null, []); },
      close() {},
    }),
  };
  await defaultReadCounters({ host: '10.14.0.11' }, { snmp });
  assert.ok(!oids.includes(IF_MIB.ifInOctets), 'the narrow octet column was never walked');
});

test('an EtherLike column the device lacks is NULL, never zero', async () => {
  // Zero FCS errors is what RULES OUT a bad cable. A device that cannot count
  // them has ruled out nothing, and the two must not read the same.
  const out = await defaultReadCounters({ host: '10.14.0.11' }, { snmp: fakeSnmp(HC_TABLE) });
  assert.equal(out.interfaces[0].fcsErrors, null);
  assert.equal(out.interfaces[0].lateCollisions, null);

  const withEther = { ...HC_TABLE, [ETHERLIKE.dot3StatsFCSErrors]: { 1: 0, 2: 12 } };
  const out2 = await defaultReadCounters({ host: '10.14.0.11' }, { snmp: fakeSnmp(withEther) });
  assert.equal(out2.interfaces[0].fcsErrors, 0, 'a measured zero is a measurement');
  assert.equal(out2.interfaces[1].fcsErrors, 12);
});

test('one failed column does not cost the other thirty-nine', async () => {
  const snmp = fakeSnmp(HC_TABLE, { failOids: [ETHERLIKE.dot3StatsFCSErrors, IF_MIB.ifInErrors] });
  const out = await defaultReadCounters({ host: '10.14.0.11' }, { snmp });
  assert.equal(out.interfaces.length, 2);
  assert.equal(out.interfaces[0].inOctets, 1000);
  assert.equal(out.interfaces[0].inErrors, null);
});

test('duplex is named, because half against full is the fault it describes', async () => {
  const table = { ...HC_TABLE, [ETHERLIKE.dot3StatsDuplexStatus]: { 1: 3, 2: 2 } };
  const out = await defaultReadCounters({ host: '10.14.0.11' }, { snmp: fakeSnmp(table) });
  assert.equal(out.interfaces[0].duplex, 'full');
  assert.equal(out.interfaces[1].duplex, 'half');
});

test('a runaway walk is capped, and the count of what was dropped travels', async () => {
  const big = { [IF_MIB.ifHCInOctets]: {}, [IF_MIB.ifName]: {} };
  for (let i = 1; i <= 50; i += 1) { big[IF_MIB.ifHCInOctets][i] = i; big[IF_MIB.ifName][i] = `Gi0/${i}`; }
  const out = await defaultReadCounters({ host: '10.14.0.11' }, { snmp: fakeSnmp(big), maxInterfaces: 10 });
  assert.equal(out.interfaces.length, 10);
  assert.equal(out.truncated, 40);
});

test('pollSnmpCounters stamps the AGENT clock, which is what elapsed time is measured from', async () => {
  const at = new Date('2026-09-20T12:00:00.000Z');
  const out = await pollSnmpCounters({
    device: { deviceId: 4, host: '10.14.0.11' },
    readCounters: async () => ({ sysUpTimeTicks: 42, hc: true, interfaces: [] }),
    now: () => at,
  });
  assert.equal(out.deviceId, 4);
  assert.equal(out.readAt, at.toISOString());
  assert.equal(out.sysUpTimeTicks, 42);
});

test('a poll with no host is refused rather than aimed at nothing', async () => {
  await assert.rejects(() => pollSnmpCounters({ device: { deviceId: 1 } }), /needs a device with a host/);
});

// =========================================================== the counter cycle
const TARGET = (over = {}) => ({
  deviceId: 1, host: '10.14.0.11', port: 161, version: '2c', community: 'public',
  collect: ['ifcounters'], counterIntervalSec: 60, ...over,
});

function makePoller(over = {}) {
  const submitted = [];
  const polled = [];
  const poller = createSnmpPoller({
    submit: async () => {},
    submitCounters: async (payload) => { submitted.push(payload); },
    pollCounters: async ({ device }) => { polled.push(device.deviceId); return { deviceId: device.deviceId, interfaces: [] }; },
    ...over,
  });
  return { poller, submitted, polled };
}

test('only devices that ASKED for counters are in the counter cycle', async () => {
  // The volume is opt-in per device: `collect` already decides what a device is
  // polled for, and counters are just another kind.
  const { poller, polled } = makePoller();
  poller.setTargets([TARGET(), TARGET({ deviceId: 2, collect: ['fdb'] })]);
  await poller.runCounterCycle({ force: true });
  assert.deepEqual(polled, [1]);
});

test('the counter interval is floored, so nobody can configure a tight loop', async () => {
  let t = 1000;
  const { poller, polled } = makePoller({ now: () => t });
  poller.setTargets([TARGET({ counterIntervalSec: 1 })]);
  await poller.runCounterCycle();
  t += 10000; // ten seconds later
  await poller.runCounterCycle();
  assert.deepEqual(polled, [1], 'ten seconds is under the 30-second floor');
  t += 25000;
  await poller.runCounterCycle();
  assert.deepEqual(polled, [1, 1]);
});

test('the counter schedule is kept APART from the topology schedule', async () => {
  // A device whose bridge-table walk is timing out may well still answer a
  // counter read, and one cycle's bad luck must not stall the other's clock.
  let t = 1000;
  const polledTopology = [];
  const { poller, polled } = makePoller({
    now: () => t,
    poll: async ({ device }) => { polledTopology.push(device.deviceId); return { deviceId: device.deviceId }; },
  });
  poller.setTargets([TARGET({ intervalSec: 300 })]);
  await poller.runCycle();
  await poller.runCounterCycle();
  t += 61000;
  await poller.runCounterCycle();
  assert.deepEqual(polled, [1, 1], 'the counter cycle ran twice');
  assert.deepEqual(polledTopology, [1], 'the topology cycle is still waiting out its 300s');
});

test('devices are polled a FEW at a time — not all at once, not one at a time', async () => {
  // Sequential does not fit: twenty devices at a 30-second worst case is ten
  // minutes against a wanted minute. All at once is the burst that looks like a
  // scan. Both failure modes are real, so the cycle is bounded.
  let inFlight = 0;
  let peak = 0;
  const { poller } = makePoller({
    counterConcurrency: 4,
    pollCounters: async ({ device }) => {
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 5));
      inFlight -= 1;
      return { deviceId: device.deviceId, interfaces: [] };
    },
  });
  poller.setTargets(Array.from({ length: 12 }, (_, i) => TARGET({ deviceId: i + 1 })));
  await poller.runCounterCycle({ force: true });
  assert.equal(peak, 4, `peaked at ${peak}`);
});

test('one device failing costs that device and nothing else', async () => {
  const { poller, submitted } = makePoller({
    pollCounters: async ({ device }) => {
      if (device.deviceId === 2) throw new Error('RequestTimedOutError');
      return { deviceId: device.deviceId, interfaces: [] };
    },
  });
  poller.setTargets([TARGET(), TARGET({ deviceId: 2 }), TARGET({ deviceId: 3 })]);
  const r = await poller.runCounterCycle({ force: true });
  assert.equal(r.polled, 2);
  assert.equal(r.failed, 1);
  assert.equal(submitted[0].errors[0].deviceId, 2);
  assert.match(submitted[0].errors[0].error, /RequestTimedOutError/);
});

test('a cycle already running is skipped, not queued', async () => {
  let release;
  const gate = new Promise((r) => { release = r; });
  const { poller } = makePoller({ pollCounters: async () => { await gate; return { interfaces: [] }; } });
  poller.setTargets([TARGET()]);
  const first = poller.runCounterCycle({ force: true });
  const second = await poller.runCounterCycle({ force: true });
  assert.equal(second.skipped, true);
  release();
  await first;
});

test('with no counter endpoint wired the cycle does nothing at all', async () => {
  // An older server, or a fleet that does not want the volume.
  const poller = createSnmpPoller({ submit: async () => {} });
  poller.setTargets([TARGET()]);
  const r = await poller.runCounterCycle({ force: true });
  assert.equal(r.skipped, true);
  assert.equal(r.polled, 0);
});

test('a failed submit is NOT held for a retry', async () => {
  // A counter snapshot is only meaningful next to the reading before it.
  // Re-sending a stale one later has the server compute a rate across a gap
  // that never happened.
  const seen = [];
  const { poller } = makePoller({
    submitCounters: async (payload) => {
      seen.push(payload);
      if (seen.length === 1) throw new Error('503');
    },
  });
  poller.setTargets([TARGET()]);
  await assert.rejects(() => poller.runCounterCycle({ force: true }), /503/);
  await poller.runCounterCycle({ force: true });
  assert.equal(seen.length, 2);
  assert.equal(seen[1].devices.length, 1, 'the second cycle sent its OWN reading, not the stale one');
});
