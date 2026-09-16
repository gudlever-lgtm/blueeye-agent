'use strict';

// Late collisions off the EtherLike-MIB — the counter that names a duplex
// mismatch, and the one case where "absent" and "zero" must not be the same
// answer.

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { sampleSnmp, OID, toNumber } = require('../src/snmpMonitor');

const iface = (over = {}) => ({
  name: 'Gi0/1', rxBytes: 0, txBytes: 0, rxErrors: 0, txErrors: 0,
  rxDrop: 0, txDrop: 0, operStatus: 'up', speedMbps: 100, ...over,
});

// Two consecutive counter reads, in order.
function twoReads(first, second) {
  let call = 0;
  return async () => { call += 1; return call === 1 ? first : second; };
}

const sample = (readCounters) => sampleSnmp({ snmp: {}, intervalMs: 1, sleepFn: async () => {}, readCounters });

test('the EtherLike-MIB column is walked at the OID the RFC gives it', () => {
  assert.equal(OID.dot3StatsLateCollisions, '1.3.6.1.2.1.10.7.2.1.8');
});

test('late collisions are reported as the delta over the interval', async () => {
  const r = await sample(twoReads(
    { 1: iface({ lateCollisions: 5 }) },
    { 1: iface({ lateCollisions: 42 }) },
  ));
  assert.equal(r.interfaces[0].lateCollisions, 37);
});

test('a device that does not implement the counter reports null, not zero', async () => {
  // This is the whole point. EtherLike-MIB is optional, plenty of devices omit
  // it, and `toNumber(undefined)` is 0 — so collapsing the two would make a
  // switch that CANNOT report late collisions look exactly like a switch with a
  // clean link. Zero late collisions is what rules a duplex mismatch OUT.
  const r = await sample(twoReads({ 1: iface({ lateCollisions: null }) }, { 1: iface({ lateCollisions: null }) }));
  assert.equal(r.interfaces[0].lateCollisions, null);
});

test('a device that implements it and has none reports zero', async () => {
  const r = await sample(twoReads({ 1: iface({ lateCollisions: 0 }) }, { 1: iface({ lateCollisions: 0 }) }));
  assert.equal(r.interfaces[0].lateCollisions, 0);
});

test('a counter that appears or disappears mid-interval measures nothing', async () => {
  // One sample without the column means there is no interval to subtract over.
  // Reporting the other sample's raw total would be a lifetime count dressed up
  // as a rate.
  const appeared = await sample(twoReads({ 1: iface({ lateCollisions: null }) }, { 1: iface({ lateCollisions: 9 }) }));
  assert.equal(appeared.interfaces[0].lateCollisions, null);
  const vanished = await sample(twoReads({ 1: iface({ lateCollisions: 9 }) }, { 1: iface({ lateCollisions: null }) }));
  assert.equal(vanished.interfaces[0].lateCollisions, null);
});

test('a counter reset clamps to zero rather than going negative', async () => {
  const r = await sample(twoReads({ 1: iface({ lateCollisions: 900 }) }, { 1: iface({ lateCollisions: 3 }) }));
  assert.equal(r.interfaces[0].lateCollisions, 0);
});

test('the rest of the interface row is unchanged', async () => {
  const r = await sample(twoReads(
    { 1: iface({ rxBytes: 0, rxErrors: 1, lateCollisions: 0 }) },
    { 1: iface({ rxBytes: 1000, rxErrors: 4, lateCollisions: 0 }) },
  ));
  const i = r.interfaces[0];
  assert.equal(i.iface, 'Gi0/1');
  assert.equal(i.rxBytes, 1000);
  assert.equal(i.rxErrors, 3);
  assert.equal(i.speedMbps, 100);
  assert.equal(i.operStatus, 'up');
  assert.equal(r.source, 'snmp');
});

test('a walk that returns no EtherLike column at all still produces a sample', async () => {
  // `safe()` swallows the failed walk, so the field is simply missing from the
  // row the reader builds. The sample must survive that — the octet counters are
  // the point of the poll and an optional MIB must never cost them.
  const bare = { 1: { name: 'Gi0/1', rxBytes: 0, txBytes: 0, rxErrors: 0, txErrors: 0, rxDrop: 0, txDrop: 0 } };
  const bare2 = { ...bare, 1: { ...bare[1], rxBytes: 500 } };
  const r = await sample(twoReads(bare, bare2));
  assert.equal(r.interfaces.length, 1);
  assert.equal(r.interfaces[0].rxBytes, 500);
  assert.equal(r.interfaces[0].lateCollisions, null);
});

test('toNumber still turns an absent value into 0 — which is why the reader checks for the key instead', () => {
  assert.equal(toNumber(undefined), 0);
  assert.equal(toNumber(null), 0);
  assert.equal(toNumber(7), 7);
});
