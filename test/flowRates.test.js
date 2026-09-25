'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { aggregateFlows } = require('../src/netflow/aggregate');
const { createSflowCollector } = require('../src/sflow/collector');
const { createNetflowCollector } = require('../src/netflow/collector');

// A flow-sourced agent used to report byte counts and nothing else, so the
// dashboard's bandwidth columns — which read totals.rxBytesPerSec /
// txBytesPerSec, the fields the proc and SNMP samplers produce — showed 0 B/s
// forever, however much traffic was arriving. These pin the rates down.

const HOST = '10.0.0.5';
const FLOWS = [
  // Inbound to this host.
  { srcAddr: '1.1.1.1', dstAddr: HOST, srcPort: 443, dstPort: 51000, protocolName: 'tcp', bytes: 4000, packets: 20 },
  // Outbound from this host.
  { srcAddr: HOST, dstAddr: '1.1.1.1', srcPort: 51000, dstPort: 443, protocolName: 'tcp', bytes: 1000, packets: 10 },
  // Neither end is this host — a switch exporting its own ports.
  { srcAddr: '192.168.9.1', dstAddr: '192.168.9.2', srcPort: 4000, dstPort: 80, protocolName: 'tcp', bytes: 500, packets: 5 },
];

test('aggregateFlows splits the interval into rx/tx rates around the host', () => {
  const t = aggregateFlows(FLOWS, { elapsedSec: 10, localIps: [HOST] }).totals;
  assert.equal(t.rxBytes, 4000);
  assert.equal(t.txBytes, 1000);
  assert.equal(t.unattributedBytes, 500);
  assert.equal(t.rxBytesPerSec, 400);
  assert.equal(t.txBytesPerSec, 100);
  assert.equal(t.bytesPerSec, 550); // the whole interval, direction or not
  assert.equal(t.elapsedSec, 10);
});

test('every byte is counted exactly once', () => {
  const t = aggregateFlows(FLOWS, { elapsedSec: 10, localIps: [HOST] }).totals;
  assert.equal(t.rxBytes + t.txBytes + t.unattributedBytes, t.bytes);
});

test('an exporter that is not this host attributes no direction, and says so', () => {
  // A switch: none of its flows touch the agent's own addresses.
  const t = aggregateFlows(FLOWS, { elapsedSec: 10, localIps: ['172.16.0.9'] }).totals;
  assert.equal(t.rxBytesPerSec, 0);
  assert.equal(t.txBytesPerSec, 0);
  assert.equal(t.unattributedBytes, t.bytes);
  // The total rate is still real — the dashboard shows it, and says the
  // direction is unknown rather than showing a zero it cannot explain.
  assert.equal(t.bytesPerSec, 550);
});

test('a flow between two of the host\'s own addresses is counted in neither direction', () => {
  const t = aggregateFlows(
    [{ srcAddr: HOST, dstAddr: '10.0.0.6', srcPort: 1, dstPort: 80, protocolName: 'tcp', bytes: 900, packets: 9 }],
    { elapsedSec: 9, localIps: [HOST, '10.0.0.6'] }
  ).totals;
  assert.equal(t.rxBytes, 0);
  assert.equal(t.txBytes, 0);
  assert.equal(t.unattributedBytes, 900);
});

test('without an interval the totals are byte counts only (backward compatible)', () => {
  const t = aggregateFlows(FLOWS).totals;
  assert.equal(t.bytes, 5500);
  assert.equal(t.bytesPerSec, undefined);
  assert.equal(t.rxBytesPerSec, undefined);
  assert.equal(t.elapsedSec, undefined);
});

// The collectors measure the interval themselves: the rate must come from the
// time that actually elapsed between drains, not from the interval the caller
// asked for, or a slow sample overstates the bandwidth.
function fakeSocket() {
  return {
    on() {}, once() {}, close() {},
    bind(port, addr, cb) { cb(); },
  };
}

for (const [name, factory] of [['sFlow', createSflowCollector], ['NetFlow', createNetflowCollector]]) {
  test(`the ${name} collector measures the interval over the real elapsed time`, async () => {
    let clock = 1000;
    const c = factory({ createSocket: fakeSocket, now: () => clock, localIps: () => [HOST] });
    await c.start();
    clock += 8000;
    assert.equal(c.drain().totals.elapsedSec, 8);
    // The next interval starts where this one ended, not where the collector did.
    clock += 2000;
    assert.equal(c.drain().totals.elapsedSec, 2);
    c.stop();
  });
}

test('a failure to read the host addresses costs the split, never the snapshot', async () => {
  const c = createSflowCollector({
    createSocket: fakeSocket,
    now: () => 0,
    localIps: () => { throw new Error('no interfaces'); },
  });
  await c.start();
  const snap = c.drain();
  assert.equal(snap.source, 'sflow');
  assert.equal(snap.totals.bytes, 0);
  c.stop();
});
