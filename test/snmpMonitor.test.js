'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { sampleSnmp, toNumber } = require('../src/snmpMonitor');

test('sampleSnmp computes per-interface deltas and rates from two reads', async () => {
  const snapshots = [
    { 1: { name: 'Gi0/0', rxBytes: 1000, txBytes: 2000 }, 2: { name: 'Gi0/1', rxBytes: 0, txBytes: 0 } },
    { 1: { name: 'Gi0/0', rxBytes: 5000, txBytes: 8000 }, 2: { name: 'Gi0/1', rxBytes: 100, txBytes: 50 } },
  ];
  let call = 0;
  const traffic = await sampleSnmp({
    snmp: { host: '10.0.0.1' },
    intervalMs: 1000,
    readCounters: async () => snapshots[call++],
    sleepFn: async () => {},
    now: (() => { const v = [1000, 2000]; let i = 0; return () => v[i++]; })(),
  });

  assert.equal(traffic.source, 'snmp');
  assert.equal(traffic.interfaces.length, 2);
  const gi00 = traffic.interfaces.find((i) => i.iface === 'Gi0/0');
  assert.equal(gi00.rxBytes, 4000); // 5000 - 1000
  assert.equal(gi00.txBytes, 6000); // 8000 - 2000
  assert.equal(gi00.rxBytesPerSec, 4000); // over 1s
  assert.equal(traffic.totals.rxBytes, 4100);
  assert.equal(traffic.totals.txBytes, 6050);
});

test('sampleSnmp clamps counter resets to 0 (no negative deltas)', async () => {
  const snapshots = [
    { 1: { name: 'Gi0/0', rxBytes: 9000, txBytes: 9000 } },
    { 1: { name: 'Gi0/0', rxBytes: 10, txBytes: 20 } }, // counter reset
  ];
  let call = 0;
  const traffic = await sampleSnmp({
    snmp: { host: '10.0.0.1' },
    intervalMs: 1000,
    readCounters: async () => snapshots[call++],
    sleepFn: async () => {},
    now: (() => { const v = [0, 1000]; let i = 0; return () => v[i++]; })(),
  });
  assert.equal(traffic.interfaces[0].rxBytes, 0);
  assert.equal(traffic.interfaces[0].txBytes, 0);
});

test('sampleSnmp carries error/drop deltas + oper-status/speed through', async () => {
  const snapshots = [
    { 1: { name: 'Gi0/0', rxBytes: 0, txBytes: 0, rxErrors: 2, txErrors: 1, rxDrop: 5, txDrop: 0, operStatus: 'up', speedMbps: 1000 } },
    { 1: { name: 'Gi0/0', rxBytes: 0, txBytes: 0, rxErrors: 5, txErrors: 4, rxDrop: 9, txDrop: 0, operStatus: 'up', speedMbps: 1000 } },
  ];
  let call = 0;
  const traffic = await sampleSnmp({
    snmp: { host: '10.0.0.1' },
    intervalMs: 1000,
    readCounters: async () => snapshots[call++],
    sleepFn: async () => {},
    now: (() => { const v = [0, 1000]; let i = 0; return () => v[i++]; })(),
  });
  const gi00 = traffic.interfaces[0];
  assert.equal(gi00.rxErrors, 3); // 5 - 2
  assert.equal(gi00.txErrors, 3); // 4 - 1
  assert.equal(gi00.rxDrop, 4); // 9 - 5
  assert.equal(gi00.operStatus, 'up');
  assert.equal(gi00.speedMbps, 1000);
  assert.equal(traffic.totals.rxErrors, 3);
});

test('toNumber handles numbers and 64-bit Buffers', () => {
  assert.equal(toNumber(1234), 1234);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(9999n);
  assert.equal(toNumber(buf), 9999);
});
