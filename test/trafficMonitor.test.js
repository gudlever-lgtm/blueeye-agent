'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { parseProcNetDev, sampleTraffic } = require('../src/trafficMonitor');

const SNAP1 = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:     100       1    0    0    0     0          0         0      100       1    0    0    0     0       0          0
  eth0:    1000      10    0    0    0     0          0         0     2000      12    0    0    0     0       0          0`;

const SNAP2 = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:     150       2    0    0    0     0          0         0      150       2    0    0    0     0       0          0
  eth0:    3000      20    0    0    0     0          0         0     6000      24    0    0    0     0       0          0`;

test('parseProcNetDev extracts rx/tx bytes, packets, errors and drops per interface', () => {
  const parsed = parseProcNetDev(SNAP1);
  assert.deepEqual(parsed.eth0, { rxBytes: 1000, rxPackets: 10, rxErrors: 0, rxDrop: 0, txBytes: 2000, txPackets: 12, txErrors: 0, txDrop: 0 });
  assert.deepEqual(parsed.lo, { rxBytes: 100, rxPackets: 1, rxErrors: 0, rxDrop: 0, txBytes: 100, txPackets: 1, txErrors: 0, txDrop: 0 });
});

test('parseProcNetDev reads the error/drop columns', () => {
  const txt = 'h\nh\n  eth0: 1000 10 3 4 0 0 0 0 2000 12 5 6 0 0 0 0';
  const p = parseProcNetDev(txt);
  assert.equal(p.eth0.rxErrors, 3);
  assert.equal(p.eth0.rxDrop, 4);
  assert.equal(p.eth0.txErrors, 5);
  assert.equal(p.eth0.txDrop, 6);
});

test('sampleTraffic includes error/drop deltas + injected interface meta', async () => {
  const s1 = 'h\nh\n  eth0: 1000 10 1 1 0 0 0 0 2000 12 1 1 0 0 0 0';
  const s2 = 'h\nh\n  eth0: 3000 20 4 2 0 0 0 0 6000 24 6 3 0 0 0 0';
  const snaps = [s1, s2];
  let c = 0;
  const traffic = await sampleTraffic({
    readProc: () => snaps[c++],
    sleepFn: async () => {},
    intervalMs: 1000,
    now: (() => { const v = [1000, 2000]; let i = 0; return () => v[i++]; })(),
    readIfaceMeta: () => ({ operStatus: 'up', speedMbps: 1000 }),
  });
  const e = traffic.interfaces[0];
  assert.equal(e.rxErrors, 3); // 4-1
  assert.equal(e.txErrors, 5); // 6-1
  assert.equal(e.rxDrop, 1); // 2-1
  assert.equal(e.txDrop, 2); // 3-1
  assert.equal(e.operStatus, 'up');
  assert.equal(e.speedMbps, 1000);
  assert.equal(traffic.totals.rxErrors, 3);
});

test('sampleTraffic computes per-interface deltas and rates (loopback excluded)', async () => {
  const snapshots = [SNAP1, SNAP2];
  let call = 0;
  const traffic = await sampleTraffic({
    readProc: () => snapshots[call++],
    sleepFn: async () => {},
    now: (() => {
      const values = [1000, 2000]; // 1 second elapsed
      let i = 0;
      return () => values[i++];
    })(),
    intervalMs: 1000,
  });

  assert.equal(traffic.interfaces.length, 1); // lo excluded
  const eth0 = traffic.interfaces[0];
  assert.equal(eth0.iface, 'eth0');
  assert.equal(eth0.rxBytes, 2000); // 3000 - 1000
  assert.equal(eth0.txBytes, 4000); // 6000 - 2000
  assert.equal(eth0.rxBytesPerSec, 2000); // over 1s
  assert.equal(eth0.txBytesPerSec, 4000);
  assert.equal(traffic.totals.rxBytes, 2000);
  assert.equal(traffic.totals.txBytes, 4000);
});

test('sampleTraffic returns empty interfaces when /proc is unreadable', async () => {
  const traffic = await sampleTraffic({
    readProc: () => {
      throw new Error('no /proc');
    },
    sleepFn: async () => {},
    intervalMs: 10,
  });
  assert.deepEqual(traffic.interfaces, []);
  assert.equal(traffic.totals.rxBytes, 0);
});
