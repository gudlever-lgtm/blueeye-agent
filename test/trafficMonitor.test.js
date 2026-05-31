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

test('parseProcNetDev extracts rx/tx bytes and packets per interface', () => {
  const parsed = parseProcNetDev(SNAP1);
  assert.deepEqual(parsed.eth0, { rxBytes: 1000, rxPackets: 10, txBytes: 2000, txPackets: 12 });
  assert.deepEqual(parsed.lo, { rxBytes: 100, rxPackets: 1, txBytes: 100, txPackets: 1 });
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
