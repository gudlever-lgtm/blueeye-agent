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

test('sampleTraffic caps the interface list at the busiest N (veth farms vs the 64KiB result cap)', async () => {
  // 8 interfaces with distinct traffic; cap at 3 -> the 3 busiest survive,
  // totals still cover all 8, and the snapshot says how many were omitted.
  const line = (name, bytes) => `  ${name}: ${bytes} 1 0 0 0 0 0 0 ${bytes} 1 0 0 0 0 0 0`;
  const names = ['veth0', 'veth1', 'veth2', 'veth3', 'veth4', 'eth0', 'veth5', 'veth6'];
  const s1 = ['h', 'h', ...names.map((n) => line(n, 0))].join('\n');
  // eth0 moves the most bytes, veth6 second, veth5 third; the rest trickle.
  const traffic = { veth0: 10, veth1: 20, veth2: 30, veth3: 40, veth4: 50, eth0: 9000, veth5: 700, veth6: 800 };
  const s2 = ['h', 'h', ...names.map((n) => line(n, traffic[n]))].join('\n');
  const snaps = [s1, s2];
  let c = 0;
  const out = await sampleTraffic({
    readProc: () => snaps[c++],
    sleepFn: async () => {},
    intervalMs: 1000,
    now: (() => { const v = [1000, 2000]; let i = 0; return () => v[i++]; })(),
    readIfaceMeta: () => ({ operStatus: 'up', speedMbps: null }),
    maxInterfaces: 3,
  });
  assert.equal(out.interfaces.length, 3);
  assert.deepEqual(out.interfaces.map((i) => i.iface), ['eth0', 'veth6', 'veth5']); // busiest first
  assert.equal(out.interfacesOmitted, 5);
  // Totals still account for every interface, kept or omitted.
  assert.equal(out.totals.rxBytes, Object.values(traffic).reduce((s, v) => s + v, 0));
});

test('sampleTraffic under the cap keeps its original order and omits the marker field', async () => {
  const snapshots = [SNAP1, SNAP2];
  let call = 0;
  const out = await sampleTraffic({
    readProc: () => snapshots[call++],
    sleepFn: async () => {},
    intervalMs: 1000,
    maxInterfaces: 64,
  });
  assert.equal(out.interfaces.length, 1);
  assert.equal('interfacesOmitted' in out, false); // shape unchanged for normal hosts
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
