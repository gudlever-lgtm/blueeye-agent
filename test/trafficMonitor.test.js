'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { parseProcNetDev, parseDuplex, sampleTraffic, buildSnapshot } = require('../src/trafficMonitor');

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
  // Updated deliberately: the parse now also keeps the fifo/frame/colls/carrier
  // columns (duplex + cabling detail), so the exact shape grew four keys.
  const zeroDetail = { rxFifo: 0, rxFrame: 0, txColls: 0, txCarrier: 0 };
  assert.deepEqual(parsed.eth0, { rxBytes: 1000, rxPackets: 10, rxErrors: 0, rxDrop: 0, txBytes: 2000, txPackets: 12, txErrors: 0, txDrop: 0, ...zeroDetail });
  assert.deepEqual(parsed.lo, { rxBytes: 100, rxPackets: 1, rxErrors: 0, rxDrop: 0, txBytes: 100, txPackets: 1, txErrors: 0, txDrop: 0, ...zeroDetail });
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

test('buildSnapshot (extracted for non-/proc sources, e.g. trafficMonitorWin.js) takes two cumulative-counter snapshots directly', async () => {
  const first = { eth0: { rxBytes: 1000, rxPackets: 10, rxErrors: 0, rxDrop: 0, txBytes: 2000, txPackets: 12, txErrors: 0, txDrop: 0 } };
  const second = { eth0: { rxBytes: 3000, rxPackets: 20, rxErrors: 1, rxDrop: 0, txBytes: 6000, txPackets: 24, txErrors: 0, txDrop: 2 } };
  const traffic = await buildSnapshot(first, second, {
    intervalMs: 1000,
    elapsedSec: 1,
    readIfaceMeta: () => ({ operStatus: 'Up', speedMbps: 1000 }),
  });
  assert.equal(traffic.interfaces.length, 1);
  const eth0 = traffic.interfaces[0];
  assert.equal(eth0.rxBytes, 2000);
  assert.equal(eth0.txBytes, 4000);
  assert.equal(eth0.rxErrors, 1);
  assert.equal(eth0.txDrop, 2);
  assert.equal(eth0.operStatus, 'Up');
  assert.equal(eth0.speedMbps, 1000);
  assert.equal(traffic.totals.rxBytes, 2000);
});

// A real /proc/net/dev from a host on a half-duplex 100 Mbit port (header lines
// verbatim from the kernel, column spacing as printed). eth1 is the damaged
// one: frame errors on receive, collisions + carrier errors on transmit.
const PROC_DUPLEX_1 = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 8123456   81234    0    0    0     0          0         0  8123456   81234    0    0    0     0       0          0
  eth0: 912345678 1234567    0    3    0     0          0      4521 45678901  234567    0    0    0     0       0          0
  eth1: 12345678   98765   42    0    7    40          0       120  9876543   87654   11    0    0   300       5          0
`;
const PROC_DUPLEX_2 = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 8123556   81235    0    0    0     0          0         0  8123556   81235    0    0    0     0       0          0
  eth0: 912445678 1234667    0    3    0     0          0      4521 45688901  234667    0    0    0     0       0          0
  eth1: 12445678   99765   52    0    9    48          0       120  9976543   88654   14    0    0   360       6          0
`;

test('parseProcNetDev reads fifo/frame (rx) and colls/carrier (tx) from a real /proc/net/dev', () => {
  const p = parseProcNetDev(PROC_DUPLEX_1);
  assert.equal(p.eth1.rxErrors, 42);
  assert.equal(p.eth1.rxFifo, 7);
  assert.equal(p.eth1.rxFrame, 40);
  assert.equal(p.eth1.txErrors, 11);
  assert.equal(p.eth1.txColls, 300);
  assert.equal(p.eth1.txCarrier, 5);
  assert.equal(p.eth0.rxDrop, 3);
  assert.equal(p.eth0.txColls, 0);
});

test('sampleTraffic reports duplex + frame/fifo/collision/carrier deltas per interval', async () => {
  const snaps = [PROC_DUPLEX_1, PROC_DUPLEX_2];
  let c = 0;
  const traffic = await sampleTraffic({
    readProc: () => snaps[c++],
    sleepFn: async () => {},
    now: (() => { const v = [0, 2000]; let i = 0; return () => v[i++]; })(),
    readIfaceMeta: async (iface) => (iface === 'eth1'
      ? { operStatus: 'up', speedMbps: 100, duplex: 'half' }
      : { operStatus: 'up', speedMbps: 1000, duplex: 'full' }),
  });
  const eth1 = traffic.interfaces.find((i) => i.iface === 'eth1');
  assert.equal(eth1.duplex, 'half');
  assert.equal(eth1.rxFrameErrors, 8);
  assert.equal(eth1.rxFifoErrors, 2);
  assert.equal(eth1.txCollisions, 60);
  assert.equal(eth1.txCarrierErrors, 1);
  const eth0 = traffic.interfaces.find((i) => i.iface === 'eth0');
  assert.equal(eth0.duplex, 'full');
  assert.equal(eth0.rxFrameErrors, 0);
  assert.equal(eth0.txCollisions, 0);
});

test('buildSnapshot: a source without the detail counters reports null, never 0', async () => {
  // Windows (trafficMonitorWin) feeds counters without fifo/frame/colls/carrier
  // and meta without duplex — "not measured" must stay distinguishable from
  // "measured zero", which is what rules a duplex mismatch out.
  const first = { eth0: { rxBytes: 1, txBytes: 1, rxPackets: 1, txPackets: 1, rxErrors: 0, txErrors: 0, rxDrop: 0, txDrop: 0 } };
  const second = { eth0: { rxBytes: 2, txBytes: 2, rxPackets: 2, txPackets: 2, rxErrors: 0, txErrors: 0, rxDrop: 0, txDrop: 0 } };
  const snap = await buildSnapshot(first, second, {
    intervalMs: 1000, elapsedSec: 1, readIfaceMeta: async () => ({ operStatus: 'up', speedMbps: 1000 }),
  });
  const e = snap.interfaces[0];
  assert.equal(e.duplex, null);
  assert.equal(e.rxFrameErrors, null);
  assert.equal(e.rxFifoErrors, null);
  assert.equal(e.txCollisions, null);
  assert.equal(e.txCarrierErrors, null);
});

test('parseDuplex accepts only the kernel vocabulary', () => {
  assert.equal(parseDuplex('full\n'), 'full');
  assert.equal(parseDuplex('half'), 'half');
  assert.equal(parseDuplex('unknown\n'), 'unknown');
  assert.equal(parseDuplex(''), null);
  assert.equal(parseDuplex('Invalid argument'), null);
  assert.equal(parseDuplex(null), null);
});
