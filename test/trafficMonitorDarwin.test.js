'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { parseNetstatIb, sampleTraffic } = require('../src/trafficMonitorDarwin');

// Realistic netstat -ib output (macOS): Link lines + IPv4/IPv6 lines follow
const NETSTAT_SNAP1 = `
Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
lo0        16384 <Link#1>                          1000     0     100000     1000     0     100000     0
lo0        16384 127           127.0.0.1            500     0      50000      500     0      50000     0
en0         1500 <Link#4>    aa:bb:cc:dd:ee:ff     5000     2    1000000     4000     1    2000000     0
en0         1500 192.168.1   192.168.1.5           4800     0     980000     3900     0    1980000     0
`.trim();

const NETSTAT_SNAP2 = `
Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
lo0        16384 <Link#1>                          1010     0     101000     1010     0     101000     0
lo0        16384 127           127.0.0.1            505     0      50500      505     0      50500     0
en0         1500 <Link#4>    aa:bb:cc:dd:ee:ff     5200     3    1003000     4100     1    2004000     0
en0         1500 192.168.1   192.168.1.5           5000     1    1001000     4000     0    2003000     0
`.trim();

test('parseNetstatIb extracts only Link lines, skips IPv4/IPv6 rows', () => {
  const parsed = parseNetstatIb(NETSTAT_SNAP1);
  // Only 2 interfaces (lo0 + en0), not 4 rows
  assert.deepEqual(Object.keys(parsed).sort(), ['en0', 'lo0']);
  assert.deepEqual(parsed.en0, {
    rxPackets: 5000, rxErrors: 2, rxBytes: 1000000,
    txPackets: 4000, txErrors: 1, txBytes: 2000000,
  });
  assert.deepEqual(parsed.lo0, {
    rxPackets: 1000, rxErrors: 0, rxBytes: 100000,
    txPackets: 1000, txErrors: 0, txBytes: 100000,
  });
});

test('parseNetstatIb returns empty object on empty/bad input', () => {
  assert.deepEqual(parseNetstatIb(''), {});
  assert.deepEqual(parseNetstatIb('no link lines here\n127.0.0.1\n'), {});
});

test('sampleTraffic computes deltas and rates, excludes lo0 by default', async () => {
  const snaps = [NETSTAT_SNAP1, NETSTAT_SNAP2];
  let call = 0;
  const result = await sampleTraffic({
    runNetstatFn: () => Promise.resolve(parseNetstatIb(snaps[call++])),
    sleepFn: async () => {},
    intervalMs: 1000,
    now: (() => { const v = [1000, 2000]; let i = 0; return () => v[i++]; })(),
  });

  assert.equal(result.interfaces.length, 1); // lo0 excluded
  const en0 = result.interfaces[0];
  assert.equal(en0.iface, 'en0');
  assert.equal(en0.rxBytes, 3000);   // 1003000 - 1000000
  assert.equal(en0.txBytes, 4000);   // 2004000 - 2000000
  assert.equal(en0.rxPackets, 200);  // 5200 - 5000
  assert.equal(en0.txPackets, 100);  // 4100 - 4000
  assert.equal(en0.rxErrors, 1);     // 3 - 2
  assert.equal(en0.txErrors, 0);     // 1 - 1
  assert.equal(en0.rxDrop, 0);
  assert.equal(en0.txDrop, 0);
  assert.equal(en0.rxBytesPerSec, 3000);
  assert.equal(en0.txBytesPerSec, 4000);
  assert.equal(en0.operStatus, null);
  assert.equal(en0.speedMbps, null);
  assert.equal(result.totals.rxBytes, 3000);
  assert.equal(result.totals.txBytes, 4000);
  assert.equal(result.elapsedSec, 1);
  assert.equal(result.intervalMs, 1000);
});

test('sampleTraffic includes lo0 when includeLoopback is true', async () => {
  const snaps = [NETSTAT_SNAP1, NETSTAT_SNAP2];
  let call = 0;
  const result = await sampleTraffic({
    runNetstatFn: () => Promise.resolve(parseNetstatIb(snaps[call++])),
    sleepFn: async () => {},
    intervalMs: 1000,
    now: (() => { const v = [1000, 2000]; let i = 0; return () => v[i++]; })(),
    includeLoopback: true,
  });
  const names = result.interfaces.map((i) => i.iface);
  assert.ok(names.includes('lo0'));
});

test('sampleTraffic returns empty snapshot when netstat fails', async () => {
  const result = await sampleTraffic({
    runNetstatFn: () => Promise.resolve({}),
    sleepFn: async () => {},
    intervalMs: 1000,
    now: (() => { const v = [1000, 2000]; let i = 0; return () => v[i++]; })(),
  });
  assert.deepEqual(result.interfaces, []);
  assert.equal(result.totals.rxBytes, 0);
});

test('sampleTraffic delta clamps negative counters (wrap-around) to zero', async () => {
  const first = () => Promise.resolve({ en0: { rxBytes: 9999, txBytes: 9999, rxPackets: 100, txPackets: 100, rxErrors: 0, txErrors: 0 } });
  const second = () => Promise.resolve({ en0: { rxBytes: 100, txBytes: 100, rxPackets: 10, txPackets: 10, rxErrors: 0, txErrors: 0 } });
  let call = 0;
  const fns = [first, second];
  const result = await sampleTraffic({
    runNetstatFn: () => fns[call++](),
    sleepFn: async () => {},
    intervalMs: 1000,
    now: (() => { const v = [1000, 2000]; let i = 0; return () => v[i++]; })(),
  });
  assert.equal(result.interfaces[0].rxBytes, 0); // clamped, not negative
  assert.equal(result.interfaces[0].txBytes, 0);
});

test('sampleTraffic caps interface list and keeps totals over all interfaces', async () => {
  // 5 interfaces, cap at 2 — busiest survive, totals cover all
  const makeSnap = (bytes) => ({
    en0:  { rxBytes: bytes, txBytes: bytes, rxPackets: 1, txPackets: 1, rxErrors: 0, txErrors: 0 },
    en1:  { rxBytes: bytes * 2, txBytes: bytes * 2, rxPackets: 1, txPackets: 1, rxErrors: 0, txErrors: 0 },
    utun0: { rxBytes: bytes * 3, txBytes: bytes * 3, rxPackets: 1, txPackets: 1, rxErrors: 0, txErrors: 0 },
    utun1: { rxBytes: bytes * 4, txBytes: bytes * 4, rxPackets: 1, txPackets: 1, rxErrors: 0, txErrors: 0 },
    utun2: { rxBytes: bytes * 5, txBytes: bytes * 5, rxPackets: 1, txPackets: 1, rxErrors: 0, txErrors: 0 },
  });
  const snaps = [makeSnap(0), makeSnap(100)];
  let call = 0;
  const result = await sampleTraffic({
    runNetstatFn: () => Promise.resolve(snaps[call++]),
    sleepFn: async () => {},
    intervalMs: 1000,
    now: (() => { const v = [1000, 2000]; let i = 0; return () => v[i++]; })(),
    maxInterfaces: 2,
  });
  assert.equal(result.interfaces.length, 2);
  assert.equal(result.interfacesOmitted, 3);
  // utun2 (500) and utun1 (400) are busiest
  assert.equal(result.interfaces[0].iface, 'utun2');
  assert.equal(result.interfaces[1].iface, 'utun1');
  // totals = (100+200+300+400+500)*2 = 3000 rx + 3000 tx
  assert.equal(result.totals.rxBytes, 1500);
  assert.equal(result.totals.txBytes, 1500);
});
