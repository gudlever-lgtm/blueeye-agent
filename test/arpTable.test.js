'use strict';

// Unit tests for the ARP/neighbour table collector (src/arpTable.js).
//
// The parsers are pure, so the exact byte-level formats are tested without
// needing a host that happens to have the right tool installed. Collection is
// tested with an injected execFile/readFile, including every failure path — this
// runs on the capabilities hot path and must never throw.

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  collectArpTable,
  parseProcNetArp,
  parseIpNeigh,
  parseArpDashAn,
  parseWindowsArp,
  normalizeMac,
  isUsableMac,
  dedupeByIp,
} = require('../src/arpTable');

const PROC_NET_ARP = [
  'IP address       HW type     Flags       HW address            Mask     Device',
  '192.168.1.1      0x1         0x2         00:11:22:33:44:55     *        eth0',
  '192.168.1.50     0x1         0x2         00:1a:2b:3c:4d:5e     *        eth0',
  '192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        eth0',
].join('\n');

// ------------------------------------------------------------------ normalise
test('normalizeMac accepts colon and dash forms, lowercased', () => {
  assert.equal(normalizeMac('00:11:22:33:44:55'), '00:11:22:33:44:55');
  assert.equal(normalizeMac('00-11-22-33-44-55'), '00:11:22:33:44:55');
  assert.equal(normalizeMac('00:11:22:33:44:55'.toUpperCase()), '00:11:22:33:44:55');
  assert.equal(normalizeMac('nope'), null);
  assert.equal(normalizeMac(null), null);
});

test('isUsableMac drops broadcast/multicast/incomplete but keeps virtual hosts', () => {
  assert.equal(isUsableMac('00:11:22:33:44:55'), true);
  assert.equal(isUsableMac('00:00:00:00:00:00'), false);
  assert.equal(isUsableMac('ff:ff:ff:ff:ff:ff'), false);
  assert.equal(isUsableMac('01:00:5e:00:00:16'), false);
  assert.equal(isUsableMac('33:33:00:00:00:01'), false);
  // Locally administered unicast — VMs and containers are real hosts.
  assert.equal(isUsableMac('02:42:ac:11:00:02'), true);
  assert.equal(isUsableMac('aa:bb:cc:dd:ee:ff'), true);
});

// -------------------------------------------------------------------- parsers
test('parseProcNetArp honours the complete flag', () => {
  assert.deepEqual(parseProcNetArp(PROC_NET_ARP), [
    { ip: '192.168.1.1', mac: '00:11:22:33:44:55', interface: 'eth0' },
    { ip: '192.168.1.50', mac: '00:1a:2b:3c:4d:5e', interface: 'eth0' },
  ]);
});

test('parseIpNeigh handles IPv6 and skips FAILED/INCOMPLETE', () => {
  const text = [
    '192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE',
    '192.168.1.9 dev eth0 FAILED',
    '10.0.0.7 dev eth1 lladdr 02:42:ac:11:00:02 INCOMPLETE',
    'fe80::1%eth0 dev eth0 lladdr 00:1a:2b:3c:4d:5e router REACHABLE',
  ].join('\n');
  assert.deepEqual(parseIpNeigh(text), [
    { ip: '192.168.1.1', mac: '00:11:22:33:44:55', interface: 'eth0' },
    { ip: 'fe80::1', mac: '00:1a:2b:3c:4d:5e', interface: 'eth0' },
  ]);
});

test('parseArpDashAn handles the BSD/macOS form and skips <incomplete>', () => {
  const text = [
    '? (192.168.1.1) at 00:11:22:33:44:55 [ether] on en0',
    '? (192.168.1.7) at <incomplete> on en0',
    'gw (10.0.0.1) at 00:1a:2b:3c:4d:5e on en0 ifscope [ethernet]',
  ].join('\n');
  assert.deepEqual(parseArpDashAn(text), [
    { ip: '192.168.1.1', mac: '00:11:22:33:44:55', interface: 'en0' },
    { ip: '10.0.0.1', mac: '00:1a:2b:3c:4d:5e', interface: 'en0' },
  ]);
});

test('parseWindowsArp carries the Interface: header across rows', () => {
  const text = [
    'Interface: 192.168.1.34 --- 0xb',
    '  Internet Address      Physical Address      Type',
    '  192.168.1.1           00-11-22-33-44-55     dynamic',
    '  192.168.1.255         ff-ff-ff-ff-ff-ff     static',
    '  192.168.1.60          00-1a-2b-3c-4d-5e     dynamic',
  ].join('\r\n');
  assert.deepEqual(parseWindowsArp(text), [
    { ip: '192.168.1.1', mac: '00:11:22:33:44:55', interface: '192.168.1.34' },
    { ip: '192.168.1.60', mac: '00:1a:2b:3c:4d:5e', interface: '192.168.1.34' },
  ]);
});

test('every parser survives empty and garbage input', () => {
  for (const parse of [parseProcNetArp, parseIpNeigh, parseArpDashAn, parseWindowsArp]) {
    for (const input of ['', null, undefined, 'total nonsense\nmore nonsense']) {
      assert.deepEqual(parse(input), []);
    }
  }
});

// --------------------------------------------------------------------- dedupe
test('dedupeByIp keeps the first occurrence and applies the cap', () => {
  // First-wins keeps repeated reports idempotent when /proc and `ip neigh`
  // both mention an address.
  const deduped = dedupeByIp([
    { ip: '10.0.0.1', mac: '00:11:22:33:44:55', interface: 'eth0' },
    { ip: '10.0.0.1', mac: '00:1a:2b:3c:4d:5e', interface: 'eth1' },
    { ip: '10.0.0.2', mac: '00:1a:2b:3c:4d:5e', interface: 'eth0' },
  ], 10);
  assert.equal(deduped.length, 2);
  assert.equal(deduped[0].mac, '00:11:22:33:44:55');

  const many = Array.from({ length: 50 }, (_, i) => ({ ip: `10.0.0.${i}`, mac: '00:11:22:33:44:55', interface: null }));
  assert.equal(dedupeByIp(many, 5).length, 5);
});

// ----------------------------------------------------------------- collection
test('Linux collection reads /proc/net/arp and merges ip neigh for IPv6', () => {
  const readFileFn = (p) => { if (p === '/proc/net/arp') return PROC_NET_ARP; throw new Error('ENOENT'); };
  const execFileFn = (cmd, args, opts, cb) => {
    if (cmd === 'ip') return cb(null, 'fe80::1 dev eth0 lladdr 00:aa:bb:cc:dd:01 REACHABLE');
    return cb(new Error('not found'));
  };
  return collectArpTable({ platform: 'linux', readFileFn, execFileFn }).then((entries) => {
    assert.deepEqual(entries.map((e) => e.ip), ['192.168.1.1', '192.168.1.50', 'fe80::1']);
  });
});

test('Linux collection falls back to arp -an when /proc and ip are unavailable', async () => {
  const readFileFn = () => { throw new Error('ENOENT'); };
  const execFileFn = (cmd, args, opts, cb) => {
    if (cmd === 'arp') return cb(null, '? (192.168.1.1) at 00:11:22:33:44:55 [ether] on eth0');
    return cb(new Error('not found'));
  };
  const entries = await collectArpTable({ platform: 'linux', readFileFn, execFileFn });
  assert.deepEqual(entries, [{ ip: '192.168.1.1', mac: '00:11:22:33:44:55', interface: 'eth0' }]);
});

test('macOS and Windows collection use their own tool', async () => {
  const calls = [];
  const execFileFn = (cmd, args, opts, cb) => {
    calls.push([cmd, args.join(' ')]);
    if (cmd === 'arp' && args[0] === '-an') return cb(null, '? (10.0.0.1) at 00:11:22:33:44:55 on en0');
    if (cmd === 'arp' && args[0] === '-a') {
      return cb(null, 'Interface: 10.0.0.9 --- 0x1\n  10.0.0.1   00-11-22-33-44-55  dynamic');
    }
    return cb(new Error('not found'));
  };

  const mac = await collectArpTable({ platform: 'darwin', execFileFn });
  assert.equal(mac[0].ip, '10.0.0.1');
  const win = await collectArpTable({ platform: 'win32', execFileFn });
  assert.equal(win[0].ip, '10.0.0.1');
  assert.deepEqual(calls.map((c) => c[1]), ['-an', '-a']);
});

test('collection returns [] rather than throwing when everything fails', async () => {
  const readFileFn = () => { throw new Error('ENOENT'); };
  const execFileFn = (cmd, args, opts, cb) => cb(new Error('command not found'));
  for (const platform of ['linux', 'darwin', 'win32']) {
    assert.deepEqual(await collectArpTable({ platform, readFileFn, execFileFn }), []);
  }
});

test('collection returns [] when execFile throws synchronously', async () => {
  // A locked-down container can make spawn throw outright rather than call back.
  const execFileFn = () => { throw new Error('EPERM'); };
  const readFileFn = () => { throw new Error('ENOENT'); };
  assert.deepEqual(await collectArpTable({ platform: 'linux', readFileFn, execFileFn }), []);
});

test('collection applies the entry cap', async () => {
  // A busy L3 switch can hold tens of thousands of neighbours; one capabilities
  // POST must not become a very large write.
  const lines = Array.from({ length: 5000 }, (_, i) =>
    `10.0.${Math.floor(i / 250)}.${i % 250}      0x1   0x2   00:11:22:33:44:55   *   eth0`);
  const readFileFn = () => lines.join('\n');
  const execFileFn = (cmd, args, opts, cb) => cb(new Error('not found'));
  const entries = await collectArpTable({ platform: 'linux', readFileFn, execFileFn, cap: 100 });
  assert.equal(entries.length, 100);
});
