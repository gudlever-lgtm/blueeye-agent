'use strict';

// Catalyst IOS implements no Q-BRIDGE-MIB. Two things follow, both found by
// the end-to-end run against the full snmpsim-data Cisco 3750 recording:
//
//   * its VLAN NAMES are in CISCO-VTP-MIB vtpVlanName, not dot1qVlanStaticName
//     — the agent reported 0 VLANs for a switch with 274 of them;
//   * its FORWARDING TABLE is one BRIDGE-MIB instance per VLAN, served only
//     under community string indexing ("community@<vlan>"; v3 context
//     "vlan-<vlan>") — the agent read VLAN 1's, 15 MACs, and nothing else.
//
// The VTP rows below are the recording's own (test/fixtures/snmprec/
// cisco-c3750.snmprec). The recording holds only the DEFAULT instance, which
// on IOS is VLAN 1's table, so the other VLANs' tables are synthetic and
// served by a fake session keyed by community.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');

const { loadSnmprec, createSnmprecSession, TYPES } = require('../test-support/snmprec');
const {
  defaultReadTables, buildTopology, parseVtpVlans, vlanCredential, MAX_VLAN_FDB_WALKS,
} = require('../src/snmpTopology');
const { BRIDGE, Q_BRIDGE, CISCO_VTP } = require('../src/snmp/oids');

const C3750 = loadSnmprec(path.join(__dirname, 'fixtures', 'snmprec', 'cisco-c3750.snmprec'));
const COLLECT = ['if', 'fdb', 'lldp', 'vlan'];
const DEVICE = { host: 'recorded', community: 'public', version: '2c' };

const int = (oid, value) => ({ oid, type: TYPES.Integer, value });
const macOid = (base, mac) => `${base}.${mac.split(':').map((h) => parseInt(h, 16)).join('.')}`;
// One VLAN's BRIDGE-MIB instance: { mac: bridgePort } plus its own port map.
function vlanTable(fdb, basePorts) {
  const vbs = [];
  for (const [bp, ifIndex] of Object.entries(basePorts)) vbs.push(int(`${BRIDGE.dot1dBasePortIfIndex}.${bp}`, ifIndex));
  for (const [mac, bp] of Object.entries(fdb)) {
    vbs.push(int(macOid(BRIDGE.dot1dTpFdbPort, mac), bp));
    vbs.push(int(macOid(BRIDGE.dot1dTpFdbStatus, mac), 3));
  }
  return vbs;
}
// The recording's own default-instance FDB rows, as VLAN 1's table.
const VLAN1 = C3750.filter((vb) => vb.oid.startsWith(`${BRIDGE.dot1dTpFdbPort}.`)
  || vb.oid.startsWith(`${BRIDGE.dot1dTpFdbStatus}.`) || vb.oid.startsWith(`${BRIDGE.dot1dBasePortIfIndex}.`));

// vlanSession fake: a recording per community, an empty table otherwise, and
// a log of every credential it was asked to open.
function sessionsByCommunity(tables, { fail = () => false } = {}) {
  const opened = [];
  const open = (device) => {
    opened.push(device);
    if (fail(device)) throw Object.assign(new Error('RequestTimedOutError'), { code: 'ETIMEDOUT' });
    const key = device.v3 ? device.v3.context : device.community;
    return createSnmprecSession(tables[key] || []);
  };
  return { opened, open };
}

// ---------------------------------------------------------------- VLAN names
test('VTP: operational VLANs, reserved 1002-1005 left out, one per VLAN', () => {
  const name = (d, v, n) => ({ [`${d}.${v}`]: n });
  const vlans = parseVtpVlans(
    { ...name(1, 1, 'default'), ...name(1, 20, 'Office'), ...name(1, 1002, 'fddi-default'), ...name(1, 30, 'Down'), ...name(2, 20, 'Other domain') },
    { '1.1': 1, '1.20': 1, '1.1002': 1, '1.30': 2, '2.20': 1 },
  );
  assert.deepEqual(vlans, [{ vlan: 1, name: 'default' }, { vlan: 20, name: 'Office' }]);
  assert.deepEqual(parseVtpVlans({ 7: 'no domain' }, {}), [], 'malformed index');
});

test('Catalyst 3750 (recording): VLAN names come from CISCO-VTP-MIB', async () => {
  const session = createSnmprecSession(C3750);
  const topo = buildTopology(await defaultReadTables(DEVICE, { collect: COLLECT, session }));
  // 278 vtpVlanName rows in the recording, 4 of them the reserved defaults.
  assert.equal(topo.vlans.length, 274);
  assert.deepEqual(topo.vlans[0], { vlan: 1, name: 'default' });
  assert.ok(topo.vlans.some((v) => v.vlan === 100 && v.name === 'VLAN0100'));
  assert.deepEqual(topo.vlans[topo.vlans.length - 1], { vlan: 4000, name: 'VLAN4000' });
  assert.ok(!topo.vlans.some((v) => v.vlan >= 1002 && v.vlan <= 1005));
  assert.ok(topo.supported.includes('vlan'));
  assert.ok(session.calls.subtree.includes(CISCO_VTP.vtpVlanName));
});

test('a device with Q-BRIDGE is not asked for VTP at all, and opens no per-VLAN session', async () => {
  const q = [
    { oid: `${Q_BRIDGE.dot1qVlanStaticName}.20`, type: TYPES.OctetString, value: Buffer.from('Office') },
    int(`${Q_BRIDGE.dot1qTpFdbPort}.20.0.80.86.1.2.3`, 1),
    int(`${BRIDGE.dot1dBasePortIfIndex}.1`, 1),
    // VTP rows too, to prove they are not read when Q-BRIDGE answered.
    { oid: `${CISCO_VTP.vtpVlanName}.1.30`, type: TYPES.OctetString, value: Buffer.from('vtp') },
  ];
  const session = createSnmprecSession(q);
  const v = sessionsByCommunity({});
  const topo = buildTopology(await defaultReadTables(DEVICE, { collect: COLLECT, session, vlanCursor: new Map(), vlanSession: v.open }));
  assert.deepEqual(topo.vlans, [{ vlan: 20, name: 'Office' }]);
  assert.ok(!session.calls.subtree.includes(CISCO_VTP.vtpVlanName));
  assert.equal(v.opened.length, 0);
  assert.equal(topo.fdb[0].vlan, 20);
});

// ------------------------------------------------------------ per-VLAN FDB
test('vlanCredential: community@vlan on v1/v2c, context vlan-<id> on v3, nothing without a credential', () => {
  assert.equal(vlanCredential({ host: 'h', community: 'c0mm', version: '2c' }, 100).community, 'c0mm@100');
  assert.equal(vlanCredential({ host: 'h', community: 'c0mm', version: '1' }, 5).community, 'c0mm@5');
  const v3 = vlanCredential({ host: 'h', version: '3', v3: { user: 'u', authKey: 'k', authProto: 'sha' } }, 7);
  assert.equal(v3.v3.context, 'vlan-7');
  assert.equal(v3.v3.user, 'u');
  assert.equal(vlanCredential({ host: 'h' }, 7), null, 'no community: never guessed');
  assert.equal(vlanCredential({ host: 'h', version: '3' }, 7), null);
});

test('Catalyst 3750: each VLAN\'s table is read under community@vlan, tagged, resolved through its own port map, deduped', async () => {
  const V100_MAC = '00:50:56:aa:00:01';
  const V1_MAC = '00:11:21:e7:f1:17'; // in the recording's default table
  const v = sessionsByCommunity({
    'public@1': VLAN1,
    // VLAN 100's instance numbers its bridge ports differently (bridge port 3
    // is Gi1/0/7 here, not in the default instance): its own map must win.
    'public@100': vlanTable({ [V100_MAC]: 3 }, { 3: 10107 }),
    // A MAC the default instance also lists — reported once, tagged.
    'public@21': vlanTable({ [V1_MAC]: 7 }, { 7: 10107 }),
  });
  const session = createSnmprecSession(C3750);
  const tables = await defaultReadTables(DEVICE, { collect: COLLECT, session, vlanSession: v.open, vlanCursor: new Map() });
  const topo = buildTopology(tables);

  // The first poll: the first 64 non-reserved VLANs, in order, with the exact community.
  assert.equal(v.opened.length, MAX_VLAN_FDB_WALKS);
  assert.deepEqual(v.opened.slice(0, 3).map((d) => d.community), ['public@1', 'public@2', 'public@21']);
  assert.ok(v.opened.every((d) => /^public@\d+$/.test(d.community) && d.host === 'recorded'));
  assert.ok(!v.opened.some((d) => /@100[2-5]$/.test(d.community)));

  const v100 = topo.fdb.filter((r) => r.vlan === 100);
  assert.deepEqual(v100.map((r) => [r.mac, r.bridgePort, r.ifIndex, r.ifName]), [[V100_MAC, 3, 10107, 'Gi1/0/7']]);

  // VLAN 1's table is the default instance: every recorded MAC comes back
  // tagged 1 (or 21 for the one VLAN 21 also has), none as untagged VLAN 0.
  const recorded = VLAN1.filter((vb) => vb.oid.startsWith(`${BRIDGE.dot1dTpFdbPort}.`)).length;
  assert.equal(recorded, 15);
  assert.equal(topo.fdb.filter((r) => r.vlan === 0).length, 0, 'no untagged duplicate');
  assert.equal(topo.fdb.filter((r) => r.vlan === 1).length, 15);
  assert.equal(topo.fdb.filter((r) => r.mac === V1_MAC).length, 2, 'the same MAC in two VLANs is two rows');
  const keys = new Set(topo.fdb.map((r) => `${r.vlan}|${r.mac}`));
  assert.equal(keys.size, topo.fdb.length, 'one row per (vlan, mac)');
  for (const r of topo.fdb) assert.match(r.ifName, /^Gi1\/0\/\d+$/);
  assert.ok(topo.supported.includes('fdb'));

  // 274 VLANs, 64 read this poll; the rest rotate in on the following polls.
  assert.deepEqual(topo.partial, [{ kind: 'fdb', reason: 'rotating', vlans: 64, of: 274 }]);
});

test('Catalyst 3750: VLANs beyond the first 64 rotate in over the following polls; VLAN 1 is read every poll', async () => {
  // Found end to end: on a 274-VLAN switch a MAC in VLAN 336 (the 65th) was
  // never collected, because every poll read the same first 64.
  const cursor = new Map();
  const seen = new Set();
  const perPoll = [];
  for (let poll = 0; poll < 6; poll += 1) {
    const v = sessionsByCommunity({ 'public@1': VLAN1 });
    // eslint-disable-next-line no-await-in-loop
    await defaultReadTables(DEVICE, { collect: COLLECT, session: createSnmprecSession(C3750), vlanSession: v.open, vlanCursor: cursor });
    const vlans = v.opened.map((d) => Number(d.community.split('@')[1]));
    perPoll.push(vlans);
    for (const x of vlans) seen.add(x);
  }
  for (const vlans of perPoll) {
    assert.equal(vlans.length, MAX_VLAN_FDB_WALKS);
    assert.ok(vlans.includes(1), 'the default VLAN every poll');
  }
  assert.notDeepEqual(perPoll[0], perPoll[1], 'the second poll reads other VLANs');
  // 273 rotating VLANs at 63 a poll: five polls cover every one of the 274.
  assert.equal(seen.size, 274);
  assert.ok(seen.has(336));
});

test('a device that does not answer community@vlan: the walk gives up early, the default table stands', async () => {
  const v = sessionsByCommunity({}, { fail: () => true });
  const session = createSnmprecSession(C3750);
  const topo = buildTopology(await defaultReadTables(DEVICE, { collect: COLLECT, session, vlanCursor: new Map(), vlanSession: v.open }));
  assert.ok(v.opened.length <= 3 + 3, `gave up after ${v.opened.length} VLANs`);
  assert.equal(topo.fdb.length, 15, 'the default instance is still reported');
  assert.ok(topo.fdb.every((r) => r.vlan === 0));
  assert.equal(topo.partial[0].kind, 'fdb');
  assert.equal(topo.partial[0].reason, 'error');
  assert.equal(topo.partial[0].vlans, 0);
});

test('per-VLAN walks run inside the optional-phase budget and never cost the core tables', async () => {
  // Every VLAN session hangs: its walks feed nothing and never finish.
  const hanging = () => ({
    subtree() {}, get(o, cb) { setImmediate(() => cb(null, [])); }, close() {},
  });
  const session = createSnmprecSession(C3750);
  const t0 = Date.now();
  const topo = buildTopology(await defaultReadTables(DEVICE, {
    collect: COLLECT, session, vlanCursor: new Map(), vlanSession: hanging, timeoutMs: 600,
  }));
  assert.ok(Date.now() - t0 < 2000, `bounded: ${Date.now() - t0} ms`);
  assert.equal(topo.fdb.length, 15, 'core forwarding table intact');
  assert.equal(topo.vlans.length, 274, 'core VLAN names intact');
  assert.equal(topo.interfaces.length, 19);
  assert.equal(topo.partial[0].kind, 'fdb');
  assert.equal(topo.partial[0].reason, 'timeout');
});

test('SNMPv3: the per-VLAN session carries the vlan-<id> context', async () => {
  const v3dev = { host: 'recorded', version: '3', v3: { user: 'ro', authKey: 'k', authProto: 'sha' } };
  const v = sessionsByCommunity({ 'vlan-100': vlanTable({ '00:50:56:aa:00:09': 3 }, { 3: 10107 }) });
  const session = createSnmprecSession(C3750);
  const topo = buildTopology(await defaultReadTables(v3dev, { collect: COLLECT, session, vlanCursor: new Map(), vlanSession: v.open }));
  assert.ok(v.opened.every((d) => /^vlan-\d+$/.test(d.v3.context) && d.v3.user === 'ro'));
  assert.equal(topo.fdb.filter((r) => r.vlan === 100).length, 1);
});

test('an injected session with no vlanSession opens nothing else (tests and direct callers)', async () => {
  const session = createSnmprecSession(C3750);
  const tables = await defaultReadTables(DEVICE, { collect: COLLECT, session });
  assert.deepEqual(tables.vlanFdb, []);
  assert.equal(buildTopology(tables).fdb.length, 15);
});
