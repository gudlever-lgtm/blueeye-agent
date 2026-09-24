'use strict';

// SNMP walks of two REAL switches (snmpsim recordings, see
// test/fixtures/snmprec/README.md) through the agent's own readers:
// defaultReadTables → buildTopology, and defaultReadCounters. The other SNMP
// tests hand-build a few varbinds; these are what a ProCurve and a Catalyst
// actually answer — gaps in the tables, loopbacks, VLAN interfaces, a bridge
// port numbering that is not the ifIndex, counters above 2^47.
//
// Assertions are on well-formedness and on facts read straight out of the
// recording, not on a snapshot of the output, so a new field in the topology
// does not break them.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');

const {
  loadSnmprec, parseSnmprec, createSnmprecSession, createSnmprecModule,
} = require('../test-support/snmprec');
const { defaultReadTables, buildTopology } = require('../src/snmpTopology');
const { defaultReadCounters, pollSnmpCounters } = require('../src/snmp/counters');
const { toNumber } = require('../src/snmp/session');

const DIR = path.join(__dirname, 'fixtures', 'snmprec');
const rec = (name) => loadSnmprec(path.join(DIR, `${name}.snmprec`));
const COLLECT = ['if', 'fdb', 'lldp', 'vlan', 'cdp'];

const MAC = /^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/;
const STATUS = new Set(['up', 'down', 'testing', 'unknown', 'dormant', 'notPresent', 'lowerLayerDown']);

async function topologyOf(name) {
  const session = createSnmprecSession(rec(name));
  const tables = await defaultReadTables({ host: 'recorded' }, { collect: COLLECT, session });
  assert.equal(session.closed, true, 'the reader closes the session it was handed');
  return { tables, topo: buildTopology(tables) };
}

// Facts straight from the recording, for cross-checks.
function column(varbinds, base) {
  const out = new Map();
  for (const vb of varbinds) if (vb.oid.startsWith(`${base}.`)) out.set(vb.oid.slice(base.length + 1), vb.value);
  return out;
}

function assertWellFormed(topo, name) {
  assert.ok(Number.isInteger(topo.sysUpTimeTicks) && topo.sysUpTimeTicks > 0, `${name}: sysUpTime`);
  assert.ok(topo.sysName, `${name}: sysName`);

  const ifIndexes = new Set();
  for (const i of topo.interfaces) {
    assert.ok(Number.isInteger(i.ifIndex) && i.ifIndex > 0, `${name}: ifIndex ${i.ifIndex}`);
    assert.ok(!ifIndexes.has(i.ifIndex), `${name}: ifIndex ${i.ifIndex} once`);
    ifIndexes.add(i.ifIndex);
    assert.equal(typeof i.ifName, 'string');
    assert.ok(i.ifName.length > 0);
    if (i.adminStatus != null) assert.ok(STATUS.has(i.adminStatus), `${name}: admin ${i.adminStatus}`);
    if (i.operStatus != null) assert.ok(STATUS.has(i.operStatus), `${name}: oper ${i.operStatus}`);
    if (i.physAddress != null) assert.match(i.physAddress, MAC, `${name}: ${i.ifName} mac`);
    if (i.speedMbps != null) assert.ok(Number.isInteger(i.speedMbps) && i.speedMbps >= 0);
  }

  for (const r of topo.fdb) {
    assert.match(r.mac, MAC, `${name}: fdb mac`);
    assert.ok(Number.isInteger(r.bridgePort) && r.bridgePort > 0, `${name}: bridge port`);
    assert.ok(Number.isInteger(r.vlan) && r.vlan >= 0 && r.vlan <= 4094, `${name}: vlan ${r.vlan}`);
    assert.ok(!['self', 'invalid'].includes(r.status), `${name}: ${r.status} never reported`);
    assert.ok(Number.isInteger(r.portMacCount) && r.portMacCount >= 1);
    // Resolved through dot1dBasePortIfIndex, onto a port that exists — or
    // honestly null, never invented.
    if (r.ifIndex != null) {
      assert.ok(ifIndexes.has(r.ifIndex), `${name}: fdb ifIndex ${r.ifIndex} is a real port`);
      assert.equal(r.ifName, topo.interfaces.find((i) => i.ifIndex === r.ifIndex).ifName);
    } else {
      assert.equal(r.ifName, null);
    }
  }
  const keys = new Set(topo.fdb.map((r) => `${r.vlan}|${r.mac}`));
  assert.equal(keys.size, topo.fdb.length, `${name}: one row per (vlan, mac)`);

  for (const n of topo.neighbours) {
    assert.ok(['lldp', 'cdp'].includes(n.protocol), `${name}: protocol ${n.protocol}`);
    assert.ok(typeof n.remoteChassisId === 'string' && n.remoteChassisId.length > 0, `${name}: chassis id`);
    assert.ok(Number.isInteger(n.localPort) && n.localPort > 0, `${name}: local port`);
  }
  for (const v of topo.vlans) {
    assert.ok(Number.isInteger(v.vlan) && v.vlan >= 1 && v.vlan <= 4094);
    assert.ok(typeof v.name === 'string' && v.name.length > 0);
  }
}

// ---- the helper itself ------------------------------------------------------

test('snmprec helper: values come back in net-snmp\'s shapes', () => {
  const vbs = parseSnmprec([
    '1.3.6.1.2.1.1.5.0|4|sw-1',
    '1.3.6.1.2.1.1.3.0|67|3110697828',
    '1.3.6.1.2.1.2.2.1.6.1|4x|ac162d927d3f',
    '1.3.6.1.2.1.1.2.0|6|1.3.6.1.4.1.9.1.516',
    '1.3.6.1.2.1.31.1.1.1.6.9|70|257487775630445',
    '1.3.6.1.2.1.31.1.1.1.6.10|70|0',
    '1.3.6.1.2.1.2.2.1.8.1|2|1',
  ].join('\n'));
  const by = Object.fromEntries(vbs.map((v) => [v.oid, v.value]));
  assert.ok(Buffer.isBuffer(by['1.3.6.1.2.1.1.5.0']));
  assert.equal(by['1.3.6.1.2.1.1.3.0'], 3110697828);
  assert.equal(by['1.3.6.1.2.1.2.2.1.6.1'].toString('hex'), 'ac162d927d3f');
  assert.equal(by['1.3.6.1.2.1.1.2.0'], '1.3.6.1.4.1.9.1.516');
  // BER content octets, sign pad included — what net-snmp really returns.
  assert.equal(by['1.3.6.1.2.1.31.1.1.1.6.9'].toString('hex'), '00ea2f0b66846d');
  assert.equal(by['1.3.6.1.2.1.31.1.1.1.6.10'].toString('hex'), '00');
  // sorted in OID order, numerically
  assert.deepEqual(vbs.map((v) => v.oid).slice(0, 3), ['1.3.6.1.2.1.1.2.0', '1.3.6.1.2.1.1.3.0', '1.3.6.1.2.1.1.5.0']);
});

test('toNumber reads a 7-byte Counter64 (≥ 2^47, BER sign pad) whole — it once read six bytes, 256× low', () => {
  assert.equal(toNumber(Buffer.from('00ea2f0b66846d', 'hex')), 257487775630445);
  assert.equal(toNumber(Buffer.from('01000000000000', 'hex')), 2 ** 48);
  assert.equal(toNumber(Buffer.from('00', 'hex')), 0);
  assert.equal(toNumber(Buffer.from('03e8', 'hex')), 1000);
});

// ---- HPE ProCurve 6120XG ---------------------------------------------------

test('ProCurve 6120XG: interfaces, Q-BRIDGE FDB, LLDP, CDP and VLANs come out well-formed', async () => {
  const { topo } = await topologyOf('hpe-procurve-516733-b21');
  assertWellFormed(topo, 'procurve');
  const vbs = rec('hpe-procurve-516733-b21');

  assert.equal(topo.sysName, 'DUMSYS-64');
  assert.match(topo.sysDescr, /^ProCurve 516733-B21 6120XG Blade Switch/);
  assert.equal(topo.interfaces.length, column(vbs, '1.3.6.1.2.1.2.2.1.2').size, 'one row per ifDescr');
  for (const cap of ['if', 'fdb', 'lldp', 'vlan']) assert.ok(topo.supported.includes(cap), cap);

  // Q-BRIDGE wins over BRIDGE-MIB: every row carries a real VLAN id.
  assert.ok(topo.fdb.length > 200);
  assert.ok(topo.fdb.every((r) => r.vlan >= 1));
  assert.ok(topo.fdb.every((r) => r.ifIndex != null), 'every learned port resolves on this switch');
  // …and no more rows than the recording's learned (3) / other (1) / mgmt (5) entries
  const qStatus = column(vbs, '1.3.6.1.2.1.17.7.1.2.2.1.3');
  const reportable = [...qStatus.values()].filter((s) => ![2, 4].includes(s)).length;
  assert.ok(topo.fdb.length <= reportable);

  const lldp = topo.neighbours.filter((n) => n.protocol === 'lldp');
  assert.equal(lldp.length, column(vbs, '1.0.8802.1.1.2.1.4.1.1.5').size);
  // Chassis subtype 4 (macAddress) decodes as a MAC; subtype 7 (local) is the
  // neighbour's own text — here a Nexus 5548 that shares port 17 with a
  // second neighbour.
  const subtype = column(vbs, '1.0.8802.1.1.2.1.4.1.1.4');
  const chassis = [...column(vbs, '1.0.8802.1.1.2.1.4.1.1.5').keys()];
  const byLocal = chassis.map((k) => ({ local: Number(k.split('.')[1]), st: subtype.get(k) }));
  for (const { local, st } of byLocal) {
    const mine = lldp.filter((n) => n.localPort === local).map((n) => n.remoteChassisId);
    if (st === 4) assert.ok(mine.some((id) => MAC.test(id)), `port ${local}: MAC chassis id`);
    else assert.ok(mine.includes('NWPU-CA-5548-01(SSI183706KP)'), `port ${local}: local-subtype chassis id as text`);
  }
  assert.equal(lldp.filter((n) => n.localPort === 17).length, 2, 'two neighbours on one port are both kept');
  assert.deepEqual(topo.vlans.map((v) => v.vlan).slice(0, 2), [1, 50]);
  assert.equal(topo.vlans[0].name, 'DEFAULT_VLAN');
});

test('ProCurve 6120XG: a real duplicate ifName (two "lo0") is reported as the device says it', async () => {
  // Recorded fact the server's name-keyed port identity has to live with
  // (blueeye-server test/snmpRealPayloads.test.js pins what happens there).
  const { topo } = await topologyOf('hpe-procurve-516733-b21');
  const lo0 = topo.interfaces.filter((i) => i.ifName === 'lo0').map((i) => i.ifIndex);
  assert.deepEqual(lo0.sort((a, b) => a - b), [4170, 4179]);
});

test('ProCurve 6120XG: counters over HC columns, EtherLike present, real zero stays zero', async () => {
  const out = await pollSnmpCounters({
    device: { deviceId: 7, host: 'recorded', community: 'c' },
    readCounters: (d) => defaultReadCounters(d, { snmp: createSnmprecModule(rec('hpe-procurve-516733-b21')) }),
    now: () => new Date('2026-09-24T02:00:00Z'),
  });
  assert.equal(out.deviceId, 7);
  assert.equal(out.hc, true);
  assert.equal(out.sysUpTimeTicks, 3110697828);
  assert.equal(out.interfaces.length, 42);
  for (const i of out.interfaces) {
    for (const k of ['inOctets', 'outOctets', 'inErrors', 'outErrors', 'inDiscards', 'outDiscards']) {
      assert.ok(Number.isSafeInteger(i[k]) && i[k] >= 0, `${i.ifName} ${k}=${i[k]}`);
    }
  }
  const port1 = out.interfaces.find((i) => i.ifIndex === 1);
  assert.equal(port1.inOctets, 1618982453357);
  assert.equal(port1.fcsErrors, 0, 'EtherLike answered: a real zero');
  assert.equal(port1.duplex, 'full');
});

// ---- Cisco Catalyst 3750 -----------------------------------------------------

test('Catalyst 3750: dot1d FDB is resolved through the bridge-port map (bridge port is NOT ifIndex)', async () => {
  const { topo } = await topologyOf('cisco-c3750');
  assertWellFormed(topo, 'c3750');
  const vbs = rec('cisco-c3750');

  const basePort = column(vbs, '1.3.6.1.2.1.17.1.4.1.2');
  assert.equal(basePort.get('1'), 10101, 'recording: bridge port 1 is ifIndex 10101');
  assert.ok(topo.fdb.length > 0);
  for (const r of topo.fdb) {
    assert.equal(r.vlan, 0, 'BRIDGE-MIB carries no VLAN');
    assert.equal(r.ifIndex, basePort.get(String(r.bridgePort)));
    assert.notEqual(r.ifIndex, r.bridgePort);
    assert.match(r.ifName, /^Gi1\/0\/\d+$/);
  }
  assert.ok(topo.supported.includes('fdb'));
  assert.ok(!topo.supported.includes('lldp'), 'no LLDP in this walk: unsupported, not "zero neighbours"');
});

test('Catalyst 3750: CDP neighbours name the local port and the neighbour\'s address', async () => {
  const { topo } = await topologyOf('cisco-c3750');
  const cdp = topo.neighbours.filter((n) => n.protocol === 'cdp');
  assert.equal(cdp.length, column(rec('cisco-c3750'), '1.3.6.1.4.1.9.9.23.1.2.1.1.6').size);
  for (const n of cdp) {
    assert.match(n.localIfName, /^Gi1\/0\/\d+$/);
    if (n.remoteAddress != null) assert.match(n.remoteAddress, /^\d{1,3}(?:\.\d{1,3}){3}$/);
  }
});

test('Catalyst 3750: a real Counter64 above 2^47 is read exactly', async () => {
  const out = await defaultReadCounters({ host: 'recorded', community: 'c' }, { snmp: createSnmprecModule(rec('cisco-c3750')) });
  const gi9 = out.interfaces.find((i) => i.ifIndex === 10109);
  assert.equal(gi9.ifName, 'Gi1/0/9');
  assert.equal(gi9.inOctets, 257487775630445, 'the value in the recording, not /256');
  // VLAN interfaces have no EtherLike row: absent is null, never 0.
  const vl1 = out.interfaces.find((i) => i.ifIndex === 1);
  assert.equal(vl1.fcsErrors, null);
  assert.equal(vl1.duplex, null);
});

// ---- optional: the same recordings through real net-snmp + snmpsim ----------

const ENDPOINT = process.env.BLUEEYE_SNMPSIM_ENDPOINT || '';
let netSnmp = null;
try { netSnmp = require('net-snmp'); } catch { netSnmp = null; }

test('snmpsim + real net-snmp give exactly what the helper gives', {
  skip: (!ENDPOINT && 'set BLUEEYE_SNMPSIM_ENDPOINT=host:port (snmpsim serving test/fixtures/snmprec)')
    || (!netSnmp && 'net-snmp not installed'),
}, async () => {
  const [host, port] = ENDPOINT.split(':');
  for (const name of ['hpe-procurve-516733-b21', 'cisco-c3750']) {
    const device = { host, port: Number(port) || 161, community: name, version: '2c' };
    // eslint-disable-next-line no-await-in-loop
    // vlanSession null: the recordings hold the default bridge instance only,
    // so the per-VLAN walk (community@vlan) has no files to answer from here.
    const real = buildTopology(await defaultReadTables(device, { collect: COLLECT, vlanSession: null }));
    // eslint-disable-next-line no-await-in-loop
    const { topo } = await topologyOf(name);
    assert.deepEqual(real, topo, `${name}: topology`);
    // eslint-disable-next-line no-await-in-loop
    const realCounters = await defaultReadCounters(device);
    // eslint-disable-next-line no-await-in-loop
    const fakeCounters = await defaultReadCounters({ host: 'x', community: 'c' }, { snmp: createSnmprecModule(rec(name)) });
    assert.deepEqual(realCounters, fakeCounters, `${name}: counters`);
  }
});
