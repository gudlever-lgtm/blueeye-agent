'use strict';

// Tests for the SNMP topology reader (src/snmpTopology.js).
//
// buildTopology is pure, so every decision is tested against fixtures rather
// than a switch — which matters here more than anywhere else in this repo,
// because the failure mode is not a crash. It is an ANSWER THAT LOOKS RIGHT:
// send a technician to port 7 when the device is on port 12, and they will
// believe the tool before they believe the cable.
//
// The fixtures are shaped the way net-snmp hands a subtree back: an object
// keyed by the OID suffix after the column base.

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  buildTopology,
  parseFdbIndex,
  macFromOidParts,
  decodeLldpId,
  localPortFromLldpIndex,
  pollSnmpTopology,
} = require('../src/snmpTopology');

// 00:1b:44:11:3a:b7 as the decimal OID components a FDB table indexes by.
const MAC_OID = '0.27.68.17.58.183';
const MAC = '00:1b:44:11:3a:b7';

// A switch where bridge port != ifIndex — the case that matters. Bridge ports
// 1..3 map to ifIndex 10001..10003, which is how plenty of real hardware
// numbers them.
const BASE_PORTS = { 1: 10001, 2: 10002, 3: 10003 };
const IF_NAMES = { 10001: 'GigabitEthernet0/1', 10002: 'GigabitEthernet0/2', 10003: 'GigabitEthernet0/24' };

function qbridge(over = {}) {
  return {
    ifName: IF_NAMES,
    basePortIfIndex: BASE_PORTS,
    qFdbPort: { [`20.${MAC_OID}`]: 2 },
    qFdbStatus: { [`20.${MAC_OID}`]: 3 }, // learned
    vlanName: { 20: 'Kontor' },
    ...over,
  };
}

// ------------------------------------------------------------ the index maths
test('a MAC is rebuilt from its OID components', () => {
  assert.equal(macFromOidParts(['0', '27', '68', '17', '58', '183']), MAC);
  assert.equal(macFromOidParts(['0', '27', '68']), null, 'too few');
  assert.equal(macFromOidParts(['0', '27', '68', '17', '58', '999']), null, 'out of range');
  assert.equal(macFromOidParts(null), null);
});

test('a Q-BRIDGE index carries the VLAN, a BRIDGE index does not', () => {
  assert.deepEqual(parseFdbIndex(`20.${MAC_OID}`, { withVlan: true }), { vlan: 20, mac: MAC });
  assert.deepEqual(parseFdbIndex(MAC_OID, { withVlan: false }), { vlan: 0, mac: MAC });
  // A wrong-length index is refused rather than parsed into a plausible MAC.
  assert.equal(parseFdbIndex(MAC_OID, { withVlan: true }), null);
  assert.equal(parseFdbIndex(`5000.${MAC_OID}`, { withVlan: true }), null, 'VLAN out of range');
});

test('an LLDP index yields the local port', () => {
  assert.equal(localPortFromLldpIndex('0.3.1'), 3);
  assert.equal(localPortFromLldpIndex('nonsense'), null);
});

test("the device's own subtype decides whether an LLDP id is a MAC or a name", () => {
  // LENGTH CANNOT TELL THEM APART: "Gi0/24" is exactly six bytes, the same as a
  // MAC. Reading the subtype column is the difference between a port name and
  // "47:69:30:2f:32:34".
  const giBytes = Buffer.from('Gi0/24', 'utf8');
  assert.equal(giBytes.length, 6, 'the ambiguity is real, not hypothetical');
  assert.equal(decodeLldpId(giBytes, 'text'), 'Gi0/24');
  assert.equal(decodeLldpId(Buffer.from([0x00, 0x1b, 0x44, 0x11, 0x3a, 0xb7]), 'mac'), MAC);

  // With no subtype reported, all-printable bytes are read as text: a port
  // named "Gi0/24" is far likelier than a MAC whose every octet is ASCII.
  assert.equal(decodeLldpId(giBytes), 'Gi0/24');
  assert.equal(decodeLldpId(Buffer.from([0x00, 0x1b, 0x44, 0x11, 0x3a, 0xb7])), MAC);

  assert.equal(decodeLldpId(Buffer.from([0x01, 0x02, 0x03])), '010203');
  assert.equal(decodeLldpId('  sw-core-1  '), 'sw-core-1');
  assert.equal(decodeLldpId(null), null);
});

// ------------------------------------------------- bridge port is not ifIndex
test('a bridge port is resolved through dot1dBasePortIfIndex, not assumed', () => {
  // THE test in this file. The FDB says bridge port 2; the answer must be
  // GigabitEthernet0/2 via ifIndex 10002 — not "port 2", and not the interface
  // that happens to sit at ifIndex 2.
  const r = buildTopology(qbridge());
  assert.equal(r.fdb.length, 1);
  assert.deepEqual(r.fdb[0], {
    mac: MAC, vlan: 20, bridgePort: 2, ifIndex: 10002,
    ifName: 'GigabitEthernet0/2', status: 'learned', portMacCount: 1,
  });
});

test('an unresolvable bridge port yields NULL, never a fabricated port', () => {
  // A device that does not implement dot1dBasePortTable still reports a
  // forwarding table. Saying "port 2" would be a guess dressed as an answer.
  const r = buildTopology(qbridge({ basePortIfIndex: {} }));
  assert.equal(r.fdb[0].bridgePort, 2, 'what the device said survives');
  assert.equal(r.fdb[0].ifIndex, null);
  assert.equal(r.fdb[0].ifName, null);
  assert.ok(!r.supported.includes('fdb'), 'and fdb is not claimed as supported');
});

test('an ifIndex with no name resolves the index but not the name', () => {
  const r = buildTopology(qbridge({ ifName: {} }));
  assert.equal(r.fdb[0].ifIndex, 10002);
  assert.equal(r.fdb[0].ifName, null);
});

// ------------------------------------------------------------ what is skipped
test("the switch's own MAC is not reported as a device on a port", () => {
  const r = buildTopology(qbridge({ qFdbStatus: { [`20.${MAC_OID}`]: 4 } })); // self
  assert.deepEqual(r.fdb, []);
});

test('an entry ageing out is dropped', () => {
  const r = buildTopology(qbridge({ qFdbStatus: { [`20.${MAC_OID}`]: 2 } })); // invalid
  assert.deepEqual(r.fdb, []);
});

test('bridge port 0 means "known but not located" and is not a port', () => {
  // The device is saying it knows the address but not where it is. Storing 0
  // as a port would send somebody to a patch panel that does not exist.
  const r = buildTopology(qbridge({ qFdbPort: { [`20.${MAC_OID}`]: 0 } }));
  assert.deepEqual(r.fdb, []);
});

// ------------------------------------------------------- Q-BRIDGE vs BRIDGE
test('Q-BRIDGE wins when both tables answer, so nothing is double-counted', () => {
  // The same MAC appears in both tables with the same bridge port. Merging
  // would double every entry on every switch that implements both.
  const r = buildTopology(qbridge({
    dFdbPort: { [MAC_OID]: 2 },
    dFdbStatus: { [MAC_OID]: 3 },
  }));
  assert.equal(r.fdb.length, 1);
  assert.equal(r.fdb[0].vlan, 20, 'the per-VLAN answer is the one kept');
});

test('a BRIDGE-MIB-only device falls back, with vlan 0 meaning "not said"', () => {
  const r = buildTopology({
    ifName: IF_NAMES,
    basePortIfIndex: BASE_PORTS,
    dFdbPort: { [MAC_OID]: 3 },
    dFdbStatus: { [MAC_OID]: 3 },
  });
  assert.equal(r.fdb.length, 1);
  assert.equal(r.fdb[0].vlan, 0, '0 is not a real VLAN id, so it is unambiguous');
  assert.equal(r.fdb[0].ifName, 'GigabitEthernet0/24');
});

test('the same MAC in two VLANs is two rows, not one', () => {
  // A router sub-interface, or a phone on a voice and a data VLAN. Folding
  // these would silently discard a real observation.
  const r = buildTopology(qbridge({
    qFdbPort: { [`20.${MAC_OID}`]: 2, [`30.${MAC_OID}`]: 2 },
    qFdbStatus: { [`20.${MAC_OID}`]: 3, [`30.${MAC_OID}`]: 3 },
  }));
  assert.equal(r.fdb.length, 2);
  assert.deepEqual(r.fdb.map((e) => e.vlan).sort(), [20, 30]);
});

// -------------------------------------------------------------- port occupancy
test('port_mac_count separates an end device from an uplink', () => {
  // The field that turns a hit into an answer: one MAC means a patch panel to
  // walk to; forty means an uplink and one more hop to go.
  const many = {};
  const status = {};
  for (let i = 0; i < 40; i += 1) {
    const idx = `20.0.27.68.17.58.${i}`;
    many[idx] = 3; // all on bridge port 3 — an uplink
    status[idx] = 3;
  }
  many[`20.${MAC_OID}`] = 2; // the one we are looking for, alone on port 2
  status[`20.${MAC_OID}`] = 3;

  const r = buildTopology(qbridge({ qFdbPort: many, qFdbStatus: status }));
  const mine = r.fdb.find((e) => e.mac === MAC);
  assert.equal(mine.portMacCount, 1);
  assert.equal(r.fdb.find((e) => e.bridgePort === 3).portMacCount, 40);
});

test('the cap keeps the ports that answer the question', () => {
  // A core switch's 20 000-entry uplink must not push out the access ports,
  // which are the rows a technician is actually looking for.
  const ports = {};
  const status = {};
  for (let i = 0; i < 300; i += 1) {
    const idx = `20.0.27.68.1.${Math.floor(i / 256)}.${i % 256}`;
    ports[idx] = 3; // the crowded uplink
    status[idx] = 3;
  }
  ports[`20.${MAC_OID}`] = 2;
  status[`20.${MAC_OID}`] = 3;

  const r = buildTopology(qbridge({ qFdbPort: ports, qFdbStatus: status }), { maxFdb: 10 });
  assert.equal(r.fdb.length, 10);
  assert.ok(r.fdbTruncated);
  assert.equal(r.fdbTotal, 301, 'the true size is still reported');
  assert.ok(r.fdb.some((e) => e.mac === MAC), 'the lone-MAC port survived the cap');
});

// ------------------------------------------------------------------ neighbours
test('LLDP neighbours are resolved to the local interface', () => {
  const r = buildTopology(qbridge({
    lldpChassis: { '0.3.1': Buffer.from([0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33]) },
    lldpChassisSubtype: { '0.3.1': 4 }, // macAddress
    lldpPort: { '0.3.1': Buffer.from('Gi1/0/5', 'utf8') },
    lldpPortSubtype: { '0.3.1': 5 },    // interfaceName
    lldpSysName: { '0.3.1': 'sw-acc-2' },
    lldpPortDesc: { '0.3.1': 'uplink to core' },
  }));
  assert.equal(r.neighbours.length, 1);
  assert.deepEqual(r.neighbours[0], {
    localPort: 3,
    localIfIndex: 10003,
    localIfName: 'GigabitEthernet0/24',
    remoteChassisId: 'aa:bb:cc:11:22:33',
    remotePortId: 'Gi1/0/5',
    remotePortDesc: 'uplink to core',
    remoteSysName: 'sw-acc-2',
  });
});

test('a six-byte port NAME survives the whole path, not just the decoder', () => {
  // The regression this guards: "Gi0/24" reaching the UI as a MAC address.
  const r = buildTopology(qbridge({
    lldpChassis: { '0.3.1': Buffer.from('sw-acc-2', 'utf8') },
    lldpChassisSubtype: { '0.3.1': 7 }, // local
    lldpPort: { '0.3.1': Buffer.from('Gi0/24', 'utf8') },
    lldpPortSubtype: { '0.3.1': 5 },    // interfaceName
  }));
  assert.equal(r.neighbours[0].remotePortId, 'Gi0/24');
  assert.equal(r.neighbours[0].remoteChassisId, 'sw-acc-2');
});

test('a neighbour on a device with no bridge-port table still reports', () => {
  // LLDP's local port number is usually the ifIndex on such devices; dropping
  // an otherwise good neighbour would be the worse answer.
  const r = buildTopology({
    ifName: { 3: 'eth3' },
    basePortIfIndex: {},
    lldpChassis: { '0.3.1': 'sw-x' },
  });
  assert.equal(r.neighbours.length, 1);
  assert.equal(r.neighbours[0].localIfIndex, 3);
  assert.equal(r.neighbours[0].localIfName, 'eth3');
});

// ------------------------------------------------------- supported, not empty
test('supported says what the device ANSWERED, so the UI can say "not supported"', () => {
  // A device that cannot answer must never look like one that answered "none" —
  // the same rule connectionTest/checks.js follows with available:false, and
  // the same one snmpMonitor follows by reporting an absent counter as null.
  const full = buildTopology(qbridge({
    lldpChassis: { '0.3.1': 'sw-x' },
  }));
  assert.deepEqual([...full.supported].sort(), ['fdb', 'if', 'lldp', 'vlan']);

  const ifOnly = buildTopology({ ifName: IF_NAMES, basePortIfIndex: {} });
  assert.deepEqual(ifOnly.supported, ['if']);
  assert.deepEqual(ifOnly.fdb, []);
});

test('VLAN names come back so the UI can write "VLAN 20 (Kontor)"', () => {
  const r = buildTopology(qbridge());
  assert.deepEqual(r.vlans, [{ vlan: 20, name: 'Kontor' }]);
});

test('buildTopology survives junk without throwing', () => {
  for (const bad of [null, undefined, {}, { qFdbPort: null }, { basePortIfIndex: 'x' }]) {
    const r = buildTopology(bad);
    assert.ok(Array.isArray(r.fdb));
    assert.ok(Array.isArray(r.supported));
  }
});

// ------------------------------------------------------------------ the poll
test('pollSnmpTopology passes the device through and tags the result', async () => {
  let seenSnmp = null;
  let seenOpts = null;
  const r = await pollSnmpTopology({
    device: { deviceId: 7, host: '10.14.0.11', port: 161, version: '2c', community: 'public', collect: ['if', 'fdb'] },
    readTables: async (snmp, opts) => { seenSnmp = snmp; seenOpts = opts; return qbridge(); },
  });
  assert.equal(r.deviceId, 7);
  assert.equal(seenSnmp.host, '10.14.0.11');
  assert.equal(seenSnmp.community, 'public');
  assert.deepEqual(seenOpts.collect, ['if', 'fdb']);
  assert.equal(r.fdb.length, 1);
});

test('an empty collect list falls back to everything rather than nothing', async () => {
  let seenOpts = null;
  await pollSnmpTopology({
    device: { deviceId: 7, host: '10.14.0.11', collect: [] },
    readTables: async (_s, opts) => { seenOpts = opts; return qbridge(); },
  });
  assert.deepEqual(seenOpts.collect, ['if', 'fdb', 'lldp', 'vlan']);
});

test('a device with no host is refused with a coded error', async () => {
  await assert.rejects(
    () => pollSnmpTopology({ device: { deviceId: 1 } }),
    (err) => err.code === 'SNMP_BAD_TARGET',
  );
});

// ===================================== trin 1: the port inventory, in earnest
// The server stores these rows now (migration 108), keyed on the NAME, so what
// the name is and where it came from stopped being cosmetic.

test('a port with no ifName falls back to ifDescr, and the row says so', () => {
  const out = buildTopology({
    ifName: {},
    ifDescr: { 1: 'FastEthernet0/1' },
    ifAlias: { 1: 'to the printer' },
    ifOperStatus: { 1: 1 },
    ifAdminStatus: { 1: 1 },
    ifHighSpeed: { 1: 100 },
  });
  assert.equal(out.interfaces.length, 1);
  assert.equal(out.interfaces[0].ifName, 'FastEthernet0/1');
  assert.equal(out.interfaces[0].nameSource, 'ifDescr');
  assert.equal(out.interfaces[0].operStatus, 'up');
  assert.equal(out.interfaces[0].speedMbps, 100);
});

test('a port with neither name is keyed on its index, and marked as such', () => {
  const out = buildTopology({ ifName: {}, ifDescr: { 7: '   ' }, ifOperStatus: { 7: 2 } });
  assert.equal(out.interfaces[0].ifName, 'ifIndex.7');
  assert.equal(out.interfaces[0].nameSource, 'ifIndex');
  assert.equal(out.interfaces[0].operStatus, 'down');
});

test('the FABRICATED name never reaches the forwarding table', () => {
  // Stage 02's rule: a port the switch did not name is reported as null rather
  // than as a made-up "port N". `ifIndex.7` is exactly such a fabrication — it
  // is fine as a row id in this device's own port list, and it is NOT an answer
  // to "which port is this MAC on", because that answer sends somebody walking.
  const out = buildTopology({
    // The device listed the port but named it with neither column — a blank
    // ifDescr is how that actually arrives.
    ifName: {},
    ifDescr: { 7: '   ' },
    basePortIfIndex: { 2: 7 },
    dFdbPort: { [MAC_OID]: 2 },
    dFdbStatus: { [MAC_OID]: 3 },
  });
  assert.equal(out.interfaces[0].ifName, 'ifIndex.7', 'the inventory still names it');
  assert.equal(out.fdb.length, 1);
  assert.equal(out.fdb[0].ifIndex, 7);
  assert.equal(out.fdb[0].ifName, null, 'the forwarding answer stays honest');
});

test('admin and oper status are separate answers', () => {
  // Somebody turned this port off, versus this port fell over. Different
  // faults, different places to go.
  const out = buildTopology({
    ifName: { 1: 'Gi0/1', 2: 'Gi0/2' },
    ifAdminStatus: { 1: 2, 2: 1 },
    ifOperStatus: { 1: 2, 2: 2 },
  });
  const byName = Object.fromEntries(out.interfaces.map((i) => [i.ifName, i]));
  assert.equal(byName['Gi0/1'].adminStatus, 'down', 'shut on purpose');
  assert.equal(byName['Gi0/2'].adminStatus, 'up', 'fell over');
  assert.equal(byName['Gi0/2'].operStatus, 'down');
});

test('a speed of zero is NULL, not zero', () => {
  // ifHighSpeed reads 0 for a port whose speed the device does not know. Stored
  // as 0 it would make "unknown" look like "stalled", and a utilisation
  // percentage against it is not a number at all.
  const out = buildTopology({ ifName: { 1: 'Gi0/1' }, ifHighSpeed: { 1: 0 } });
  assert.equal(out.interfaces[0].speedMbps, null);
});

test('ifPhysAddress is rendered once, and only when it is six bytes', () => {
  const out = buildTopology({
    ifName: { 1: 'Gi0/1', 2: 'Gi0/2' },
    ifPhysAddress: { 1: Buffer.from([0x00, 0x1b, 0x44, 0x11, 0x3a, 0xb7]), 2: Buffer.from([0x00, 0x1b]) },
  });
  const byName = Object.fromEntries(out.interfaces.map((i) => [i.ifName, i]));
  assert.equal(byName['Gi0/1'].physAddress, '00:1b:44:11:3a:b7');
  assert.equal(byName['Gi0/2'].physAddress, null, 'two bytes is not a MAC');
});
