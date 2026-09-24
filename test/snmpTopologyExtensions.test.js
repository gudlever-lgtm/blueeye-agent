'use strict';

// Tests for what the topology poll reads beyond FDB/LLDP/VLAN: CDP neighbours,
// the router's ARP table (IP-MIB), the ENTITY-MIB inventory and the rest of
// the system group (sysLocation/sysContact/sysObjectID).
//
// Two layers, like the rest of this area:
//
//   * buildTopology against walk-shaped fixtures — an object keyed by the OID
//     suffix after the column base, which is what walkColumn returns;
//   * defaultReadTables against a fake SESSION that serves varbinds exactly as
//     net-snmp hands them back ({ oid, type, value }, OCTET STRINGs as
//     Buffers), so the index decoding is tested on the real byte layouts, from
//     the wire to the payload.

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  buildTopology,
  pollSnmpTopology,
  defaultReadTables,
  parseIpNetToPhysicalIndex,
  parseIpNetToMediaIndex,
  parseCdpIndex,
  decodeCdpAddress,
  ipv6FromBytes,
  MAX_CHASSIS,
} = require('../src/snmpTopology');
const { CDP, IP_MIB, ENTITY, SYSTEM, IF_MIB } = require('../src/snmp/oids');
const { splitSubmission, createSnmpPoller } = require('../src/snmpPoller');

const mac = (...b) => Buffer.from(b);
const IF_NAMES = { 10102: 'GigabitEthernet1/0/2', 20: 'Vlan20', 30: 'Vlan30' };

// 2001:db8::1 and fe80::1 as the sixteen OID components an InetAddress index
// carries.
const V6_GLOBAL = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const V6_LINKLOCAL = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

// ------------------------------------------------------------ index decoding
test('an ipNetToPhysical index carries ifIndex, type, LENGTH and the address bytes', () => {
  assert.deepEqual(parseIpNetToPhysicalIndex('20.1.4.10.20.0.84'), { ifIndex: 20, ip: '10.20.0.84' });
  assert.deepEqual(parseIpNetToPhysicalIndex(`20.2.16.${V6_GLOBAL.join('.')}`), { ifIndex: 20, ip: '2001:db8::1' });
  // A non-conforming agent that leaves the length out is still read, because
  // the component count only makes sense one way.
  assert.deepEqual(parseIpNetToPhysicalIndex('20.1.10.20.0.84'), { ifIndex: 20, ip: '10.20.0.84' });
  // A length that disagrees with the bytes, an octet out of range, a zoned
  // type and an ifIndex of 0 are all refused rather than guessed.
  assert.equal(parseIpNetToPhysicalIndex('20.1.4.10.20.0'), null);
  assert.equal(parseIpNetToPhysicalIndex('20.1.4.10.20.0.300'), null);
  assert.equal(parseIpNetToPhysicalIndex('20.3.8.10.20.0.84.0.0.0.1'), null, 'ipv4z is link-scoped');
  assert.equal(parseIpNetToPhysicalIndex('0.1.4.10.20.0.84'), null);
  assert.equal(parseIpNetToPhysicalIndex('junk'), null);
});

test('an ipNetToMedia index is ifIndex plus four octets', () => {
  assert.deepEqual(parseIpNetToMediaIndex('30.192.168.30.7'), { ifIndex: 30, ip: '192.168.30.7' });
  assert.equal(parseIpNetToMediaIndex('30.192.168.30'), null);
  assert.equal(parseIpNetToMediaIndex('30.192.168.30.256'), null);
});

test('IPv6 is written in its one RFC 5952 spelling', () => {
  assert.equal(ipv6FromBytes(V6_GLOBAL), '2001:db8::1');
  assert.equal(ipv6FromBytes(new Array(16).fill(0)), '::');
  // The LONGEST zero run is collapsed, and a single zero group is not.
  assert.equal(ipv6FromBytes([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1]), '2001:db8:0:1::1');
  assert.equal(ipv6FromBytes([0x20, 0x01, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1]), '2001:0:1:1:1:1:1:1');
});

test('a CDP index is <ifIndex>.<deviceIndex>', () => {
  assert.deepEqual(parseCdpIndex('10102.3'), { ifIndex: 10102, deviceIndex: 3 });
  assert.equal(parseCdpIndex('10102'), null);
  assert.equal(parseCdpIndex('0.1'), null);
});

test('cdpCacheAddress is decoded from BYTES by its address type', () => {
  // 0a 0e 00 0b — read as text this is "\n\u000e\u0000\u000b".
  assert.equal(decodeCdpAddress(mac(0x0a, 0x0e, 0x00, 0x0b), 1), '10.14.0.11');
  assert.equal(decodeCdpAddress(Buffer.from(V6_GLOBAL), 20), '2001:db8::1');
  // No type: length decides.
  assert.equal(decodeCdpAddress(mac(192, 168, 1, 1), null), '192.168.1.1');
  // A type that disagrees with the length, or an unknown type, is not an
  // address — never a plausible-looking wrong one.
  assert.equal(decodeCdpAddress(mac(192, 168, 1, 1), 20), null);
  assert.equal(decodeCdpAddress(mac(1, 2, 3, 4, 5, 6), 1), null);
  assert.equal(decodeCdpAddress(null, 1), null);
});

// --------------------------------------------------------------------- CDP
const cdpTables = (over = {}) => ({
  ifName: IF_NAMES,
  cdpDeviceId: { '10102.1': Buffer.from('sw-dist-1.corp.local') },
  cdpAddressType: { '10102.1': 1 },
  cdpAddress: { '10102.1': mac(0x0a, 0x0e, 0x00, 0x0b) },
  cdpDevicePort: { '10102.1': Buffer.from('GigabitEthernet1/0/48') },
  cdpPlatform: { '10102.1': Buffer.from('cisco WS-C3850-48P') },
  ...over,
});

test('a CDP neighbour is reported on its local port, tagged cdp', () => {
  const r = buildTopology(cdpTables());
  assert.deepEqual(r.neighbours, [{
    protocol: 'cdp',
    localPort: 10102,
    localIfIndex: 10102,
    localIfName: 'GigabitEthernet1/0/2',
    remoteChassisId: 'sw-dist-1.corp.local',
    remotePortId: 'GigabitEthernet1/0/48',
    remotePortDesc: null,
    remoteSysName: 'sw-dist-1.corp.local',
    remoteAddress: '10.14.0.11',
    remotePlatform: 'cisco WS-C3850-48P',
  }]);
  assert.ok(r.supported.includes('cdp'));
  assert.ok(!r.supported.includes('lldp'), 'a CDP neighbour is not LLDP support');
});

test('LLDP and CDP share the neighbour cap, LLDP first', () => {
  const lldpChassis = {};
  for (let i = 1; i <= 3; i += 1) lldpChassis[`0.${i}.1`] = `sw-${i}`;
  const r = buildTopology(cdpTables({ lldpChassis }), { maxNeighbours: 3 });
  assert.equal(r.neighbours.length, 3);
  assert.ok(r.neighbours.every((n) => n.protocol === 'lldp'));
  const both = buildTopology(cdpTables({ lldpChassis }), { maxNeighbours: 4 });
  assert.deepEqual(both.neighbours.map((n) => n.protocol), ['lldp', 'lldp', 'lldp', 'cdp']);
  assert.deepEqual([...both.supported].sort(), ['cdp', 'if', 'lldp']);
});

test('a CDP neighbour with no device id is dropped, and a missing address is null', () => {
  const r = buildTopology(cdpTables({
    cdpDeviceId: { '10102.1': Buffer.from(''), '10102.2': Buffer.from('ap-3') },
    cdpAddress: {},
  }));
  assert.equal(r.neighbours.length, 1);
  assert.equal(r.neighbours[0].remoteChassisId, 'ap-3');
  assert.equal(r.neighbours[0].remoteAddress, null);
});

// --------------------------------------------------------------------- ARP
test('the router ARP table: IPv4 and global IPv6 kept, the rest dropped', () => {
  const r = buildTopology({
    ifName: IF_NAMES,
    arpPhys: {
      '20.1.4.10.20.0.84': mac(0x00, 0x1b, 0x44, 0x11, 0x3a, 0xb7),
      '20.1.4.169.254.1.9': mac(0x00, 0x0e, 0x8c, 0x01, 0x02, 0x03), // APIPA: a real device
      [`20.2.16.${V6_GLOBAL.join('.')}`]: mac(0x00, 0x1b, 0x44, 0x11, 0x3a, 0xb8),
      [`20.2.16.${V6_LINKLOCAL.join('.')}`]: mac(0x00, 0x1b, 0x44, 0x11, 0x3a, 0xb9), // link-local
      '20.1.4.10.20.0.85': mac(0, 0, 0, 0, 0, 0), // incomplete: no MAC yet
      '20.1.4.10.20.0.86': mac(0x01, 0x00, 0x5e, 0x00, 0x00, 0x01), // multicast MAC
      '20.1.4.10.20.0.87': mac(0x00, 0x1b, 0x44, 0x11, 0x3a, 0xba), // state incomplete
      '20.1.4.10.20.0.88': mac(0x00, 0x1b, 0x44, 0x11, 0x3a), // five bytes: not a MAC
      '20.1.4.224.0.0.5': mac(0x00, 0x1b, 0x44, 0x11, 0x3a, 0xbb), // multicast IP
    },
    arpState: { '20.1.4.10.20.0.87': 7, '20.1.4.10.20.0.84': 1 },
  });
  assert.deepEqual(r.arp, [
    { ip: '10.20.0.84', mac: '00:1b:44:11:3a:b7', ifIndex: 20, ifName: 'Vlan20' },
    { ip: '169.254.1.9', mac: '00:0e:8c:01:02:03', ifIndex: 20, ifName: 'Vlan20' },
    { ip: '2001:db8::1', mac: '00:1b:44:11:3a:b8', ifIndex: 20, ifName: 'Vlan20' },
  ]);
  assert.equal(r.arpSource, 'ipNetToPhysical');
  assert.equal(r.arpTruncated, false);
  assert.ok(r.supported.includes('arp'));
});

test('ipNetToMedia is the fallback, and an invalid(2) entry is dropped', () => {
  const r = buildTopology({
    ifName: IF_NAMES,
    arpMedia: {
      '30.192.168.30.7': mac(0x00, 0x80, 0xf4, 0x01, 0x02, 0x03),
      '30.192.168.30.8': mac(0x00, 0x80, 0xf4, 0x01, 0x02, 0x04),
    },
    arpMediaType: { '30.192.168.30.8': 2, '30.192.168.30.7': 3 },
  });
  assert.deepEqual(r.arp, [{ ip: '192.168.30.7', mac: '00:80:f4:01:02:03', ifIndex: 30, ifName: 'Vlan30' }]);
  assert.equal(r.arpSource, 'ipNetToMedia');
});

test('an ARP entry on an unnamed interface keeps its index and a NULL name', () => {
  const r = buildTopology({ arpMedia: { '99.10.0.0.1': mac(0x00, 0x80, 0xf4, 0, 0, 1) } });
  assert.equal(r.arp[0].ifIndex, 99);
  assert.equal(r.arp[0].ifName, null);
});

test('the ARP table is bounded, and a cut walk says truncated', () => {
  const arpPhys = {};
  for (let i = 1; i <= 10; i += 1) arpPhys[`20.1.4.10.20.1.${i}`] = mac(0x00, 0x1b, 0x44, 0, 0, i);
  const r = buildTopology({ arpPhys }, { maxArp: 4 });
  assert.equal(r.arp.length, 4);
  assert.equal(r.arpTotal, 10);
  assert.equal(r.arpTruncated, true);

  // Under the cap, but the WALK stopped at its bound: the table was not read
  // to the end, and the report must not claim it was.
  const cut = buildTopology({ arpPhys, arpWalkLimit: 10 });
  assert.equal(cut.arp.length, 10);
  assert.equal(cut.arpTruncated, true);
});

test('a device with no IP-MIB table yields no ARP and no error', () => {
  const r = buildTopology({ ifName: IF_NAMES });
  assert.deepEqual(r.arp, []);
  assert.equal(r.arpSource, null);
  assert.ok(!r.supported.includes('arp'));
});

// ------------------------------------------------------------------ ENTITY
const entity = (over = {}) => ({
  entClass: { 1: 3, 2: 9, 3: 9, 4: 10, 1000: 3, 1001: 6 },
  entDescr: { 1: 'Cisco Catalyst 3850 48-port PoE', 2: 'Uplink module', 3: 'Empty slot', 1000: 'Stack member 2' },
  entName: { 1: 'Switch 1', 2: 'Switch 1 - FRU Uplink Module 1', 1000: 'Switch 2' },
  entModelName: { 1: 'WS-C3850-48P', 2: 'C3850-NM-4-1G', 1000: 'WS-C3850-48P', 1001: 'PWR-C1-715WAC' },
  entSerialNum: { 1: 'FOC1234X0AB', 2: 'FOC5678Y1CD', 1000: 'FOC9999Z2EF', 4: 'SFP123' },
  entMfgName: { 1: 'Cisco Systems, Inc.', 1000: 'Cisco Systems, Inc.' },
  entHardwareRev: { 1: 'V07' },
  entFirmwareRev: { 1: '16.12.4' },
  entSoftwareRev: { 1: '16.12.04', 1000: '16.12.04' },
  ...over,
});

test('the inventory keeps every chassis and the modules that say what they are', () => {
  const r = buildTopology(entity());
  assert.deepEqual(r.inventory.map((e) => [e.entIndex, e.class, e.serial]), [
    [1, 'chassis', 'FOC1234X0AB'],
    [2, 'module', 'FOC5678Y1CD'],
    // index 3 is a module with neither model nor serial — an empty slot
    // index 4 is a port (class 10) and 1001 a power supply (class 6)
    [1000, 'chassis', 'FOC9999Z2EF'],
  ]);
  assert.deepEqual(r.inventory[0], {
    entIndex: 1,
    class: 'chassis',
    name: 'Switch 1',
    descr: 'Cisco Catalyst 3850 48-port PoE',
    model: 'WS-C3850-48P',
    serial: 'FOC1234X0AB',
    vendor: 'Cisco Systems, Inc.',
    hardwareRev: 'V07',
    firmwareRev: '16.12.4',
    softwareRev: '16.12.04',
  });
  assert.ok(r.supported.includes('entity'));
});

test('the chassis list is bounded', () => {
  const entClass = {};
  for (let i = 1; i <= MAX_CHASSIS + 5; i += 1) entClass[i] = 3;
  const r = buildTopology({ entClass });
  assert.equal(r.inventory.length, MAX_CHASSIS);
});

test('a device without ENTITY-MIB yields an empty inventory', () => {
  const r = buildTopology({ ifName: IF_NAMES });
  assert.deepEqual(r.inventory, []);
  assert.ok(!r.supported.includes('entity'));
});

// ------------------------------------------------------------ system group
test('sysLocation, sysContact and sysObjectID are carried, trimmed, null when absent', () => {
  const r = buildTopology({
    sysLocation: '  Bygning 3, rum 2.14, rack B  ',
    sysContact: 'netdrift@example.dk',
    sysObjectId: '1.3.6.1.4.1.9.1.1745',
  });
  assert.equal(r.sysLocation, 'Bygning 3, rum 2.14, rack B');
  assert.equal(r.sysContact, 'netdrift@example.dk');
  assert.equal(r.sysObjectId, '1.3.6.1.4.1.9.1.1745');
  const none = buildTopology({ sysLocation: '   ' });
  assert.equal(none.sysLocation, null);
  assert.equal(none.sysContact, null);
  assert.equal(none.sysObjectId, null);
});

// ---------------------------------------------- the reader, on the wire shape
// A session that answers like net-snmp: subtree() feeds varbinds in GETBULK-
// sized chunks and stops when the feed callback returns true; get() answers
// every OID, with a NoSuchObject (type 128, value null) for one it lacks.
function fakeSession(varbinds, { failSecondGet = false } = {}) {
  const calls = { subtree: [], get: 0, closed: false, fed: {} };
  const session = {
    calls,
    subtree(base, maxRep, feed, done) {
      calls.subtree.push(base);
      const rows = varbinds.filter((vb) => vb.oid.startsWith(`${base}.`));
      calls.fed[base] = 0;
      for (let i = 0; i < rows.length; i += maxRep) {
        const chunk = rows.slice(i, i + maxRep);
        calls.fed[base] += chunk.length;
        if (feed(chunk)) break;
      }
      setImmediate(() => done(null));
    },
    get(oids, cb) {
      calls.get += 1;
      if (failSecondGet && calls.get === 2) { setImmediate(() => cb(new Error('noSuchName'))); return; }
      const out = oids.map((oid) => {
        const hit = varbinds.find((vb) => vb.oid === oid);
        return hit || { oid, type: 128, value: null };
      });
      setImmediate(() => cb(null, out));
    },
    close() { calls.closed = true; },
  };
  return session;
}

const OCTETS = 4;
const INT = 2;
const vb = (oid, value, type = OCTETS) => ({ oid, type, value });

function routerVarbinds() {
  return [
    vb(SYSTEM.sysUpTime, 123456, 67),
    vb(SYSTEM.sysName, Buffer.from('rtr-ot-1')),
    vb(SYSTEM.sysLocation, Buffer.from('Hal 2, tavlerum, rack A3\0\0')),
    vb(SYSTEM.sysContact, Buffer.from('OT-drift')),
    vb(SYSTEM.sysObjectID, '1.3.6.1.4.1.9.1.2066', 6),
    vb(`${IF_MIB.ifName}.20`, Buffer.from('Vlan20')),
    vb(`${IF_MIB.ifName}.10102`, Buffer.from('Gi1/0/2')),
    // ipNetToPhysicalTable, real index layout: ifIndex.type.len.bytes
    vb(`${IP_MIB.ipNetToPhysicalPhysAddress}.20.1.4.10.20.0.84`, mac(0x00, 0x1b, 0x44, 0x11, 0x3a, 0xb7)),
    vb(`${IP_MIB.ipNetToPhysicalPhysAddress}.20.1.4.10.20.0.90`, mac(0x00, 0x0e, 0x8c, 0xaa, 0xbb, 0xcc)),
    vb(`${IP_MIB.ipNetToPhysicalPhysAddress}.20.2.16.${V6_GLOBAL.join('.')}`, mac(0x00, 0x1b, 0x44, 0x11, 0x3a, 0xb7)),
    vb(`${IP_MIB.ipNetToPhysicalState}.20.1.4.10.20.0.84`, 1, INT),
    vb(`${IP_MIB.ipNetToPhysicalState}.20.1.4.10.20.0.90`, 7, INT),
    // The deprecated table too: it must NOT be read when the newer one answered.
    vb(`${IP_MIB.ipNetToMediaPhysAddress}.20.10.20.0.84`, mac(0x00, 0x1b, 0x44, 0x11, 0x3a, 0xb7)),
    // CDP
    vb(`${CDP.cdpCacheDeviceId}.10102.1`, Buffer.from('sw-dist-1')),
    vb(`${CDP.cdpCacheAddressType}.10102.1`, 1, INT),
    vb(`${CDP.cdpCacheAddress}.10102.1`, mac(0x0a, 0x0e, 0x00, 0x0b)),
    vb(`${CDP.cdpCacheDevicePort}.10102.1`, Buffer.from('Gi1/0/48')),
    vb(`${CDP.cdpCachePlatform}.10102.1`, Buffer.from('cisco WS-C3850-48P')),
    // ENTITY
    vb(`${ENTITY.entPhysicalClass}.1`, 3, INT),
    vb(`${ENTITY.entPhysicalModelName}.1`, Buffer.from('ISR4331/K9')),
    vb(`${ENTITY.entPhysicalSerialNum}.1`, Buffer.from('FDO2201A0XY')),
    vb(`${ENTITY.entPhysicalMfgName}.1`, Buffer.from('Cisco Systems Inc')),
  ];
}

test('the reader decodes a router from net-snmp-shaped varbinds, end to end', async () => {
  const session = fakeSession(routerVarbinds());
  const r = await pollSnmpTopology({
    device: { deviceId: 4, host: '10.20.0.1', community: 'c', collect: ['if', 'cdp', 'arp', 'entity'] },
    readTables: (snmp, opts) => defaultReadTables(snmp, { ...opts, session }),
  });
  assert.equal(r.sysLocation, 'Hal 2, tavlerum, rack A3', 'trailing NUL padding stripped');
  assert.equal(r.sysContact, 'OT-drift');
  assert.equal(r.sysObjectId, '1.3.6.1.4.1.9.1.2066');
  assert.equal(r.sysUpTimeTicks, 123456);
  assert.deepEqual(r.arp, [
    { ip: '10.20.0.84', mac: '00:1b:44:11:3a:b7', ifIndex: 20, ifName: 'Vlan20' },
    { ip: '2001:db8::1', mac: '00:1b:44:11:3a:b7', ifIndex: 20, ifName: 'Vlan20' },
  ]);
  assert.equal(r.arpSource, 'ipNetToPhysical');
  assert.ok(!session.calls.subtree.includes(IP_MIB.ipNetToMediaPhysAddress),
    'the deprecated table was read although the newer one answered');
  assert.equal(r.neighbours[0].remoteAddress, '10.14.0.11');
  assert.equal(r.neighbours[0].localIfName, 'Gi1/0/2');
  assert.equal(r.inventory[0].serial, 'FDO2201A0XY');
  assert.equal(r.inventory[0].model, 'ISR4331/K9');
  assert.deepEqual([...r.supported].sort(), ['arp', 'cdp', 'entity', 'if']);
  assert.equal(session.calls.closed, true);
});

test('the reader falls back to ipNetToMedia when the newer table is empty', async () => {
  const session = fakeSession([
    vb(`${IP_MIB.ipNetToMediaPhysAddress}.30.192.168.30.7`, mac(0x00, 0x80, 0xf4, 1, 2, 3)),
    vb(`${IP_MIB.ipNetToMediaType}.30.192.168.30.7`, 3, INT),
  ]);
  const t = await defaultReadTables({}, { collect: ['arp'], session });
  const r = buildTopology(t);
  assert.deepEqual(r.arp, [{ ip: '192.168.30.7', mac: '00:80:f4:01:02:03', ifIndex: 30, ifName: null }]);
  assert.equal(r.arpSource, 'ipNetToMedia');
});

test('the ARP walk stops at its bound instead of reading the whole table', async () => {
  const rows = [];
  for (let i = 1; i <= 40; i += 1) {
    rows.push(vb(`${IP_MIB.ipNetToPhysicalPhysAddress}.20.1.4.10.0.0.${i}`, mac(0x00, 0x1b, 0x44, 0, 0, i)));
  }
  const session = fakeSession(rows);
  // The bound is the module's own; the fake only shows the walk honours a
  // feed callback that returns true.
  const { walkColumn } = require('../src/snmp/session');
  const out = await walkColumn(session, IP_MIB.ipNetToPhysicalPhysAddress, { maxRows: 10, maxRepetitions: 4 });
  assert.equal(Object.keys(out).length, 10);
  assert.ok(session.calls.fed[IP_MIB.ipNetToPhysicalPhysAddress] < 40, 'the walk did not stop');
});

test('a device that does not answer the new MIBs yields empty tables, not an error', async () => {
  const session = fakeSession([vb(SYSTEM.sysUpTime, 5, 67)]);
  const r = await pollSnmpTopology({
    device: { deviceId: 4, host: '10.20.0.1', community: 'c', collect: ['if', 'fdb', 'lldp', 'vlan', 'cdp', 'arp', 'entity'] },
    readTables: (snmp, opts) => defaultReadTables(snmp, { ...opts, session }),
  });
  assert.deepEqual(r.neighbours, []);
  assert.deepEqual(r.arp, []);
  assert.deepEqual(r.inventory, []);
  assert.deepEqual(r.supported, []);
  assert.equal(r.sysLocation, null, 'a NoSuchObject is not a location');
});

test('a failing second system GET (SNMPv1 noSuchName) does not cost the uptime', async () => {
  const session = fakeSession(routerVarbinds(), { failSecondGet: true });
  const t = await defaultReadTables({}, { collect: ['if'], session });
  assert.equal(t.sysUpTimeTicks, 123456);
  assert.equal(t.sysName, 'rtr-ot-1');
  assert.equal(t.sysLocation, null);
});

test('the new tables are walked only when the device collects them', async () => {
  const session = fakeSession(routerVarbinds());
  await defaultReadTables({}, { collect: ['if', 'fdb', 'lldp', 'vlan'], session });
  for (const oid of [CDP.cdpCacheDeviceId, IP_MIB.ipNetToPhysicalPhysAddress, ENTITY.entPhysicalClass]) {
    assert.ok(!session.calls.subtree.includes(oid), `${oid} walked for an old collect list`);
  }
});

// ------------------------------------------------------------ the submission
test('a cycle too big for one POST is split by device, errors in the first part', () => {
  const big = (id) => ({ deviceId: id, fdb: [], arp: Array.from({ length: 50 }, (_, i) => ({ ip: `10.0.${id}.${i}`, mac: '00:1b:44:11:3a:b7', ifIndex: 1, ifName: 'Vlan1' })) });
  const devices = [big(1), big(2), big(3)];
  const one = JSON.stringify(devices[0]).length;
  const parts = splitSubmission({ devices, errors: [{ deviceId: 9, error: 'timeout' }] }, one * 2 + 200);
  assert.ok(parts.length >= 2);
  assert.deepEqual(parts.flatMap((p) => p.devices.map((d) => d.deviceId)), [1, 2, 3], 'a device was lost or split');
  assert.deepEqual(parts[0].errors, [{ deviceId: 9, error: 'timeout' }]);
  assert.ok(parts.slice(1).every((p) => p.errors.length === 0), 'errors were sent twice');
  for (const p of parts) assert.ok(JSON.stringify(p).length <= one * 2 + 200);
});

test('one device too big on its own has its ARP table trimmed, and says so', () => {
  const d = { deviceId: 1, fdb: [], arp: Array.from({ length: 400 }, (_, i) => ({ ip: `10.0.1.${i}`, mac: '00:1b:44:11:3a:b7', ifIndex: 1, ifName: 'Vlan1' })), arpTruncated: false };
  const parts = splitSubmission({ devices: [d], errors: [] }, 4000);
  assert.equal(parts.length, 1);
  assert.ok(parts[0].devices[0].arp.length < 400);
  assert.equal(parts[0].devices[0].arpTruncated, true);
  assert.ok(JSON.stringify(parts[0]).length <= 4000);
  assert.equal(d.arp.length, 400, 'the poll result itself was mutated');
});

test('a normal cycle is still exactly one POST', async () => {
  const sent = [];
  const poller = createSnmpPoller({
    submit: async (b) => { sent.push(b); },
    poll: async ({ device }) => ({ deviceId: device.deviceId, fdb: [], arp: [] }),
  });
  poller.setTargets([
    { deviceId: 1, host: '10.0.0.1', community: 'c' },
    { deviceId: 2, host: '10.0.0.2', community: 'c' },
  ]);
  await poller.runCycle({ force: true });
  assert.equal(sent.length, 1);
  assert.equal(sent[0].devices.length, 2);
});

test('the poller splits a big cycle into several POSTs', async () => {
  const sent = [];
  const arp = Array.from({ length: 100 }, (_, i) => ({ ip: `10.0.0.${i}`, mac: '00:1b:44:11:3a:b7', ifIndex: 1, ifName: 'Vlan1' }));
  const poller = createSnmpPoller({
    submit: async (b) => { sent.push(b); },
    poll: async ({ device }) => ({ deviceId: device.deviceId, fdb: [], arp }),
    submitMaxBytes: JSON.stringify({ deviceId: 1, fdb: [], arp }).length + 100,
  });
  poller.setTargets([
    { deviceId: 1, host: '10.0.0.1', community: 'c' },
    { deviceId: 2, host: '10.0.0.2', community: 'c' },
  ]);
  await poller.runCycle({ force: true });
  assert.equal(sent.length, 2);
  assert.deepEqual(sent.map((b) => b.devices[0].deviceId), [1, 2]);
});
