'use strict';

// Real SNMP traps, sent by Net-SNMP's `snmptrap` and captured off the wire
// (test/fixtures/traps/README.md has every command). test/traps.test.js
// injects already-decoded varbinds; this runs the bytes a real sender emits
// through the agent's own path — decode → translate, and the receiver over a
// real UDP socket — and, where the optional `net-snmp` module is installed,
// checks the agent's decode against that library's decode of the same bytes.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const dgram = require('dgram');

const { decodeTrap } = require('../src/traps/decode');
const { translateTrap } = require('../src/traps/translate');
const { createTrapReceiver } = require('../src/traps/receiver');

const DIR = path.join(__dirname, 'fixtures', 'traps');
const load = (name) => fs.readFileSync(path.join(DIR, name));
const FILES = fs.readdirSync(DIR).filter((f) => f.endsWith('.bin')).sort();

const OID_SYSUPTIME = '1.3.6.1.2.1.1.3.0';
const OID_TRAP_OID = '1.3.6.1.6.3.1.1.4.1.0';
const OID_TRAP_ENTERPRISE = '1.3.6.1.6.3.1.1.4.3.0';

// What each capture must translate to. ifIndex is read out of the row's own
// detail varbinds, so the assertion is on what the agent reports.
const EXPECT = {
  '001-v1-linkdown-admin-down.bin': { version: '1', type: 'link.admin_down', ifIndex: 3 },
  '002-v1-linkup.bin': { version: '1', type: 'link.up', ifIndex: 3 },
  '003-v1-coldstart.bin': { version: '1', type: 'device.rebooted', ifIndex: null },
  '004-v1-cisco-config-man-event.bin': { version: '1', type: 'config.changed', ifIndex: null },
  '005-v2c-linkdown-oper-down.bin': { version: '2c', type: 'link.down', ifIndex: 10103, ifname: 'GigabitEthernet1/0/3' },
  '006-v2c-linkdown-admin-down.bin': { version: '2c', type: 'link.admin_down', ifIndex: 10104 },
  '007-v2c-linkup.bin': { version: '2c', type: 'link.up', ifIndex: 10103 },
  '008-v2c-coldstart.bin': { version: '2c', type: 'device.rebooted', ifIndex: null },
  '009-v2c-cisco-config-man-event.bin': { version: '2c', type: 'config.changed', ifIndex: null },
  '010-v2c-coldstart-other-community.bin': { version: '2c', type: 'device.rebooted', ifIndex: null, community: 'notthesame' },
};

const valueOf = (varbinds, oid) => {
  const vb = varbinds.find((v) => v.oid === oid);
  return vb ? vb.value : undefined;
};
const ifIndexOf = (row) => {
  const vb = row.detail.varbinds.find((v) => v.oid.startsWith('1.3.6.1.2.1.2.2.1.1.'));
  return vb ? Number(vb.value) : null;
};

test('fixtures: every captured trap has an expectation (and v3 is present)', () => {
  assert.deepEqual(FILES.filter((f) => !f.includes('-v3-')), Object.keys(EXPECT).sort());
  assert.ok(FILES.includes('011-v3-noauth-coldstart.bin'));
});

for (const [file, want] of Object.entries(EXPECT)) {
  test(`real trap ${file}: decode → translate gives ${want.type}`, () => {
    const decoded = decodeTrap(load(file));
    assert.equal(decoded.version, want.version);
    assert.equal(decoded.community, want.community || 'public');
    // Both versions come out in the v2 shape: sysUpTime.0 then snmpTrapOID.0.
    assert.equal(decoded.varbinds[0].oid, OID_SYSUPTIME);
    assert.equal(decoded.varbinds[1].oid, OID_TRAP_OID);
    assert.ok(Number.isInteger(decoded.varbinds[0].value) && decoded.varbinds[0].value >= 0);

    const row = translateTrap({ varbinds: decoded.varbinds, sourceIp: '192.0.2.10', receivedAt: Date.UTC(2026, 8, 24) });
    assert.equal(row.eventType, want.type);
    assert.equal(row.transport, 'trap');
    assert.equal(row.sourceIp, '192.0.2.10');
    assert.equal(row.deviceTime, null, 'a trap has no wall clock; never fabricated');
    assert.equal(row.tag, decoded.varbinds[1].value);
    assert.equal(ifIndexOf(row), want.ifIndex);
    if (want.ifIndex != null) {
      // The row names the interface, by ifDescr when the trap carries it, and
      // otherwise by index — never by a guess.
      assert.match(row.summary, want.ifname ? new RegExp(want.ifname.replace(/\//g, '\\/')) : new RegExp(`ifIndex ${want.ifIndex}\\b`));
    }
    if (want.ifname) assert.equal(row.ifname, want.ifname);
    assert.ok(Number.isInteger(row.severity) && row.severity >= 0 && row.severity <= 7);
  });
}

test('real linkDown traps: admin-down is told apart from a port that fell over', () => {
  const fault = translateTrap({ varbinds: decodeTrap(load('005-v2c-linkdown-oper-down.bin')).varbinds, sourceIp: 'x', receivedAt: 0 });
  const adminV2 = translateTrap({ varbinds: decodeTrap(load('006-v2c-linkdown-admin-down.bin')).varbinds, sourceIp: 'x', receivedAt: 0 });
  const adminV1 = translateTrap({ varbinds: decodeTrap(load('001-v1-linkdown-admin-down.bin')).varbinds, sourceIp: 'x', receivedAt: 0 });
  assert.equal(fault.eventType, 'link.down');
  assert.match(fault.summary, /now down/);
  assert.ok(fault.severity < adminV2.severity, 'a fault outranks a shutdown');
  for (const r of [adminV1, adminV2]) {
    assert.equal(r.eventType, 'link.admin_down');
    assert.match(r.summary, /administratively down/);
  }
});

test('real v1 traps carry the RFC 3584 enterprise; the Cisco specific trap maps to enterprise.0.specific', () => {
  const cold = decodeTrap(load('003-v1-coldstart.bin')).varbinds;
  assert.equal(valueOf(cold, OID_TRAP_OID), '1.3.6.1.6.3.1.1.5.1');
  assert.equal(valueOf(cold, OID_TRAP_ENTERPRISE), '1.3.6.1.4.1.9.1.1208');
  const cfg = decodeTrap(load('004-v1-cisco-config-man-event.bin')).varbinds;
  assert.equal(valueOf(cfg, OID_TRAP_OID), '1.3.6.1.4.1.9.9.43.2.0.1');
  assert.equal(valueOf(cfg, OID_TRAP_ENTERPRISE), '1.3.6.1.4.1.9.9.43.2');
  // ccmHistoryEventCommandSource = commandLine(1), config source = running(3)
  assert.equal(valueOf(cfg, '1.3.6.1.4.1.9.9.43.1.1.6.1.3.42'), 1);
  assert.equal(valueOf(cfg, '1.3.6.1.4.1.9.9.43.1.1.6.1.4.42'), 3);
});

test('a real SNMPv3 trap is refused as v3, not counted as garbage', () => {
  assert.throws(() => decodeTrap(load('011-v3-noauth-coldstart.bin')), (e) => e.code === 'TRAP_V3_UNSUPPORTED');
});

test('the receiver, fed every capture over UDP from a polled device, buffers the events and refuses the rest', async () => {
  let sock = null;
  const rx = createTrapReceiver({
    port: 0,
    bindAddress: '127.0.0.1',
    createSocket: () => { sock = dgram.createSocket('udp4'); return sock; },
    isKnownSender: (ip) => ip === '127.0.0.1',
    expectedCommunity: () => 'public',
    checkCommunity: true,
  });
  await rx.start();
  try {
    const { port } = sock.address();
    const tx = dgram.createSocket('udp4');
    for (const f of FILES) {
      // eslint-disable-next-line no-await-in-loop
      await new Promise((resolve, reject) => tx.send(load(f), port, '127.0.0.1', (e) => (e ? reject(e) : resolve())));
    }
    tx.close();
    const settled = () => { const s = rx.stats(); return s.received + s.badCommunity + s.v3 + s.undecodable; };
    const deadline = Date.now() + 2000;
    while (settled() < FILES.length && Date.now() < deadline) {
      // eslint-disable-next-line no-await-in-loop
      await new Promise((r) => setTimeout(r, 10));
    }
    const st = rx.stats();
    assert.equal(st.received, 9, 'the nine public-community v1/v2c traps');
    assert.equal(st.badCommunity, 1, 'the one sent with another community');
    assert.equal(st.v3, 1);
    assert.equal(st.undecodable, 0);
    assert.equal(st.refused, 0);

    const events = rx.drain();
    assert.equal(events.reduce((a, e) => a + e.occurrences, 0), 9);
    const types = new Set(events.map((e) => e.eventType));
    assert.deepEqual([...types].sort(), ['config.changed', 'device.rebooted', 'link.admin_down', 'link.down', 'link.up']);
    for (const e of events) assert.equal(e.sourceIp, '127.0.0.1');
  } finally {
    rx.stop();
  }
});

// ---- cross-check against the net-snmp library ----------------------------

let snmp = null;
try { snmp = require('net-snmp'); } catch { snmp = null; }

function freePort() {
  return new Promise((resolve) => {
    const s = dgram.createSocket('udp4');
    s.bind(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
  });
}

const norm = (v) => (Buffer.isBuffer(v) ? v.toString('latin1') : v);

test('net-snmp decodes the same captures to the same varbinds as the agent', { skip: !snmp && 'net-snmp not installed' }, async () => {
  const port = await freePort();
  const got = [];
  const receiver = snmp.createReceiver(
    { port, address: '127.0.0.1', transport: 'udp4', disableAuthorization: true },
    (err, n) => { if (!err && n && n.pdu) got.push(n.pdu); },
  );
  try {
    const tx = dgram.createSocket('udp4');
    for (const f of FILES) {
      // eslint-disable-next-line no-await-in-loop
      await new Promise((resolve, reject) => tx.send(load(f), port, '127.0.0.1', (e) => (e ? reject(e) : resolve())));
      // eslint-disable-next-line no-await-in-loop
      await new Promise((r) => setTimeout(r, 5)); // keep arrival order = file order
    }
    tx.close();
    const deadline = Date.now() + 2000;
    while (got.length < FILES.length && Date.now() < deadline) {
      // eslint-disable-next-line no-await-in-loop
      await new Promise((r) => setTimeout(r, 10));
    }
    assert.equal(got.length, FILES.length, 'net-snmp accepted every capture (v3 included)');

    FILES.forEach((f, i) => {
      if (f.includes('-v3-')) return; // the agent does not decode v3 — asserted above
      const lib = got[i];
      const ours = decodeTrap(load(f)).varbinds;
      if (lib.type === snmp.PduType.Trap) {
        // v1: rebuild the RFC 3584 shape from net-snmp's TrapPdu fields.
        const trapOid = lib.generic < 6 ? `1.3.6.1.6.3.1.1.5.${lib.generic + 1}` : `${lib.enterprise}.0.${lib.specific}`;
        assert.equal(valueOf(ours, OID_SYSUPTIME), lib.upTime, f);
        assert.equal(valueOf(ours, OID_TRAP_OID), trapOid, f);
        assert.equal(valueOf(ours, OID_TRAP_ENTERPRISE), lib.enterprise, f);
        assert.deepEqual(ours.slice(2, -1).map((v) => [v.oid, norm(v.value)]), lib.varbinds.map((v) => [v.oid, norm(v.value)]), f);
      } else {
        assert.deepEqual(ours.map((v) => [v.oid, norm(v.value)]), lib.varbinds.map((v) => [v.oid, norm(v.value)]), f);
      }
    });
  } finally {
    receiver.close();
  }
});
