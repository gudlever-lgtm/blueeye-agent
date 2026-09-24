'use strict';

// A slow router must cost its OPTIONAL tables (arp, entity, cdp), never its
// core ones. The server widened the default collect list with those three, all
// inside the same per-device timeout as the forwarding table; a device that
// answered the ARP walk slowly used to time out as a whole and lose its
// interfaces, forwarding table and LLDP neighbours for the cycle.
//
// What has to hold:
//   * the core walks run first and are submitted whatever the optional ones do;
//   * an optional walk that hangs is abandoned inside the device's budget, the
//     rows it had are kept where a partial table is safe (arp) and dropped
//     where it is not (cdp: diffed; entity: replaced), and the kind is named
//     in the device's `partial` list — never in `errors`, which would mark a
//     device whose core poll succeeded as failed;
//   * `supported` does not flip a kind off for one slow cycle.

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { pollSnmpTopology, defaultReadTables } = require('../src/snmpTopology');
const { createSnmpPoller, splitSubmission } = require('../src/snmpPoller');
const { walkColumnWithin } = require('../src/snmp/session');
const {
  IF_MIB, BRIDGE, LLDP, CDP, IP_MIB, ENTITY, SYSTEM,
} = require('../src/snmp/oids');
const { validateSnmpTopologyBatch } = safeServerValidation();

// The server's own validator, when the sister checkout is next to this one —
// proof that the new per-device key is ignored harmlessly rather than refused.
function safeServerValidation() {
  try {
    // eslint-disable-next-line global-require
    return require('../../blueeye-server/src/validation/snmpDeviceValidation');
  } catch {
    return {};
  }
}

const OCTETS = 4;
const INT = 2;
const vb = (oid, value, type = OCTETS) => ({ oid, type, value });
const mac = (...b) => Buffer.from(b);

// A session that answers like net-snmp, except that the walks named in `hang`
// feed `hangAfter` rows and then never finish (a router grinding through its
// ARP table), and those in `fail` end with an error.
function slowSession(varbinds, { hang = [], hangAfter = 2, fail = [], coreDelayMs = 0 } = {}) {
  const calls = { subtree: [], closed: false, fedAfterAbandon: 0 };
  return {
    calls,
    subtree(base, maxRep, feed, done) {
      calls.subtree.push(base);
      const rows = varbinds.filter((v) => v.oid.startsWith(`${base}.`));
      if (hang.includes(base)) {
        feed(rows.slice(0, hangAfter));
        // One more chunk long after the walk was abandoned: the feed callback
        // must refuse it (return true) rather than keep reading.
        const t = setTimeout(() => { if (feed(rows.slice(hangAfter)) === true) calls.fedAfterAbandon += 1; }, 400);
        t.unref();
        return; // never calls done()
      }
      if (fail.includes(base)) {
        feed(rows.slice(0, 1));
        setImmediate(() => done(new Error('RequestTimedOutError: Request timed out')));
        return;
      }
      setTimeout(() => {
        for (let i = 0; i < rows.length; i += maxRep) {
          if (feed(rows.slice(i, i + maxRep))) break;
        }
        done(null);
      }, coreDelayMs);
    },
    get(oids, cb) {
      setImmediate(() => cb(null, oids.map((oid) => varbinds.find((v) => v.oid === oid) || { oid, type: 128, value: null })));
    },
    close() { calls.closed = true; },
  };
}

// A small L3 switch: two ports, one learned MAC, one LLDP neighbour, and the
// optional tables (ARP with 5 rows, CDP, ENTITY).
function routerVarbinds() {
  const rows = [
    vb(SYSTEM.sysUpTime, 4242, 67),
    vb(SYSTEM.sysName, Buffer.from('rtr-1')),
    vb(`${IF_MIB.ifName}.1`, Buffer.from('Gi1/0/1')),
    vb(`${IF_MIB.ifName}.2`, Buffer.from('Gi1/0/2')),
    vb(`${IF_MIB.ifName}.20`, Buffer.from('Vlan20')),
    vb(`${IF_MIB.ifOperStatus}.1`, 1, INT),
    vb(`${BRIDGE.dot1dBasePortIfIndex}.1`, 1, INT),
    vb(`${BRIDGE.dot1dBasePortIfIndex}.2`, 2, INT),
    vb(`${BRIDGE.dot1dTpFdbPort}.0.27.68.17.58.183`, 2, INT),
    vb(`${BRIDGE.dot1dTpFdbStatus}.0.27.68.17.58.183`, 3, INT),
    vb(`${LLDP.lldpRemChassisId}.0.1.1`, Buffer.from('sw-core')),
    vb(`${LLDP.lldpRemChassisIdSubtype}.0.1.1`, 7, INT),
    vb(`${LLDP.lldpRemPortId}.0.1.1`, Buffer.from('Te1/1/1')),
    vb(`${LLDP.lldpRemPortIdSubtype}.0.1.1`, 5, INT),
    vb(`${LLDP.lldpRemSysName}.0.1.1`, Buffer.from('sw-core')),
    vb(`${CDP.cdpCacheDeviceId}.2.1`, Buffer.from('sw-dist-1')),
    vb(`${CDP.cdpCacheDevicePort}.2.1`, Buffer.from('Gi1/0/48')),
    vb(`${CDP.cdpCacheDeviceId}.2.2`, Buffer.from('sw-dist-2')),
    vb(`${ENTITY.entPhysicalClass}.1`, 3, INT),
    vb(`${ENTITY.entPhysicalModelName}.1`, Buffer.from('C9300-48P')),
    vb(`${ENTITY.entPhysicalSerialNum}.1`, Buffer.from('FOC1234X0YZ')),
  ];
  for (let i = 1; i <= 5; i += 1) {
    rows.push(vb(`${IP_MIB.ipNetToPhysicalPhysAddress}.20.1.4.10.20.0.${i}`, mac(0x00, 0x1b, 0x44, 0, 0, i)));
    rows.push(vb(`${IP_MIB.ipNetToPhysicalState}.20.1.4.10.20.0.${i}`, 1, INT));
  }
  return rows;
}

const ALL = ['if', 'fdb', 'lldp', 'vlan', 'cdp', 'arp', 'entity'];
const DEVICE = (over = {}) => ({
  deviceId: 9, host: '10.20.0.1', community: 'c', collect: ALL, intervalSec: 300, ...over,
});
const pollWith = (session) => (args) => pollSnmpTopology({
  ...args,
  readTables: (snmp, opts) => defaultReadTables(snmp, { ...opts, session }),
});

function assertCoreIntact(dev) {
  assert.equal(dev.fdb.length, 1, 'the forwarding table survived');
  assert.equal(dev.fdb[0].ifName, 'Gi1/0/2');
  assert.ok(dev.interfaces.length >= 2, 'the interfaces survived');
  assert.equal(dev.neighbours.filter((n) => n.protocol !== 'cdp').length, 1, 'the LLDP neighbour survived');
  assert.equal(dev.sysUpTimeTicks, 4242);
}

// ------------------------------------------------------------------ the walk
test('walkColumnWithin: a hung walk resolves at its time bound with the rows it had', async () => {
  const s = slowSession(routerVarbinds(), { hang: [IP_MIB.ipNetToPhysicalPhysAddress], hangAfter: 2 });
  const t0 = Date.now();
  const r = await walkColumnWithin(s, IP_MIB.ipNetToPhysicalPhysAddress, { timeoutMs: 60 });
  assert.equal(r.timedOut, true);
  assert.equal(r.error, null);
  assert.equal(Object.keys(r.rows).length, 2);
  assert.ok(Date.now() - t0 < 1000);
  await new Promise((res) => setTimeout(res, 450));
  assert.equal(s.calls.fedAfterAbandon, 1, 'the abandoned walk told net-snmp to stop');
  assert.equal(Object.keys(r.rows).length, 2, 'and nothing was added after the fact');
});

test('walkColumnWithin: an error resolves (never rejects) with the rows read so far', async () => {
  const s = slowSession(routerVarbinds(), { fail: [CDP.cdpCacheDeviceId] });
  const r = await walkColumnWithin(s, CDP.cdpCacheDeviceId, { timeoutMs: 1000 });
  assert.equal(r.timedOut, false);
  assert.match(r.error.message, /timed out/);
  assert.equal(Object.keys(r.rows).length, 1);
});

// ----------------------------------------------------------- the whole poll
test('an ARP walk that hangs costs the ARP table, not the device: core submitted, arp partial', async () => {
  const session = slowSession(routerVarbinds(), { hang: [IP_MIB.ipNetToPhysicalPhysAddress], hangAfter: 3 });
  const submits = [];
  const p = createSnmpPoller({
    submit: async (payload) => { submits.push(payload); },
    poll: pollWith(session),
    timeoutMs: 400,
  });
  p.setTargets([DEVICE()]);
  const t0 = Date.now();
  const out = await p.runCycle({ force: true });
  const took = Date.now() - t0;

  assert.deepEqual(out, { polled: 1, failed: 0 }, 'the device is NOT reported as failed');
  assert.ok(took < 400, `finished inside the device budget (${took} ms)`);
  assert.equal(submits.length, 1);
  assert.deepEqual(submits[0].errors, [], 'no per-device error: that would mark the poll as failed');
  const dev = submits[0].devices[0];
  assertCoreIntact(dev);
  // The rows the walk had read are kept (ARP is upserted, never replaced), and
  // the table says it is incomplete.
  assert.equal(dev.arp.length, 3);
  assert.equal(dev.arpTruncated, true);
  assert.deepEqual(dev.partial.map((x) => [x.kind, x.reason, x.rows]), [['arp', 'timeout', 3]]);
  // The other optional tables answered in time and are whole.
  assert.equal(dev.inventory[0].serial, 'FOC1234X0YZ');
  assert.equal(dev.neighbours.filter((n) => n.protocol === 'cdp').length, 2);
  assert.ok(!session.calls.subtree.includes(IP_MIB.ipNetToMediaPhysAddress),
    'a cut walk of the newer table is not a reason to walk the older one');
  assert.equal(session.calls.closed, true);
});

test('before this change the same hang lost the whole device (core and optional in one budget)', async () => {
  // The old behaviour, reproduced: a poll that is not told its budget and
  // whose reader waits on every walk is simply cut off by the poller.
  const session = slowSession(routerVarbinds(), { hang: [IP_MIB.ipNetToPhysicalPhysAddress] });
  const submits = [];
  const p = createSnmpPoller({
    submit: async (payload) => { submits.push(payload); },
    poll: ({ device }) => pollWith(session)({ device }), // no timeoutMs: unbounded optional phase
    timeoutMs: 200,
  });
  p.setTargets([DEVICE()]);
  assert.deepEqual(await p.runCycle({ force: true }), { polled: 0, failed: 1 });
  assert.equal(submits[0].devices.length, 0);
  assert.equal(submits[0].errors[0].code, 'SNMP_TIMEOUT');
});

test('a hung CDP walk drops CDP entirely (half a table would diff as removals); LLDP is kept', async () => {
  const session = slowSession(routerVarbinds(), { hang: [CDP.cdpCacheDeviceId], hangAfter: 1 });
  const dev = await pollWith(session)({ device: DEVICE(), timeoutMs: 300 });
  assertCoreIntact(dev);
  assert.equal(dev.neighbours.filter((n) => n.protocol === 'cdp').length, 0);
  assert.deepEqual(dev.partial.map((x) => [x.kind, x.reason]), [['cdp', 'timeout']]);
  assert.equal(dev.arp.length, 5, 'ARP answered in time and is whole');
  assert.equal(dev.arpTruncated, false);
});

test('a failing ENTITY walk drops the inventory (the server REPLACES it) and names the error', async () => {
  const session = slowSession(routerVarbinds(), { fail: [ENTITY.entPhysicalSerialNum] });
  const dev = await pollWith(session)({ device: DEVICE(), timeoutMs: 1000 });
  assertCoreIntact(dev);
  assert.deepEqual(dev.inventory, [], 'half an inventory would erase the other half on the server');
  assert.equal(dev.partial.length, 1);
  assert.equal(dev.partial[0].kind, 'entity');
  assert.equal(dev.partial[0].reason, 'error');
  assert.match(dev.partial[0].error, /timed out/);
});

test('core walks that use up the budget leave the optional ones un-issued, reported as no-time', async () => {
  const session = slowSession(routerVarbinds(), { coreDelayMs: 200 });
  const dev = await pollWith(session)({ device: DEVICE(), timeoutMs: 210 });
  assertCoreIntact(dev);
  assert.deepEqual(dev.partial.map((x) => [x.kind, x.reason]).sort(),
    [['arp', 'no-time'], ['cdp', 'no-time'], ['entity', 'no-time']]);
  for (const oid of [CDP.cdpCacheDeviceId, IP_MIB.ipNetToPhysicalPhysAddress, ENTITY.entPhysicalClass]) {
    assert.ok(!session.calls.subtree.includes(oid), `${oid} walked with no time left`);
  }
});

test('a healthy device carries no partial key at all', async () => {
  const dev = await pollWith(slowSession(routerVarbinds()))({ device: DEVICE(), timeoutMs: 1000 });
  assert.equal('partial' in dev, false);
  assert.deepEqual([...dev.supported].sort(), ['arp', 'cdp', 'entity', 'fdb', 'if', 'lldp']);
});

test('`supported` keeps a kind the device answered last cycle when this cycle cut it short', async () => {
  let hang = [];
  const submits = [];
  const p = createSnmpPoller({
    submit: async (payload) => { submits.push(payload); },
    poll: (args) => pollWith(slowSession(routerVarbinds(), { hang }))(args),
    timeoutMs: 300,
  });
  p.setTargets([DEVICE()]);
  await p.runCycle({ force: true });
  assert.ok(submits[0].devices[0].supported.includes('cdp'));
  hang = [CDP.cdpCacheDeviceId];
  await p.runCycle({ force: true });
  const dev = submits[1].devices[0];
  assert.equal(dev.neighbours.filter((n) => n.protocol === 'cdp').length, 0);
  assert.ok(dev.supported.includes('cdp'), 'one slow cycle is not "does not support cdp"');
  // A device never seen to answer a kind does not get it invented.
  const fresh = createSnmpPoller({
    submit: async (payload) => { submits.push(payload); },
    poll: (args) => pollWith(slowSession(routerVarbinds(), { hang: [CDP.cdpCacheDeviceId] }))(args),
    timeoutMs: 300,
  });
  fresh.setTargets([DEVICE()]);
  await fresh.runCycle({ force: true });
  assert.equal(submits[2].devices[0].supported.includes('cdp'), false);
});

// -------------------------------------------------- the submission, with markers
test('the ~900 KiB split still holds with partial markers, and keeps them', () => {
  const arpRows = (id, n) => Array.from({ length: n }, (_, i) => ({
    ip: `10.${id}.${(i >> 8) & 255}.${i & 255}`, mac: '00:1b:44:11:3a:b7', ifIndex: 20, ifName: 'Vlan20',
  }));
  const partial = [{ kind: 'arp', reason: 'timeout', rows: 8192 }, { kind: 'entity', reason: 'error', error: 'x'.repeat(200) }];
  const devices = [1, 2, 3].map((id) => ({
    deviceId: id, fdb: [], interfaces: [], neighbours: [], vlans: [], supported: ['arp'],
    arp: arpRows(id, 8192), arpTruncated: true, arpTotal: 8192, partial,
  }));
  const errors = Array.from({ length: 50 }, (_, i) => ({ deviceId: 100 + i, error: 'e'.repeat(255), code: 'SNMP_TIMEOUT' }));
  const max = 200 * 1024; // small, so three routers cannot share a POST
  const parts = splitSubmission({ devices, errors }, max);
  assert.ok(parts.length >= 2);
  for (const part of parts) {
    assert.ok(Buffer.byteLength(JSON.stringify(part)) <= max, 'every POST fits');
    for (const d of part.devices) assert.deepEqual(d.partial, partial, 'markers travel with their device');
  }
  assert.equal(parts[0].errors.length, 50);
  assert.deepEqual(parts.flatMap((x) => x.devices.map((d) => d.deviceId)), [1, 2, 3]);
  if (validateSnmpTopologyBatch) {
    const errs = {};
    const batch = validateSnmpTopologyBatch(parts[0], errs);
    assert.ok(batch, `the server accepts it: ${JSON.stringify(errs)}`);
    assert.equal(batch.devices.length, parts[0].devices.length);
    assert.equal(batch.failures.length, 50);
  }
});
