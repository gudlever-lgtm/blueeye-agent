'use strict';

// Trin 2: the shared SNMP client, in its own file.
//
// Before this there were three copies of walkColumn, three `require('net-snmp')`
// guards and three value coercions, drifting slowly apart. These tests pin the
// behaviour the whole SNMP surface now rests on — and one of them documents a
// real bug the consolidation surfaced.

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  toNumber, toText, toMac, walkColumn, getScalars, openSession, closeSession, loadNetSnmp,
} = require('../src/snmp/session');
const OIDS = require('../src/snmp/oids');

// ============================================================== the coercions
test('an absent value is NULL, not zero — Number(null) is the trap', () => {
  // This is the bug consolidating the three copies surfaced. `Number(null)` is
  // 0 in JavaScript, so a single unguarded conversion turns "the device did not
  // answer" into "the device answered zero" — and zero errors is what RULES OUT
  // a fault, so the wrong answer is the confident one.
  assert.equal(toNumber(null), null);
  assert.equal(toNumber(undefined), null);
  assert.equal(toNumber(''), null);
  assert.equal(toNumber('not a number'), null);
  assert.equal(toNumber(NaN), null);
  assert.equal(toNumber(0), 0, 'a real zero is a real measurement');
});

test('a Counter64 Buffer becomes a number', () => {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(123456789012n);
  assert.equal(toNumber(buf), 123456789012);
});

test('a short Buffer (Gauge32, TimeTicks) still reads', () => {
  const buf = Buffer.from([0x00, 0x00, 0x03, 0xe8]);
  assert.equal(toNumber(buf), 1000);
  assert.equal(toNumber(Buffer.alloc(0)), null, 'an empty buffer is not a zero');
});

test('toText strips the NUL padding a switch puts on a fixed-width string', () => {
  assert.equal(toText(Buffer.from('Gi0/24\0\0\0', 'utf8')), 'Gi0/24');
  assert.equal(toText('  core-sw-1  '), 'core-sw-1');
  assert.equal(toText(''), null);
  assert.equal(toText(Buffer.from('\0\0')), null);
});

test('toMac renders exactly six bytes, and refuses anything else', () => {
  assert.equal(toMac(Buffer.from([0x00, 0x1b, 0x44, 0x11, 0x3a, 0xb7])), '00:1b:44:11:3a:b7');
  assert.equal(toMac(Buffer.from([0x00, 0x1b])), null);
  assert.equal(toMac('00:1b:44:11:3a:b7'), null, 'a string is not an OCTET STRING');
  assert.equal(toMac(null), null);
});

// ================================================================== the walk
function fakeSession({ rows = {}, err = null, capture = null } = {}) {
  return {
    closed: false,
    subtree(oid, maxRepetitions, feed, done) {
      if (capture) capture.push({ oid, maxRepetitions });
      if (err) return done(err);
      const varbinds = Object.entries(rows[oid] || {})
        .map(([suffix, value]) => ({ oid: `${oid}.${suffix}`, type: 4, value }));
      feed(varbinds);
      return done(null);
    },
    get(oids, cb) {
      if (err) return cb(err);
      return cb(null, oids.map((o) => ({ oid: o, type: 4, value: rows[o] })));
    },
    close() { this.closed = true; },
  };
}

test('walkColumn keys the result on everything after the base OID', () => {
  const base = OIDS.IF_MIB.ifName;
  const session = fakeSession({ rows: { [base]: { 1: 'Gi0/1', 2: 'Gi0/2' } } });
  return walkColumn(session, base).then((out) => {
    assert.deepEqual(out, { 1: 'Gi0/1', 2: 'Gi0/2' });
  });
});

test('walkColumn asks for a BULK window, because a 48-port column is 48 rows', async () => {
  // The library default is 20 per round trip. Forty columns against a big
  // chassis is the difference between one poll and a poll that outlives its
  // own interval.
  const capture = [];
  const session = fakeSession({ rows: {}, capture });
  await walkColumn(session, OIDS.IF_MIB.ifName);
  assert.equal(capture[0].maxRepetitions, 25);
  await walkColumn(session, OIDS.IF_MIB.ifName, { maxRepetitions: 50 });
  assert.equal(capture[1].maxRepetitions, 50);
});

test('walkColumn skips an error varbind rather than storing it', async () => {
  // noSuchInstance / endOfMibView carry no usable value. Skipping them is what
  // lets a device that implements half a table answer for the half it has.
  const base = OIDS.IF_MIB.ifName;
  const session = {
    subtree(oid, maxRep, feed, done) {
      feed([
        { oid: `${oid}.1`, type: 4, value: 'Gi0/1' },
        { oid: `${oid}.2`, type: undefined, value: null },
        null,
      ]);
      done(null);
    },
  };
  assert.deepEqual(await walkColumn(session, base), { 1: 'Gi0/1' });
});

test('a failed walk rejects, so the caller decides whether it was optional', async () => {
  const session = fakeSession({ err: new Error('RequestTimedOutError') });
  await assert.rejects(() => walkColumn(session, OIDS.IF_MIB.ifName), /RequestTimedOutError/);
});

test('getScalars reads several OIDs in ONE round trip', async () => {
  const session = fakeSession({
    rows: { [OIDS.SYSTEM.sysUpTime]: 123456, [OIDS.SYSTEM.sysName]: 'sw-core-1' },
  });
  const out = await getScalars(session, [OIDS.SYSTEM.sysUpTime, OIDS.SYSTEM.sysName]);
  assert.equal(toNumber(out[OIDS.SYSTEM.sysUpTime]), 123456);
  assert.equal(toText(out[OIDS.SYSTEM.sysName]), 'sw-core-1');
});

test('closeSession never throws, because a close must not fail a good poll', () => {
  assert.doesNotThrow(() => closeSession(null));
  assert.doesNotThrow(() => closeSession({}));
  assert.doesNotThrow(() => closeSession({ close() { throw new Error('already gone'); } }));
  const s = fakeSession();
  closeSession(s);
  assert.equal(s.closed, true);
});

// ================================================================== the OIDs
test('openSession picks the version the device is configured for', () => {
  const calls = [];
  const fakeSnmp = {
    Version1: 0, Version2c: 1,
    createSession: (host, community, opts) => { calls.push({ host, community, opts }); return {}; },
  };
  openSession({ host: '10.14.0.11', community: 'public', version: '2c' }, { snmp: fakeSnmp });
  openSession({ host: '10.14.0.12', version: '1', port: 1161 }, { snmp: fakeSnmp });
  assert.equal(calls[0].opts.version, 1);
  assert.equal(calls[0].opts.port, 161);
  assert.equal(calls[1].opts.version, 0);
  assert.equal(calls[1].opts.port, 1161);
  assert.equal(calls[1].community, 'public', 'the protocol default, not an empty string');
});

test('every OID is a dotted number, and none is written twice', () => {
  // The failure mode of an OID typo is not an exception — a column comes back
  // empty and the device looks like it does not implement the MIB. Nothing else
  // catches that.
  const seen = new Map();
  for (const [group, entries] of Object.entries(OIDS)) {
    if (group.endsWith('_STATUS')) continue;
    for (const [name, oid] of Object.entries(entries)) {
      assert.match(oid, /^\d+(\.\d+)+$/, `${group}.${name}`);
      if (seen.has(oid)) {
        assert.fail(`${group}.${name} repeats ${seen.get(oid)} (${oid})`);
      }
      seen.set(oid, `${group}.${name}`);
    }
  }
  assert.ok(seen.size >= 40, `only ${seen.size} OIDs`);
});

test('the high-capacity octet counters are the ones a poller should reach for', () => {
  // A 32-bit octet counter wraps in ~34 seconds on a saturated gigabit port,
  // which is faster than any polling interval worth having. Both are in the map
  // because some devices only have the narrow ones; the 64-bit pair is what the
  // counter path uses.
  assert.equal(OIDS.IF_MIB.ifHCInOctets, '1.3.6.1.2.1.31.1.1.1.6');
  assert.equal(OIDS.IF_MIB.ifHCOutOctets, '1.3.6.1.2.1.31.1.1.1.10');
  assert.equal(OIDS.IF_MIB.ifInOctets, '1.3.6.1.2.1.2.2.1.10');
});

test('net-snmp is present, so the SNMP features actually run', () => {
  // It shipped as an optionalDependency in this change. Before that, every SNMP
  // module in this repo was working code that threw SNMP_UNAVAILABLE on any
  // deployed host — the audit's first finding.
  assert.doesNotThrow(() => loadNetSnmp('SNMP'));
});
