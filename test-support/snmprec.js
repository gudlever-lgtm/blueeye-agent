'use strict';

// Serves an snmpsim `.snmprec` recording (test/fixtures/snmprec/) through the
// same interface the agent's SNMP readers use: a net-snmp SESSION
// (`get` / `subtree` / `close`) and, for readers that open their own session,
// a net-snmp-shaped MODULE whose `createSession` returns it. So
// src/snmpTopology.js defaultReadTables and src/snmp/counters.js
// defaultReadCounters run unchanged — only the device is a recording.
//
// .snmprec is `OID|TAG|VALUE`, one varbind per line, TAG being the BER type
// number (a trailing `x` means VALUE is hex). Values come back in the shapes
// net-snmp 3.x hands a caller, which is what the readers are written against:
//
//   2 Integer, 65 Counter32, 66 Gauge32, 67 TimeTicks, 71 UInteger32 -> number
//   4 OctetString, 68 Opaque, 70 Counter64                          -> Buffer
//   6 ObjectIdentifier, 64 IpAddress                                 -> string
//   5 Null                                                           -> null
//
// (Checked against a real walk: the same recordings served by snmpsim 1.2.2
// and read with net-snmp give identical tables — see
// test/snmpRealWalks.test.js, BLUEEYE_SNMPSIM_ENDPOINT.)

const fs = require('fs');

const T = {
  Integer: 2, OctetString: 4, Null: 5, OID: 6, IpAddress: 64, Counter32: 65, Gauge32: 66,
  TimeTicks: 67, Opaque: 68, Counter64: 70, UInteger32: 71, NoSuchObject: 128, NoSuchInstance: 129,
};

function compareOid(a, b) {
  const x = a.split('.').map(Number);
  const y = b.split('.').map(Number);
  for (let i = 0; i < Math.min(x.length, y.length); i += 1) {
    if (x[i] !== y[i]) return x[i] - y[i];
  }
  return x.length - y.length;
}

function decodeValue(tag, raw) {
  const hex = tag.endsWith('x');
  const type = Number(hex ? tag.slice(0, -1) : tag.split(':')[0]);
  const bytes = () => (hex ? Buffer.from(raw, 'hex') : Buffer.from(raw, 'utf8'));
  switch (type) {
    case T.Integer: case T.Counter32: case T.Gauge32: case T.TimeTicks: case T.UInteger32:
      return { type, value: Number(raw) };
    case T.OctetString: case T.Opaque:
      return { type, value: bytes() };
    case T.Counter64: {
      // net-snmp hands Counter64 back as the BER content octets: minimal
      // big-endian, plus a 0x00 sign pad when the top bit is set — so 2^47
      // and up arrive as SEVEN bytes. Reproduced exactly, because that pad is
      // what the agent's toNumber once read wrong.
      let n = BigInt(raw || 0);
      const out = [];
      do { out.unshift(Number(n & 0xffn)); n >>= 8n; } while (n > 0n);
      if (out[0] & 0x80) out.unshift(0);
      return { type, value: Buffer.from(out) };
    }
    case T.OID: return { type, value: raw };
    case T.IpAddress: return { type, value: hex ? [...bytes()].join('.') : raw };
    case T.Null: return { type, value: null };
    default: throw new Error(`snmprec: unsupported tag ${tag}`);
  }
}

// Parses a recording into varbinds sorted in OID order.
function parseSnmprec(text) {
  const out = [];
  for (const line of String(text).split('\n')) {
    if (!line || line.startsWith('#')) continue;
    const first = line.indexOf('|');
    const second = line.indexOf('|', first + 1);
    if (first < 0 || second < 0) throw new Error(`snmprec: bad line ${line.slice(0, 60)}`);
    const oid = line.slice(0, first);
    const { type, value } = decodeValue(line.slice(first + 1, second), line.slice(second + 1));
    out.push({ oid, type, value });
  }
  return out.sort((a, b) => compareOid(a.oid, b.oid));
}

function loadSnmprec(file) {
  return parseSnmprec(fs.readFileSync(file, 'utf8'));
}

// A net-snmp Session over the recording. `calls` records every get/subtree so
// a test can say what the reader asked for.
function createSnmprecSession(varbinds) {
  const byOid = new Map(varbinds.map((vb) => [vb.oid, vb]));
  const calls = { get: [], subtree: [] };
  let closed = false;
  return {
    calls,
    get closed() { return closed; },
    get(oids, cb) {
      calls.get.push(oids.slice());
      // v2c semantics: a missing OID is a noSuchObject varbind, not an error.
      const out = oids.map((oid) => byOid.get(oid) || { oid, type: T.NoSuchObject, value: null });
      setImmediate(() => cb(null, out));
    },
    subtree(oid, maxRepetitions, feed, done) {
      calls.subtree.push(oid);
      const rows = varbinds.filter((vb) => vb.oid.startsWith(`${oid}.`));
      const step = Math.max(1, Number(maxRepetitions) || 1);
      let i = 0;
      const next = () => {
        if (i >= rows.length) return done(null);
        const batch = rows.slice(i, i + step);
        i += step;
        if (feed(batch) === true) return done(null);
        return setImmediate(next);
      };
      setImmediate(next);
    },
    close() { closed = true; },
  };
}

// A net-snmp-shaped module for readers that call openSession(device, { snmp }).
function createSnmprecModule(varbinds) {
  const sessions = [];
  return {
    Version1: 0,
    Version2c: 1,
    Version3: 3,
    sessions,
    createSession() {
      const s = createSnmprecSession(varbinds);
      sessions.push(s);
      return s;
    },
  };
}

module.exports = {
  parseSnmprec, loadSnmprec, createSnmprecSession, createSnmprecModule, compareOid, TYPES: T,
};
