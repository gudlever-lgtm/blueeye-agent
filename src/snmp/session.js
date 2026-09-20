'use strict';

// The SNMP client, in one place: open a session, walk a column, read a scalar,
// close it.
//
// WHY ONE FILE. snmpMonitor.js and snmpTopology.js each carried their own
// `walkColumn`, their own `require('net-snmp')` guard, their own session
// options and their own value coercion — four copies of the same twenty lines,
// diverging slowly. The counter poller in the next stage would have been a
// fifth.
//
// WHAT IS DELIBERATELY NOT HERE: the OIDs (src/snmp/oids.js) and every decision
// about what a value MEANS. This module moves bytes. `buildTopology()` and the
// counter reader stay pure and testable without a device, which is the property
// that has caught the real bugs in this area — the LLDP subtype ambiguity, the
// bridge-port-is-not-ifIndex join, the absent-is-not-zero counter.
//
// Everything below takes an injected `snmp` module so the tests never need the
// optional dependency, and the default lazily requires it so a host without it
// fails at the call rather than at startup.

// The optional dependency, loaded on first use. A host without it gets a coded
// error the callers already know how to report (capabilities.unavailable.snmp).
function loadNetSnmp(what = 'SNMP') {
  try {
    // eslint-disable-next-line global-require
    return require('net-snmp');
  } catch {
    const err = new Error(`${what} requested but the "net-snmp" dependency is not installed.`);
    err.code = 'SNMP_UNAVAILABLE';
    throw err;
  }
}

// Coerces an SNMP value to a number. Counter64 arrives as a Buffer; a
// TimeTicks or Gauge32 as a JS number. Returns null for anything that is not a
// number at all, so a caller can tell "the device did not answer" from "the
// device answered zero" — the distinction the whole counter path rests on.
function toNumber(value) {
  // Explicit, because Number(null) is 0 in JavaScript and that single
  // conversion would turn "the device did not answer" into "the device
  // answered zero" — the exact confusion this function exists to prevent.
  if (value === null || value === undefined) return null;
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (Buffer.isBuffer(value)) {
    if (!value.length) return null;
    try {
      // Counter64 is eight bytes big-endian. Beyond 2^53 a JS number loses
      // integer precision, but an octet counter would have to run for months at
      // 100 Gbit/s to get there, and the delta is what is stored.
      if (value.length >= 8) return Number(value.readBigUInt64BE(value.length - 8));
      return value.readUIntBE(0, Math.min(value.length, 6));
    } catch {
      const hex = value.toString('hex');
      return hex ? parseInt(hex, 16) : null;
    }
  }
  // Number('') and Number('   ') are both 0, the same trap as Number(null).
  if (typeof value === 'string' && value.trim() === '') return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

// Coerces to a trimmed string, or null. Trailing NULs are how a switch pads a
// fixed-width OCTET STRING, and they must not become part of a port name.
function toText(value) {
  if (value == null) return null;
  if (Buffer.isBuffer(value)) return value.toString('utf8').replace(/\0+$/, '').trim() || null;
  const s = String(value).trim();
  return s || null;
}

// A 6-byte OCTET STRING rendered as a MAC. Anything else is not a MAC and
// becomes null rather than a plausible-looking string of the wrong bytes.
function toMac(value) {
  if (!Buffer.isBuffer(value) || value.length !== 6) return null;
  return [...value].map((b) => b.toString(16).padStart(2, '0')).join(':');
}

// Opens a session to one device. v1/v2c today; `createV3Session` is what a v3
// credential would use, and the shape of this function is what keeps that a
// change in one place rather than three.
function openSession(device, { snmp = null, timeoutMs = 5000, retries = 1 } = {}) {
  const net = snmp || loadNetSnmp();
  const version = String(device.version) === '1' ? net.Version1 : net.Version2c;
  return net.createSession(device.host, device.community || 'public', {
    port: device.port || 161,
    version,
    timeout: timeoutMs,
    retries,
  });
}

// Walks one columnar OID and returns { [indexSuffix]: rawValue }, where the
// suffix is everything after the base OID — an ifIndex for IF-MIB, a
// "vlan.mac" for Q-BRIDGE, a "chassis.port.index" for LLDP. Left raw on
// purpose: each caller knows how to read its own index, and parsing it here
// would mean this module knowing all of them.
//
// `maxRepetitions` is what makes this a GETBULK walk on v2c rather than a
// round-trip per row. A 48-port switch's counter column is 48 rows; at the
// library default that is a dozen round-trips per column and forty columns per
// device. It is the single biggest lever on how long a poll takes.
function walkColumn(session, baseOid, { maxRepetitions = 25 } = {}) {
  return new Promise((resolve, reject) => {
    const out = {};
    session.subtree(
      baseOid,
      maxRepetitions,
      (varbinds) => {
        for (const vb of varbinds || []) {
          // An error varbind (noSuchInstance/noSuchObject/endOfMibView) carries
          // no usable value. Skipping it is what lets a device that implements
          // half a table still answer for the half it has.
          if (!vb || vb.type === undefined) continue;
          out[String(vb.oid).slice(baseOid.length + 1)] = vb.value;
        }
      },
      (err) => (err ? reject(err) : resolve(out)),
    );
  });
}

// Reads one or more scalar OIDs in a single GET. Returns { [oid]: rawValue },
// omitting anything the device did not answer for.
function getScalars(session, oids) {
  const list = Array.isArray(oids) ? oids : [oids];
  return new Promise((resolve, reject) => {
    session.get(list, (err, varbinds) => {
      if (err) return reject(err);
      const out = {};
      for (const vb of varbinds || []) {
        if (!vb || vb.type === undefined) continue;
        out[String(vb.oid)] = vb.value;
      }
      return resolve(out);
    });
  });
}

// Closes a session without ever throwing. A close that fails must not turn a
// successful poll into a failed one.
function closeSession(session) {
  try {
    if (session && typeof session.close === 'function') session.close();
  } catch { /* the measurement already succeeded */ }
}

module.exports = {
  loadNetSnmp,
  openSession,
  closeSession,
  walkColumn,
  getScalars,
  toNumber,
  toText,
  toMac,
};
