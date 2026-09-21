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

// Opens a session to one device — v1, v2c or v3.
//
// THE SERVER DECIDES WHICH. The agent receives one resolved credential per
// device in `snmpTargets` and never tries alternatives: trying credentials in
// order against an address is credential spraying, it locks v3 accounts, and on
// v2c a wrong community usually just times out.
//
// NO CREDENTIAL IS NOT 'public'. The server sends a target with no community
// when the device has none it may use — its site has none configured, or this
// agent is not assigned the one it has. Defaulting to 'public' there would walk
// a production switch with a guessed community string, which is a scan, and it
// would do it under a name the customer never configured. So it is refused
// here, once, at the only place a session is opened.
//
// v3's SECURITY LEVEL is derived from which keys are present rather than sent
// as a field, for the same reason the server derives it: a stated level can
// disagree with the keys, and the keys are what actually happens on the wire.
function openSession(device, { snmp = null, timeoutMs = 5000, retries = 1 } = {}) {
  const net = snmp || loadNetSnmp();
  const options = { port: device.port || 161, timeout: timeoutMs, retries };

  const v3 = device.v3 && device.v3.user ? device.v3 : null;
  if (v3 || String(device.version) === '3') {
    if (!v3 || !v3.user) {
      const err = new Error('SNMPv3 needs a user; none was supplied for this device.');
      err.code = 'SNMP_BAD_CREDENTIAL';
      throw err;
    }
    const hasAuth = !!(v3.authKey && v3.authProto);
    const hasPriv = hasAuth && !!(v3.privKey && v3.privProto);
    options.version = net.Version3;
    if (v3.context) options.context = v3.context;
    const user = {
      name: v3.user,
      level: hasPriv ? net.SecurityLevel.authPriv
        : (hasAuth ? net.SecurityLevel.authNoPriv : net.SecurityLevel.noAuthNoPriv),
    };
    // A protocol NAME the library does not know indexes to `undefined`, and an
    // undefined protocol on an authPriv user is a session that fails somewhere
    // inside net-snmp with a message nobody can act on. The server's ENUM and
    // these names agree today; the day they stop agreeing — a widened ENUM and
    // an agent in the field that has not updated — this says which name it was.
    const protocol = (table, name, what) => {
      const value = table[name];
      if (value === undefined) {
        const err = new Error(`SNMPv3 ${what} protocol "${name}" is not one this agent knows.`);
        err.code = 'SNMP_BAD_CREDENTIAL';
        throw err;
      }
      return value;
    };
    if (hasAuth) {
      user.authProtocol = protocol(net.AuthProtocols, v3.authProto, 'auth');
      user.authKey = v3.authKey;
    }
    if (hasPriv) {
      user.privProtocol = protocol(net.PrivProtocols, v3.privProto, 'priv');
      user.privKey = v3.privKey;
    }
    return net.createV3Session(device.host, user, options);
  }

  if (!device.community) {
    const err = new Error(
      `No SNMP community is assigned for ${device.host}. The server resolves one per device`
      + ' — check that the site has a community and that this agent is assigned it.',
    );
    err.code = 'SNMP_NO_CREDENTIAL';
    throw err;
  }
  options.version = String(device.version) === '1' ? net.Version1 : net.Version2c;
  return net.createSession(device.host, device.community, options);
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
