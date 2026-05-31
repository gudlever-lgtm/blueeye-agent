'use strict';

// SNMP traffic sampler. Polls a device's IF-MIB high-capacity octet counters
// twice, `intervalMs` apart, and returns the SAME shape as the /proc sampler so
// the rest of the agent/server/dashboard treat both identically.
//
// The low-level counter read is injectable (`readCounters`) so tests don't need
// the optional `net-snmp` dependency or a real device. The default reader lazily
// requires `net-snmp`.

// IF-MIB (high-capacity) columns, by ifIndex.
const OID = {
  ifName: '1.3.6.1.2.1.31.1.1.1.1',
  ifHCInOctets: '1.3.6.1.2.1.31.1.1.1.6',
  ifHCOutOctets: '1.3.6.1.2.1.31.1.1.1.10',
};

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Coerces an SNMP Counter64 value (number or Buffer) to a JS number.
function toNumber(value) {
  if (typeof value === 'number') return value;
  if (Buffer.isBuffer(value)) {
    try {
      return Number(value.readBigUInt64BE(value.length - 8));
    } catch {
      return Number(value.toString('hex') ? parseInt(value.toString('hex'), 16) : 0);
    }
  }
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

// Walks one IF-MIB column and returns { [ifIndex]: value }. The ifIndex is the
// last component of each returned OID.
function walkColumn(session, baseOid, snmp) {
  return new Promise((resolve, reject) => {
    const out = {};
    session.subtree(
      baseOid,
      (varbinds) => {
        for (const vb of varbinds) {
          if (vb.type === undefined) continue; // error varbind
          const idx = vb.oid.slice(baseOid.length + 1);
          out[idx] = vb.value;
        }
      },
      (err) => (err ? reject(err) : resolve(out))
    );
  });
}

// Default reader: one snapshot of name + in/out octets per interface, via net-snmp.
async function defaultReadCounters(snmp) {
  let net;
  try {
    net = require('net-snmp');
  } catch {
    const err = new Error('SNMP source requested but the optional "net-snmp" dependency is not installed.');
    err.code = 'SNMP_UNAVAILABLE';
    throw err;
  }
  const version = snmp.version === '1' ? net.Version1 : net.Version2c;
  const session = net.createSession(snmp.host, snmp.community || 'public', {
    port: snmp.port || 161,
    version,
  });
  try {
    const [names, rx, tx] = await Promise.all([
      walkColumn(session, OID.ifName, snmp),
      walkColumn(session, OID.ifHCInOctets, snmp),
      walkColumn(session, OID.ifHCOutOctets, snmp),
    ]);
    const result = {};
    for (const idx of Object.keys(rx)) {
      result[idx] = {
        name: names[idx] != null ? String(names[idx]) : `if${idx}`,
        rxBytes: toNumber(rx[idx]),
        txBytes: toNumber(tx[idx]),
      };
    }
    return result;
  } finally {
    try {
      session.close();
    } catch {
      /* ignore */
    }
  }
}

// Samples SNMP interface traffic. Returns the same shape as the /proc sampler.
async function sampleSnmp({
  snmp,
  intervalMs = 1000,
  readCounters = defaultReadCounters,
  sleepFn = sleep,
  now = () => Date.now(),
} = {}) {
  const t0 = now();
  const first = await readCounters(snmp);
  await sleepFn(intervalMs);
  const t1 = now();
  const second = await readCounters(snmp);

  const elapsedSec = Math.max((t1 - t0) / 1000, 0.001);
  const interfaces = [];
  const totals = { rxBytes: 0, txBytes: 0, rxPackets: 0, txPackets: 0 };

  for (const idx of Object.keys(second)) {
    if (!first[idx]) continue;
    const rxBytes = Math.max(second[idx].rxBytes - first[idx].rxBytes, 0);
    const txBytes = Math.max(second[idx].txBytes - first[idx].txBytes, 0);
    totals.rxBytes += rxBytes;
    totals.txBytes += txBytes;
    interfaces.push({
      iface: second[idx].name,
      rxBytes,
      txBytes,
      rxPackets: 0,
      txPackets: 0,
      rxBytesPerSec: Math.round(rxBytes / elapsedSec),
      txBytesPerSec: Math.round(txBytes / elapsedSec),
    });
  }

  return {
    source: 'snmp',
    intervalMs,
    elapsedSec: Math.round(elapsedSec * 1000) / 1000,
    interfaces,
    totals: {
      ...totals,
      rxBytesPerSec: Math.round(totals.rxBytes / elapsedSec),
      txBytesPerSec: Math.round(totals.txBytes / elapsedSec),
    },
  };
}

module.exports = { sampleSnmp, toNumber, OID };
