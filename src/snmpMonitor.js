'use strict';

// SNMP traffic sampler. Polls a device's IF-MIB high-capacity octet counters
// twice, `intervalMs` apart, and returns the SAME shape as the /proc sampler so
// the rest of the agent/server/dashboard treat both identically.
//
// The low-level counter read is injectable (`readCounters`) so tests don't need
// the optional `net-snmp` dependency or a real device. The default reader lazily
// requires `net-snmp`.

// IF-MIB columns, by ifIndex. High-capacity octets + the health columns
// (errors/discards/oper-status/speed) network/firewall techs troubleshoot with.
const OID = {
  ifName: '1.3.6.1.2.1.31.1.1.1.1',
  ifHCInOctets: '1.3.6.1.2.1.31.1.1.1.6',
  ifHCOutOctets: '1.3.6.1.2.1.31.1.1.1.10',
  ifHighSpeed: '1.3.6.1.2.1.31.1.1.1.15', // Mbps
  ifOperStatus: '1.3.6.1.2.1.2.2.1.8', // 1=up, 2=down, ...
  ifInDiscards: '1.3.6.1.2.1.2.2.1.13',
  ifInErrors: '1.3.6.1.2.1.2.2.1.14',
  ifOutDiscards: '1.3.6.1.2.1.2.2.1.19',
  ifOutErrors: '1.3.6.1.2.1.2.2.1.20',
};

const OPER_STATUS = { 1: 'up', 2: 'down', 3: 'testing', 5: 'dormant', 6: 'notPresent', 7: 'lowerLayerDown' };

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Coerces an SNMP Counter64 value (number or Buffer) to a JS number.
function toNumber(value) {
  if (typeof value === 'number') return value;
  if (Buffer.isBuffer(value)) {
    try {
      return Number(value.readBigUInt64BE(value.length - 8));
    } catch {
      const hex = value.toString('hex');
      return hex ? parseInt(hex, 16) : 0;
    }
  }
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

// Walks one IF-MIB column and returns { [ifIndex]: value }. The ifIndex is the
// last component of each returned OID.
function walkColumn(session, baseOid) {
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
    // Core columns are required (no traffic sample without name + octets). The
    // health columns are best-effort: a device that doesn't implement one — or a
    // single timed-out walk — must NOT discard the whole sample.
    const safe = (oid) => walkColumn(session, oid).catch(() => ({}));
    const [names, rx, tx, inErr, outErr, inDisc, outDisc, oper, speed] = await Promise.all([
      walkColumn(session, OID.ifName),
      walkColumn(session, OID.ifHCInOctets),
      walkColumn(session, OID.ifHCOutOctets),
      safe(OID.ifInErrors),
      safe(OID.ifOutErrors),
      safe(OID.ifInDiscards),
      safe(OID.ifOutDiscards),
      safe(OID.ifOperStatus),
      safe(OID.ifHighSpeed),
    ]);
    const result = {};
    for (const idx of Object.keys(rx)) {
      const sp = toNumber(speed[idx]);
      result[idx] = {
        name: names[idx] != null ? String(names[idx]) : `if${idx}`,
        rxBytes: toNumber(rx[idx]),
        txBytes: toNumber(tx[idx]),
        rxErrors: toNumber(inErr[idx]),
        txErrors: toNumber(outErr[idx]),
        rxDrop: toNumber(inDisc[idx]),
        txDrop: toNumber(outDisc[idx]),
        operStatus: OPER_STATUS[toNumber(oper[idx])] || null,
        speedMbps: sp > 0 ? sp : null,
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
  const totals = { rxBytes: 0, txBytes: 0, rxPackets: 0, txPackets: 0, rxErrors: 0, txErrors: 0, rxDrop: 0, txDrop: 0 };
  const delta = (a, b, k) => Math.max((a[k] || 0) - (b[k] || 0), 0);

  for (const idx of Object.keys(second)) {
    if (!first[idx]) continue;
    const rxBytes = delta(second[idx], first[idx], 'rxBytes');
    const txBytes = delta(second[idx], first[idx], 'txBytes');
    const rxErrors = delta(second[idx], first[idx], 'rxErrors');
    const txErrors = delta(second[idx], first[idx], 'txErrors');
    const rxDrop = delta(second[idx], first[idx], 'rxDrop');
    const txDrop = delta(second[idx], first[idx], 'txDrop');
    totals.rxBytes += rxBytes; totals.txBytes += txBytes;
    totals.rxErrors += rxErrors; totals.txErrors += txErrors;
    totals.rxDrop += rxDrop; totals.txDrop += txDrop;
    interfaces.push({
      iface: second[idx].name,
      rxBytes,
      txBytes,
      rxPackets: 0,
      txPackets: 0,
      rxBytesPerSec: Math.round(rxBytes / elapsedSec),
      txBytesPerSec: Math.round(txBytes / elapsedSec),
      rxErrors,
      txErrors,
      rxDrop,
      txDrop,
      operStatus: second[idx].operStatus ?? null,
      speedMbps: second[idx].speedMbps ?? null,
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
