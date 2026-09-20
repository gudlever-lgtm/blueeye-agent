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
const { IF_MIB, ETHERLIKE, IF_OPER_STATUS } = require('./snmp/oids');
const { openSession, closeSession, walkColumn, toNumber } = require('./snmp/session');

// The columns this sampler walks. High-capacity octets plus the health columns
// a network technician troubleshoots with. The numbers live in
// src/snmp/oids.js, where the RFC that defines each one is named.
const OID = {
  ifName: IF_MIB.ifName,
  ifHCInOctets: IF_MIB.ifHCInOctets,
  ifHCOutOctets: IF_MIB.ifHCOutOctets,
  ifHighSpeed: IF_MIB.ifHighSpeed,
  ifOperStatus: IF_MIB.ifOperStatus,
  ifInDiscards: IF_MIB.ifInDiscards,
  ifInErrors: IF_MIB.ifInErrors,
  ifOutDiscards: IF_MIB.ifOutDiscards,
  ifOutErrors: IF_MIB.ifOutErrors,
  dot3StatsLateCollisions: ETHERLIKE.dot3StatsLateCollisions,
};

const OPER_STATUS = IF_OPER_STATUS;

// Same per-interface cap as the /proc sampler, for the same reason: a big
// chassis (or a misconfigured walk) must not push one result over the server's
// 64 KiB per-result limit and lose the whole report.
const { MAX_INTERFACES } = require('./trafficMonitor');

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// The shared coercion returns NULL for a value the device did not answer with,
// which is the distinction the lateCollisions column depends on. Where this
// file wants a counter it treats a missing one as zero explicitly, at the call
// site, so the two cases stay visibly different.
const num = (v) => { const n = toNumber(v); return n == null ? 0 : n; };


// Default reader: one snapshot of name + in/out octets per interface, via net-snmp.
async function defaultReadCounters(snmp) {
  const session = openSession(snmp);
  try {
    // Core columns are required (no traffic sample without name + octets). The
    // health columns are best-effort: a device that doesn't implement one — or a
    // single timed-out walk — must NOT discard the whole sample.
    const safe = (oid) => walkColumn(session, oid).catch(() => ({}));
    const [names, rx, tx, inErr, outErr, inDisc, outDisc, oper, speed, lateColl] = await Promise.all([
      walkColumn(session, OID.ifName),
      walkColumn(session, OID.ifHCInOctets),
      walkColumn(session, OID.ifHCOutOctets),
      safe(OID.ifInErrors),
      safe(OID.ifOutErrors),
      safe(OID.ifInDiscards),
      safe(OID.ifOutDiscards),
      safe(OID.ifOperStatus),
      safe(OID.ifHighSpeed),
      safe(OID.dot3StatsLateCollisions),
    ]);
    const result = {};
    for (const idx of Object.keys(rx)) {
      const sp = num(speed[idx]);
      result[idx] = {
        name: names[idx] != null ? String(names[idx]) : `if${idx}`,
        rxBytes: num(rx[idx]),
        txBytes: num(tx[idx]),
        rxErrors: num(inErr[idx]),
        txErrors: num(outErr[idx]),
        rxDrop: num(inDisc[idx]),
        txDrop: num(outDisc[idx]),
        operStatus: OPER_STATUS[num(oper[idx])] || null,
        speedMbps: sp > 0 ? sp : null,
        // NULL when the device did not return the column, 0 when it did and the
        // count is zero. The difference is the whole value of this counter:
        // EtherLike-MIB is optional and plenty of devices omit it, and
        // `num(undefined)` is 0 — so collapsing the two would make a switch
        // that cannot report late collisions look exactly like a switch with a
        // clean link, and "zero late collisions" is what RULES OUT a duplex
        // mismatch. Absent is not zero.
        lateCollisions: Object.prototype.hasOwnProperty.call(lateColl, idx) ? num(lateColl[idx]) : null,
      };
    }
    return result;
  } finally {
    closeSession(session);
  }
}

// Samples SNMP interface traffic. Returns the same shape as the /proc sampler.
async function sampleSnmp({
  snmp,
  intervalMs = 1000,
  readCounters = defaultReadCounters,
  sleepFn = sleep,
  now = () => Date.now(),
  maxInterfaces = MAX_INTERFACES,
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
  // The same subtraction for a counter that may be ABSENT. Either sample missing
  // it means this interval measured nothing, which is not the same as measuring
  // none — see the note on lateCollisions in defaultReadCounters.
  const nullableDelta = (a, b, k) => (
    typeof a[k] === 'number' && typeof b[k] === 'number' ? Math.max(a[k] - b[k], 0) : null
  );

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
      lateCollisions: nullableDelta(second[idx], first[idx], 'lateCollisions'),
    });
  }

  // Cap after totals (omitted ports still count there); keep the busiest ports.
  let interfacesOmitted = 0;
  if (interfaces.length > maxInterfaces) {
    interfaces.sort((a, b) => (b.rxBytes + b.txBytes) - (a.rxBytes + a.txBytes));
    interfacesOmitted = interfaces.length - maxInterfaces;
    interfaces.length = maxInterfaces;
  }

  return {
    source: 'snmp',
    intervalMs,
    elapsedSec: Math.round(elapsedSec * 1000) / 1000,
    interfaces,
    ...(interfacesOmitted ? { interfacesOmitted } : {}),
    totals: {
      ...totals,
      rxBytesPerSec: Math.round(totals.rxBytes / elapsedSec),
      txBytesPerSec: Math.round(totals.txBytes / elapsedSec),
    },
  };
}

module.exports = { sampleSnmp, toNumber, OID };
