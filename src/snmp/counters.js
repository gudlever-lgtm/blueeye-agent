'use strict';

const { IF_MIB, ETHERLIKE, SYSTEM, DUPLEX_STATUS } = require('./oids');
const {
  openSession, closeSession, walkColumn, getScalars, toNumber,
} = require('./session');

// Reads one snapshot of the interface counters on a switch.
//
// THIS IS A SNAPSHOT, NOT A RATE. snmpMonitor.js — the 1:1 traffic source —
// reads twice `intervalMs` apart and sends rates; the raw counters never leave
// the host. That works when the agent is measuring ITSELF at a cadence it
// controls, and it is the wrong shape here for two reasons:
//
//   * ONE READ PER CYCLE, NOT TWO. Twenty switches at forty columns each is
//     already a lot of walking; doing it twice per cycle to compute a delta the
//     server can compute from consecutive snapshots doubles the load on
//     production switches for nothing.
//   * THE RAW COUNTER IS EVIDENCE. Without it a rate can never be recomputed, a
//     counter reset can never be recognised after the fact, and a missing cycle
//     cannot be told apart from a cycle that measured zero. The server stores
//     both (migration 109) and works the delta out, because the server is the
//     one that knows what the previous reading was.
//
// sysUpTime rides along on every read. A device that rebooted between two polls
// has counters that restarted at zero, and subtracting across that boundary
// produces a number that looks like a measurement and is not one.

// The 64-bit counters, preferred everywhere they exist. A 32-bit octet counter
// wraps in ~34 seconds on a saturated gigabit port — faster than any polling
// interval worth having — so on those devices a delta is a guess, and this
// module says so rather than producing one.
const HC_COLUMNS = {
  inOctets: IF_MIB.ifHCInOctets,
  outOctets: IF_MIB.ifHCOutOctets,
  inUcastPkts: IF_MIB.ifHCInUcastPkts,
  outUcastPkts: IF_MIB.ifHCOutUcastPkts,
  inMulticastPkts: IF_MIB.ifHCInMulticastPkts,
  inBroadcastPkts: IF_MIB.ifHCInBroadcastPkts,
  outMulticastPkts: IF_MIB.ifHCOutMulticastPkts,
  outBroadcastPkts: IF_MIB.ifHCOutBroadcastPkts,
};

// The narrow fallbacks, for gear with no ifXTable at all.
const NARROW_COLUMNS = {
  inOctets: IF_MIB.ifInOctets,
  outOctets: IF_MIB.ifOutOctets,
  inMulticastPkts: IF_MIB.ifInMulticastPkts,
  inBroadcastPkts: IF_MIB.ifInBroadcastPkts,
  outMulticastPkts: IF_MIB.ifOutMulticastPkts,
  outBroadcastPkts: IF_MIB.ifOutBroadcastPkts,
};

// Columns with no high-capacity counterpart. An error counter that needs 64
// bits is a fault nobody will miss.
const ERROR_COLUMNS = {
  inErrors: IF_MIB.ifInErrors,
  outErrors: IF_MIB.ifOutErrors,
  inDiscards: IF_MIB.ifInDiscards,
  outDiscards: IF_MIB.ifOutDiscards,
};

// EtherLike-MIB: the two counters that NAME a physical fault rather than
// describing congestion. Optional on the device and treated as such — absent is
// null, never zero, because "zero FCS errors" is what rules out a bad cable and
// a device that cannot count them has ruled out nothing.
const ETHER_COLUMNS = {
  fcsErrors: ETHERLIKE.dot3StatsFCSErrors,
  alignmentErrors: ETHERLIKE.dot3StatsAlignmentErrors,
  lateCollisions: ETHERLIKE.dot3StatsLateCollisions,
  carrierSenseErrors: ETHERLIKE.dot3StatsCarrierSenseErrors,
};

// How many interfaces one device may report per cycle. A chassis with a
// thousand ports is real; a walk that runs away is a way to become the outage.
const MAX_INTERFACES = 1024;

// Turns { [ifIndex]: rawValue } into a number, keeping ABSENT distinct from
// zero: a key the walk never returned stays undefined, and only a key the
// device actually answered becomes a number.
function pick(column, idx) {
  if (!column || !Object.prototype.hasOwnProperty.call(column, idx)) return null;
  return toNumber(column[idx]);
}

// Reads every counter column on one device. Returns
// { sysUpTimeTicks, readAt, interfaces: [{ ifIndex, ...counters }], hc }.
//
// `hc` says whether the 64-bit counters were available. It travels to the
// server because it decides whether a decreasing octet counter can be treated
// as a wrap at all — on a 32-bit counter at gigabit speed it cannot.
async function defaultReadCounters(device, { snmp = null, maxInterfaces = MAX_INTERFACES } = {}) {
  const session = openSession(device, { snmp });
  try {
    // The device clock first, in one GET. Every delta the server computes from
    // this snapshot is only valid if the device did not restart since the last
    // one, and this is the field that says.
    const system = await getScalars(session, [SYSTEM.sysUpTime]).catch(() => ({}));
    const sysUpTimeTicks = toNumber(system[SYSTEM.sysUpTime]);

    // Optional columns never fail the read: a device without EtherLike-MIB must
    // still report its octets, and a single timed-out walk must not discard the
    // other thirty-nine.
    const safe = (oid) => walkColumn(session, oid).catch(() => ({}));

    const hcNames = Object.keys(HC_COLUMNS);
    const hcWalks = await Promise.all(hcNames.map((k) => safe(HC_COLUMNS[k])));
    const hc = Object.fromEntries(hcNames.map((k, i) => [k, hcWalks[i]]));

    // A device with no ifXTable answers nothing at all for the HC columns. Only
    // then are the narrow ones read — on a device that HAS both, reading both
    // would double the walk to produce the same numbers less reliably.
    const haveHc = Object.keys(hc.inOctets || {}).length > 0;
    let narrow = {};
    if (!haveHc) {
      const nNames = Object.keys(NARROW_COLUMNS);
      const nWalks = await Promise.all(nNames.map((k) => safe(NARROW_COLUMNS[k])));
      narrow = Object.fromEntries(nNames.map((k, i) => [k, nWalks[i]]));
    }

    const errNames = Object.keys(ERROR_COLUMNS);
    const errWalks = await Promise.all(errNames.map((k) => safe(ERROR_COLUMNS[k])));
    const errs = Object.fromEntries(errNames.map((k, i) => [k, errWalks[i]]));

    const ethNames = Object.keys(ETHER_COLUMNS);
    const ethWalks = await Promise.all(ethNames.map((k) => safe(ETHER_COLUMNS[k])));
    const eth = Object.fromEntries(ethNames.map((k, i) => [k, ethWalks[i]]));

    const [names, duplex] = await Promise.all([
      safe(IF_MIB.ifName),
      safe(ETHERLIKE.dot3StatsDuplexStatus),
    ]);

    const octets = haveHc ? hc : narrow;
    const indexes = [...new Set([
      ...Object.keys(octets.inOctets || {}),
      ...Object.keys(errs.inErrors || {}),
    ])].map(Number).filter((n) => Number.isInteger(n) && n > 0).sort((a, b) => a - b);

    const interfaces = [];
    for (const idx of indexes.slice(0, maxInterfaces)) {
      const source = haveHc ? hc : narrow;
      interfaces.push({
        ifIndex: idx,
        // The name is carried so the server can resolve the sample to the port
        // ROW rather than to an ifIndex, which is not an identity (mig. 108).
        ifName: names[idx] == null ? null : String(names[idx]).replace(/\0+$/, '').trim() || null,
        inOctets: pick(source.inOctets, idx),
        outOctets: pick(source.outOctets, idx),
        inUcastPkts: pick(source.inUcastPkts, idx),
        outUcastPkts: pick(source.outUcastPkts, idx),
        inMulticastPkts: pick(source.inMulticastPkts, idx),
        inBroadcastPkts: pick(source.inBroadcastPkts, idx),
        outMulticastPkts: pick(source.outMulticastPkts, idx),
        outBroadcastPkts: pick(source.outBroadcastPkts, idx),
        inErrors: pick(errs.inErrors, idx),
        outErrors: pick(errs.outErrors, idx),
        inDiscards: pick(errs.inDiscards, idx),
        outDiscards: pick(errs.outDiscards, idx),
        fcsErrors: pick(eth.fcsErrors, idx),
        alignmentErrors: pick(eth.alignmentErrors, idx),
        lateCollisions: pick(eth.lateCollisions, idx),
        carrierSenseErrors: pick(eth.carrierSenseErrors, idx),
        duplex: DUPLEX_STATUS[pick(duplex, idx)] || null,
      });
    }

    return {
      sysUpTimeTicks,
      hc: haveHc,
      interfaces,
      truncated: Math.max(indexes.length - interfaces.length, 0),
    };
  } finally {
    closeSession(session);
  }
}

// Polls one device's counters. Mirrors pollSnmpTopology's contract — a device
// in, plain rows out, the reader injectable — so both are testable without a
// switch and without the optional dependency.
async function pollSnmpCounters({ device, readCounters = defaultReadCounters, now = () => new Date() } = {}) {
  if (!device || typeof device.host !== 'string' || !device.host) {
    const err = new Error('SNMP counter poll needs a device with a host.');
    err.code = 'SNMP_BAD_TARGET';
    throw err;
  }
  const readAt = now();
  const out = await readCounters({
    host: device.host, port: device.port, version: device.version,
    community: device.community, v3: device.v3,
  });
  return {
    deviceId: device.deviceId,
    // The AGENT's clock when the read happened. The server pairs it with the
    // previous reading's to get the elapsed real time, which is what the
    // device's own uptime is checked against.
    readAt: readAt instanceof Date ? readAt.toISOString() : new Date(readAt).toISOString(),
    sysUpTimeTicks: out.sysUpTimeTicks ?? null,
    hc: out.hc !== false,
    interfaces: out.interfaces || [],
    truncated: out.truncated || 0,
  };
}

module.exports = {
  pollSnmpCounters,
  defaultReadCounters,
  HC_COLUMNS,
  NARROW_COLUMNS,
  ERROR_COLUMNS,
  ETHER_COLUMNS,
  MAX_INTERFACES,
};
