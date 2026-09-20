'use strict';

// SNMP topology poller: the forwarding table, the neighbour table and the VLAN
// names, read from a switch and reported to the server.
//
// This is the piece that lets BlueEyes answer "which port is this MAC on".
// snmpMonitor.js already polls IF-MIB counters from a remote device — the SNMP
// client, the optional `net-snmp` dependency and the injectable-reader shape all
// exist. This module reads the tables that name PLACES rather than rates, and it
// deliberately mirrors that file's contract (a `readTables` function in, plain
// rows out) so both are testable without a device and without the dependency.
//
// THE ONE THING THAT MATTERS: BRIDGE PORT IS NOT ifIndex.
//
// dot1qTpFdbPort and dot1dTpFdbPort return a BRIDGE PORT NUMBER — an index into
// dot1dBasePortTable, not the ifIndex that names an interface. On many switches
// the two coincide for the first handful of ports and then diverge, which is
// worse than never matching: it gives an answer that is right in the lab and
// wrong in the building. So dot1dBasePortIfIndex is walked and the mapping is
// resolved HERE, before anything is reported, and both numbers travel: the
// bridge port as the device said it, the ifIndex and ifName as resolved. When
// the mapping is missing the resolved fields are null and the row still says
// where it came from, rather than inventing a port.

const { IF_MIB, BRIDGE, Q_BRIDGE, LLDP, SYSTEM: SYS } = require('./snmp/oids');
const {
  openSession, closeSession, walkColumn, getScalars, toNumber, toText, toMac,
} = require('./snmp/session');

// The columns this module walks, assembled from the shared OID map. The names
// are local so the rest of the file reads as it did; the numbers live in one
// place now (src/snmp/oids.js) rather than being written out here and again in
// snmpMonitor.js.
const OID = {
  ifName: IF_MIB.ifName,
  ifAlias: IF_MIB.ifAlias,
  ifDescr: IF_MIB.ifDescr,
  ifType: IF_MIB.ifType,
  ifPhysAddress: IF_MIB.ifPhysAddress,
  ifAdminStatus: IF_MIB.ifAdminStatus,
  ifOperStatus: IF_MIB.ifOperStatus,
  ifHighSpeed: IF_MIB.ifHighSpeed,
  dot1dBasePortIfIndex: BRIDGE.dot1dBasePortIfIndex,
  dot1dTpFdbPort: BRIDGE.dot1dTpFdbPort,
  dot1dTpFdbStatus: BRIDGE.dot1dTpFdbStatus,
  dot1qTpFdbPort: Q_BRIDGE.dot1qTpFdbPort,
  dot1qTpFdbStatus: Q_BRIDGE.dot1qTpFdbStatus,
  dot1qVlanStaticName: Q_BRIDGE.dot1qVlanStaticName,
  lldpRemChassisIdSubtype: LLDP.lldpRemChassisIdSubtype,
  lldpRemChassisId: LLDP.lldpRemChassisId,
  lldpRemPortIdSubtype: LLDP.lldpRemPortIdSubtype,
  lldpRemPortId: LLDP.lldpRemPortId,
  lldpRemPortDesc: LLDP.lldpRemPortDesc,
  lldpRemSysName: LLDP.lldpRemSysName,
  lldpLocPortIdSubtype: LLDP.lldpLocPortIdSubtype,
};

// dot1qTpFdbStatus / dot1dTpFdbStatus. `self` is the switch's own address and
// must never be reported as "a device is plugged in here"; `invalid` is an entry
// being aged out and is dropped.
const FDB_STATUS = { 1: 'other', 2: 'invalid', 3: 'learned', 4: 'self', 5: 'mgmt' };
const FDB_STATUS_BRIDGE = { 1: 'other', 2: 'invalid', 3: 'learned', 4: 'self', 5: 'mgmt' };

// A forwarding table on a big chassis runs to tens of thousands of rows. The
// server caps a report at 64 KiB, and a core switch's full table is of no
// diagnostic use anyway — the ports with one or two MACs are the ones that
// answer "where is this device", and those survive the cap.
const MAX_FDB_ENTRIES = 5000;
const MAX_NEIGHBOURS = 512;

// Formats six decimal OID components as a MAC. The FDB tables index by the
// address itself, so the MAC arrives as part of the OID rather than as a value.
function macFromOidParts(parts) {
  if (!Array.isArray(parts) || parts.length !== 6) return null;
  const bytes = parts.map((p) => Number(p));
  if (bytes.some((b) => !Number.isInteger(b) || b < 0 || b > 255)) return null;
  return bytes.map((b) => b.toString(16).padStart(2, '0')).join(':');
}

// Q-BRIDGE index is <vlan>.<6 MAC octets>; BRIDGE index is just the 6 octets.
function parseFdbIndex(index, { withVlan }) {
  const parts = String(index).split('.');
  if (withVlan) {
    if (parts.length !== 7) return null;
    const vlan = Number(parts[0]);
    if (!Number.isInteger(vlan) || vlan < 0 || vlan > 4095) return null;
    const mac = macFromOidParts(parts.slice(1));
    return mac ? { vlan, mac } : null;
  }
  const mac = macFromOidParts(parts);
  return mac ? { vlan: 0, mac } : null;
}

// An LLDP remote-table index is <timeMark>.<localPortNum>.<remoteIndex>; the
// middle component is the local port the neighbour is on.
function localPortFromLldpIndex(index) {
  const parts = String(index).split('.');
  if (parts.length !== 3) return null;
  const n = Number(parts[1]);
  return Number.isInteger(n) ? n : null;
}

// LLDP subtypes that mean "this OCTET STRING is a MAC address".
// lldpRemChassisIdSubtype: 4 = macAddress. lldpRemPortIdSubtype: 3 = macAddress.
const CHASSIS_SUBTYPE_MAC = 4;
const PORT_SUBTYPE_MAC = 3;

// An LLDP chassis/port id arrives as an OCTET STRING that may be text or raw
// bytes, and LENGTH CANNOT TELL THEM APART: "Gi0/24" is exactly six bytes, the
// same as a MAC. So the device's own subtype column decides, and the 6-byte
// heuristic is only the fallback for a device that did not report one — where
// all-printable bytes are read as text, because a port named "Gi0/24" is far
// more likely than a MAC whose every octet lands in the ASCII range.
function decodeLldpId(value, subtype) {
  if (value == null) return null;
  if (typeof value === 'string') return value.trim() || null;
  if (!Buffer.isBuffer(value)) return String(value);

  const asMac = () => Array.from(value).map((b) => b.toString(16).padStart(2, '0')).join(':');
  const text = value.toString('utf8');
  // eslint-disable-next-line no-control-regex
  const printable = /^[\x20-\x7e]+$/.test(text);

  if (subtype != null) {
    if (subtype === 'mac') return value.length === 6 ? asMac() : value.toString('hex');
    return printable ? (text.trim() || null) : value.toString('hex');
  }
  if (value.length === 6 && !printable) return asMac();
  if (printable) return text.trim() || null;
  return value.toString('hex');
}

// Local aliases for the shared coercions, so the call sites below read as they
// always have.
const toStr = toText;
const toNum = toNumber;

// ifAdminStatus / ifOperStatus, as IF-MIB numbers them. An unlisted value
// becomes null rather than a guess: an unknown status is not a status.
const IF_STATUS = { 1: 'up', 2: 'down', 3: 'testing', 4: 'unknown', 5: 'dormant', 6: 'notPresent', 7: 'lowerLayerDown' };
const ADMIN_STATUS = { 1: 'up', 2: 'down', 3: 'testing' };


// The default reader. Every column except the bridge-port map is best-effort:
// a device that does not implement Q-BRIDGE must still yield its BRIDGE-MIB
// table, and a device with no LLDP must still yield its forwarding table.
async function defaultReadTables(snmp, { collect = ['if', 'fdb', 'lldp', 'vlan'] } = {}) {
  const session = openSession(snmp);
  try {
    // sysUpTime FIRST, in one GET beside the device's own name. It is read on
    // every poll whatever else was asked for, because it is what says whether
    // the NEXT poll's counter delta is a measurement or an artefact of a
    // reboot — and reading it needs one round trip against a device we have
    // already opened a session to.
    const system = await getScalars(session, [SYS.sysUpTime, SYS.sysName, SYS.sysDescr])
      .catch(() => ({}));
    const safe = (oid) => walkColumn(session, oid).catch(() => ({}));
    const want = new Set(collect);

    const [
      ifName, ifAlias, ifDescr, ifType, ifPhysAddress, ifAdminStatus, ifOperStatus, ifHighSpeed,
      basePortIfIndex,
      qFdbPort, qFdbStatus, dFdbPort, dFdbStatus,
      vlanName,
      lldpChassis, lldpChassisSubtype, lldpPort, lldpPortSubtype, lldpPortDesc, lldpSysName,
    ] = await Promise.all([
      want.has('if') || want.has('fdb') ? safe(OID.ifName) : {},
      want.has('if') ? safe(OID.ifAlias) : {},
      // ifDescr is fetched whenever a name is wanted, because it is the
      // fallback when the device has no ifName at all.
      want.has('if') || want.has('fdb') ? safe(OID.ifDescr) : {},
      want.has('if') ? safe(OID.ifType) : {},
      want.has('if') ? safe(OID.ifPhysAddress) : {},
      want.has('if') ? safe(OID.ifAdminStatus) : {},
      want.has('if') ? safe(OID.ifOperStatus) : {},
      want.has('if') ? safe(OID.ifHighSpeed) : {},
      // NOT safe(): without the bridge-port map the forwarding table cannot be
      // resolved to an interface, and an unresolved answer is the one thing
      // this module must not produce silently. An empty result is handled by
      // the caller, which reports `fdb` as unsupported rather than guessing.
      want.has('fdb') ? safe(OID.dot1dBasePortIfIndex) : {},
      want.has('fdb') ? safe(OID.dot1qTpFdbPort) : {},
      want.has('fdb') ? safe(OID.dot1qTpFdbStatus) : {},
      want.has('fdb') ? safe(OID.dot1dTpFdbPort) : {},
      want.has('fdb') ? safe(OID.dot1dTpFdbStatus) : {},
      want.has('vlan') ? safe(OID.dot1qVlanStaticName) : {},
      want.has('lldp') ? safe(OID.lldpRemChassisId) : {},
      want.has('lldp') ? safe(OID.lldpRemChassisIdSubtype) : {},
      want.has('lldp') ? safe(OID.lldpRemPortId) : {},
      want.has('lldp') ? safe(OID.lldpRemPortIdSubtype) : {},
      want.has('lldp') ? safe(OID.lldpRemPortDesc) : {},
      want.has('lldp') ? safe(OID.lldpRemSysName) : {},
    ]);

    return {
      // Hundredths of a second since the device last re-initialised, and what
      // the device calls itself. Null when it did not answer — an unknown
      // uptime must never read as "just booted".
      sysUpTimeTicks: toNumber(system[SYS.sysUpTime]),
      sysName: toText(system[SYS.sysName]),
      sysDescr: toText(system[SYS.sysDescr]),
      ifName, ifAlias, ifDescr, ifType, ifPhysAddress, ifAdminStatus, ifOperStatus, ifHighSpeed,
      basePortIfIndex,
      qFdbPort, qFdbStatus, dFdbPort, dFdbStatus,
      vlanName,
      lldpChassis, lldpChassisSubtype, lldpPort, lldpPortSubtype, lldpPortDesc, lldpSysName,
    };
  } finally {
    closeSession(session);
  }
}

// Turns the raw walks into the rows the server stores. Pure — this is where
// every decision that could be got wrong lives, and it is tested against
// fixtures rather than a switch.
function buildTopology(tables, { maxFdb = MAX_FDB_ENTRIES, maxNeighbours = MAX_NEIGHBOURS } = {}) {
  const t = tables || {};

  // bridge port -> ifIndex -> name. The join the whole table rests on.
  const portToIfIndex = new Map();
  for (const [bridgePort, value] of Object.entries(t.basePortIfIndex || {})) {
    const bp = Number(bridgePort);
    const idx = toNum(value);
    if (Number.isInteger(bp) && Number.isInteger(idx) && idx > 0) portToIfIndex.set(bp, idx);
  }
  // ifIndex -> { name, source }. THE NAME IS THE PORT'S IDENTITY on the server
  // (migration 108), so where it came from has to travel with it:
  //
  //   ifName  — the switch's own short name, stable across a reboot and a
  //             module insertion. What we want.
  //   ifDescr — the fallback. Plenty of older gear implements no ifName at all,
  //             and ifDescr is less stable (some platforms rewrite it), so a
  //             row built from it is a weaker identity and says so.
  //   ifIndex — last resort, and the one case where the identity IS the
  //             volatile number. Marked, so nobody mistakes it for stable.
  //
  // Guessing silently would mean a switch quietly getting a new set of ports
  // after a firmware upgrade, with a year of counters stranded on the old ones.
  const ifNameByIndex = new Map();
  const ifNameSource = new Map();
  const indexes = new Set([
    ...Object.keys(t.ifName || {}),
    ...Object.keys(t.ifDescr || {}),
  ].map((k) => Number(k)).filter((n) => Number.isInteger(n) && n > 0));
  for (const idx of indexes) {
    const name = toStr(t.ifName ? t.ifName[idx] : null);
    const descr = toStr(t.ifDescr ? t.ifDescr[idx] : null);
    if (name) {
      ifNameByIndex.set(idx, name);
      ifNameSource.set(idx, 'ifName');
    } else if (descr) {
      ifNameByIndex.set(idx, descr);
      ifNameSource.set(idx, 'ifDescr');
    } else {
      ifNameByIndex.set(idx, `ifIndex.${idx}`);
      ifNameSource.set(idx, 'ifIndex');
    }
  }

  // The names that came off the DEVICE, with no fallback in them. The
  // forwarding table and the LLDP rows resolve through this one, never through
  // the map above: stage 02's rule is that a port the switch did not name is
  // reported as null rather than as a fabricated "port N", and `ifIndex.7` is
  // exactly such a fabrication. It is an acceptable identity for a row in the
  // port inventory, which is about THIS device; it is not an acceptable answer
  // to "which port is this MAC on", which sends somebody walking.
  const realNameByIndex = new Map();
  for (const [idx, src] of ifNameSource.entries()) {
    if (src !== 'ifIndex') realNameByIndex.set(idx, ifNameByIndex.get(idx));
  }

  // VLAN id -> name, for a UI that can say "VLAN 20 (Office)".
  const vlans = [];
  for (const [id, value] of Object.entries(t.vlanName || {})) {
    const vid = Number(id);
    const name = toStr(value);
    if (Number.isInteger(vid) && name) vlans.push({ vlan: vid, name });
  }

  // --- forwarding table ----------------------------------------------------
  //
  // Q-BRIDGE first. A device that answers both is read from the per-VLAN table
  // only: merging them would double every entry, since the same MAC appears in
  // both with the same bridge port.
  const rows = [];
  const seen = new Set();

  function collectFdb(portTable, statusTable, statusNames, withVlan) {
    for (const [index, portValue] of Object.entries(portTable || {})) {
      const parsed = parseFdbIndex(index, { withVlan });
      if (!parsed) continue;
      const bridgePort = toNum(portValue);
      // Port 0 means "the device knows this address but not where it is". It is
      // a real answer to a different question, and storing it as a port would
      // send somebody to a patch panel that does not exist.
      if (!Number.isInteger(bridgePort) || bridgePort <= 0) continue;

      const statusRaw = statusTable ? toNum(statusTable[index]) : null;
      const status = statusNames[statusRaw] || 'learned';
      // `self` is the switch's own MAC; `invalid` is an entry ageing out.
      if (status === 'self' || status === 'invalid') continue;

      const key = `${parsed.vlan}\u0000${parsed.mac}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const ifIndex = portToIfIndex.has(bridgePort) ? portToIfIndex.get(bridgePort) : null;
      rows.push({
        mac: parsed.mac,
        vlan: parsed.vlan,
        bridgePort,
        ifIndex,
        // Null rather than a fabricated "port N": see the note at the top.
        ifName: ifIndex != null ? (realNameByIndex.get(ifIndex) || null) : null,
        status,
      });
    }
  }

  const hasQBridge = Object.keys(t.qFdbPort || {}).length > 0;
  if (hasQBridge) {
    collectFdb(t.qFdbPort, t.qFdbStatus, FDB_STATUS, true);
  } else {
    collectFdb(t.dFdbPort, t.dFdbStatus, FDB_STATUS_BRIDGE, false);
  }

  // How many MACs are on each port. THE field that turns a hit into an answer:
  // one MAC is an end device and a patch panel to walk to; forty is an uplink
  // and one more hop to go. Counted over EVERYTHING seen, before the cap, so a
  // truncated report still says honestly that a port is crowded.
  const perPort = new Map();
  for (const r of rows) perPort.set(r.bridgePort, (perPort.get(r.bridgePort) || 0) + 1);
  for (const r of rows) r.portMacCount = perPort.get(r.bridgePort) || 1;

  // Keep the ports that answer the question. Sorting by port occupancy means a
  // core switch's 20 000-entry uplink does not push out the access ports, which
  // are the rows a technician is actually looking for.
  rows.sort((a, b) => a.portMacCount - b.portMacCount || a.bridgePort - b.bridgePort);
  const fdbTruncated = rows.length > maxFdb;
  const fdb = fdbTruncated ? rows.slice(0, maxFdb) : rows;

  // --- neighbours ----------------------------------------------------------
  const neighbours = [];
  for (const [index, chassisValue] of Object.entries(t.lldpChassis || {})) {
    const localPort = localPortFromLldpIndex(index);
    const chassisSubtype = toNum(t.lldpChassisSubtype ? t.lldpChassisSubtype[index] : null);
    const remoteChassisId = decodeLldpId(
      chassisValue,
      chassisSubtype == null ? null : (chassisSubtype === CHASSIS_SUBTYPE_MAC ? 'mac' : 'text'),
    );
    if (!remoteChassisId) continue;
    const ifIndex = localPort != null && portToIfIndex.has(localPort)
      ? portToIfIndex.get(localPort)
      // LLDP's local port number is usually the ifIndex already on devices that
      // do not implement the bridge-port table; fall back to it rather than
      // dropping an otherwise good neighbour.
      : localPort;
    neighbours.push({
      localPort,
      localIfIndex: ifIndex,
      localIfName: ifIndex != null ? (realNameByIndex.get(ifIndex) || null) : null,
      remoteChassisId,
      remotePortId: (function decodePort() {
        const st = toNum(t.lldpPortSubtype ? t.lldpPortSubtype[index] : null);
        return decodeLldpId(
          t.lldpPort ? t.lldpPort[index] : null,
          st == null ? null : (st === PORT_SUBTYPE_MAC ? 'mac' : 'text'),
        );
      }()),
      remotePortDesc: toStr(t.lldpPortDesc ? t.lldpPortDesc[index] : null),
      remoteSysName: toStr(t.lldpSysName ? t.lldpSysName[index] : null),
    });
    if (neighbours.length >= maxNeighbours) break;
  }

  // --- interfaces ----------------------------------------------------------
  const interfaces = [];
  for (const [idx, name] of ifNameByIndex.entries()) {
    const speed = toNum(t.ifHighSpeed ? t.ifHighSpeed[idx] : null);
    const type = toNum(t.ifType ? t.ifType[idx] : null);
    interfaces.push({
      ifIndex: idx,
      ifName: name,
      nameSource: ifNameSource.get(idx) || 'ifName',
      ifAlias: toStr(t.ifAlias ? t.ifAlias[idx] : null),
      ifDescr: toStr(t.ifDescr ? t.ifDescr[idx] : null),
      ifType: Number.isInteger(type) && type > 0 ? type : null,
      // ifHighSpeed is Mbit/s and reads 0 for a port whose speed the device
      // does not know. Null, not 0: "unknown" and "stalled" are different, and
      // a utilisation percentage computed against 0 is not a number.
      speedMbps: Number.isInteger(speed) && speed > 0 ? speed : null,
      adminStatus: ADMIN_STATUS[toNum(t.ifAdminStatus ? t.ifAdminStatus[idx] : null)] || null,
      operStatus: IF_STATUS[toNum(t.ifOperStatus ? t.ifOperStatus[idx] : null)] || null,
      physAddress: toMac(t.ifPhysAddress ? t.ifPhysAddress[idx] : null),
    });
  }

  // WHAT THE DEVICE ACTUALLY SUPPORTS. Reported so the UI can say "fdb not
  // supported" rather than showing an empty column — the same rule
  // connectionTest/checks.js follows with `available:false`, and the same one
  // snmpMonitor follows by reporting an absent counter as null rather than 0.
  // A device that CANNOT answer must never look like one that answered "none".
  const supported = [];
  if (interfaces.length) supported.push('if');
  // FDB counts as supported only when the bridge-port map came back too:
  // without it the answers cannot be resolved to an interface, which is the
  // only form in which they are worth anything.
  if (fdb.length && portToIfIndex.size) supported.push('fdb');
  if (neighbours.length) supported.push('lldp');
  if (vlans.length) supported.push('vlan');

  return {
    // The device's own clock and name, straight through. sysUpTime is what the
    // server compares against the ELAPSED REAL TIME to decide whether a counter
    // delta survived a reboot — a device that restarted and came back up
    // between two polls has a RISING uptime that rose by less than the wall
    // clock did, which is the case everybody forgets.
    sysUpTimeTicks: t.sysUpTimeTicks ?? null,
    sysName: t.sysName ?? null,
    interfaces,
    fdb,
    fdbTruncated,
    neighbours,
    vlans,
    supported,
    // Counted before the cap, so the server can show "5 000 of 21 480".
    fdbTotal: rows.length,
  };
}

// Polls one device. Returns { deviceId, ...topology } or throws with a coded
// error the caller turns into `last_error` on the device row.
async function pollSnmpTopology({
  device,
  readTables = defaultReadTables,
  maxFdb = MAX_FDB_ENTRIES,
  maxNeighbours = MAX_NEIGHBOURS,
} = {}) {
  if (!device || typeof device.host !== 'string' || !device.host) {
    const err = new Error('SNMP topology poll needs a device with a host.');
    err.code = 'SNMP_BAD_TARGET';
    throw err;
  }
  const collect = Array.isArray(device.collect) && device.collect.length
    ? device.collect
    : ['if', 'fdb', 'lldp', 'vlan'];

  const tables = await readTables(
    {
      host: device.host, port: device.port, version: device.version,
      community: device.community, v3: device.v3,
    },
    { collect },
  );
  const topology = buildTopology(tables, { maxFdb, maxNeighbours });
  return { deviceId: device.deviceId, ...topology };
}

module.exports = {
  pollSnmpTopology,
  buildTopology,
  parseFdbIndex,
  macFromOidParts,
  decodeLldpId,
  localPortFromLldpIndex,
  OID,
  MAX_FDB_ENTRIES,
  MAX_NEIGHBOURS,
};
