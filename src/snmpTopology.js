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

const {
  IF_MIB, BRIDGE, Q_BRIDGE, LLDP, CDP, CISCO_VTP, IP_MIB, ENTITY, SYSTEM: SYS,
} = require('./snmp/oids');
const {
  openSession, closeSession, walkColumn, walkColumnWithin, getScalars, toNumber, toText, toMac,
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
  ifMtu: IF_MIB.ifMtu,
  dot1dBasePortIfIndex: BRIDGE.dot1dBasePortIfIndex,
  dot1dTpFdbPort: BRIDGE.dot1dTpFdbPort,
  dot1dTpFdbStatus: BRIDGE.dot1dTpFdbStatus,
  dot1qTpFdbPort: Q_BRIDGE.dot1qTpFdbPort,
  dot1qTpFdbStatus: Q_BRIDGE.dot1qTpFdbStatus,
  dot1qVlanStaticName: Q_BRIDGE.dot1qVlanStaticName,
  vtpVlanState: CISCO_VTP.vtpVlanState,
  vtpVlanName: CISCO_VTP.vtpVlanName,
  lldpRemChassisIdSubtype: LLDP.lldpRemChassisIdSubtype,
  lldpRemChassisId: LLDP.lldpRemChassisId,
  lldpRemPortIdSubtype: LLDP.lldpRemPortIdSubtype,
  lldpRemPortId: LLDP.lldpRemPortId,
  lldpRemPortDesc: LLDP.lldpRemPortDesc,
  lldpRemSysName: LLDP.lldpRemSysName,
  lldpLocPortIdSubtype: LLDP.lldpLocPortIdSubtype,
  cdpCacheAddressType: CDP.cdpCacheAddressType,
  cdpCacheAddress: CDP.cdpCacheAddress,
  cdpCacheDeviceId: CDP.cdpCacheDeviceId,
  cdpCacheDevicePort: CDP.cdpCacheDevicePort,
  cdpCachePlatform: CDP.cdpCachePlatform,
  ipNetToPhysicalPhysAddress: IP_MIB.ipNetToPhysicalPhysAddress,
  ipNetToPhysicalState: IP_MIB.ipNetToPhysicalState,
  ipNetToMediaPhysAddress: IP_MIB.ipNetToMediaPhysAddress,
  ipNetToMediaType: IP_MIB.ipNetToMediaType,
  entPhysicalDescr: ENTITY.entPhysicalDescr,
  entPhysicalClass: ENTITY.entPhysicalClass,
  entPhysicalName: ENTITY.entPhysicalName,
  entPhysicalHardwareRev: ENTITY.entPhysicalHardwareRev,
  entPhysicalFirmwareRev: ENTITY.entPhysicalFirmwareRev,
  entPhysicalSoftwareRev: ENTITY.entPhysicalSoftwareRev,
  entPhysicalSerialNum: ENTITY.entPhysicalSerialNum,
  entPhysicalMfgName: ENTITY.entPhysicalMfgName,
  entPhysicalModelName: ENTITY.entPhysicalModelName,
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
// LLDP and CDP together: the server keeps 512 neighbours per device, and a
// switch that sees more than that is an access layer full of phones.
const MAX_NEIGHBOURS = 512;
// A router's ARP table. Eight thousand addresses is a /19 of hosts — beyond
// that it is a core router whose table answers nothing a technician asks. The
// WALK is bounded at twice that, so a 50 000-entry table costs the device a
// bounded read rather than all of it.
const MAX_ARP_ENTRIES = 8192;
const ARP_WALK_ROWS = MAX_ARP_ENTRIES * 2;
// ENTITY-MIB: every chassis (a stack of eight is eight chassis, each with its
// own serial), and a bounded number of modules. A Nexus reports thousands of
// entities — every sensor, fan and port — and the inventory wants the boxes and
// the line cards, not the thermometers.
const MAX_CHASSIS = 16;
const MAX_MODULES = 32;
const ENTITY_WALK_ROWS = 4096;
// Kept back from the optional walks (CDP, ARP, ENTITY) at the end of a
// device's time budget, for building the report and handing it over before the
// poller's own timeout fires. A tenth of the budget when that is less.
const OPTIONAL_RESERVE_MS = 2000;
// Per-VLAN forwarding tables (Cisco community string indexing, see
// readVlanFdb): at most this many VLANs per poll, a few at a time, and the
// walk gives up after this many VLANs in a row fail — a device that does not
// do community indexing (or stops answering) must not spend the whole optional
// budget proving it.
const MAX_VLAN_FDB_WALKS = 64;
const VLAN_FDB_CONCURRENCY = 4;
// Where each device's per-VLAN walk left off. A Catalyst with more VLANs than
// MAX_VLAN_FDB_WALKS is covered over several polls instead of never getting
// past its first 64 (found end to end: VLAN 336 on a 274-VLAN 3750 was never
// read). Process-lifetime state; a restart starts again at the beginning.
const vlanFdbCursor = new Map();
const VLAN_FDB_GIVE_UP_AFTER = 3;
// The FDDI/Token Ring defaults every Catalyst lists in its VTP table.
const RESERVED_VLANS = new Set([1002, 1003, 1004, 1005]);
const ENT_CLASS_CHASSIS = 3;
const ENT_CLASS_MODULE = 9;

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

// CISCO-VTP-MIB vtpVlanTable -> [{ vlan, name }], ascending. The index is
// <managementDomain>.<vlanId>. Only VLANs the switch reports as operational
// (vtpVlanState 1; a row with no state is taken as it stands), never the
// reserved 1002-1005, and a VLAN listed in two management domains once.
function parseVtpVlans(nameRows, stateRows) {
  const out = new Map();
  for (const [index, value] of Object.entries(nameRows || {})) {
    const parts = String(index).split('.');
    if (parts.length !== 2) continue;
    const vlan = Number(parts[1]);
    if (!Number.isInteger(vlan) || vlan < 1 || vlan > 4094 || RESERVED_VLANS.has(vlan)) continue;
    const state = stateRows ? toNumber(stateRows[index]) : null;
    if (state != null && state !== 1) continue;
    if (out.has(vlan)) continue;
    out.set(vlan, toText(value));
  }
  return [...out.entries()].sort((a, b) => a[0] - b[0]).map(([vlan, name]) => ({ vlan, name }));
}

// The credential that reads one VLAN's BRIDGE-MIB instance on Catalyst IOS:
// "community@<vlan>" on v1/v2c, the context "vlan-<vlan>" on v3 (which the
// device must map with `snmp-server group … context vlan- match prefix`).
// Null when the device has no credential to index.
function vlanCredential(device, vlan) {
  if (!device) return null;
  const v3 = device.v3 && device.v3.user ? device.v3 : null;
  if (v3 || String(device.version) === '3') {
    return v3 ? { ...device, v3: { ...v3, context: `vlan-${vlan}` } } : null;
  }
  return device.community ? { ...device, community: `${device.community}@${vlan}` } : null;
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

// ---------------------------------------------------------------- addresses

function ipv4FromBytes(bytes) {
  if (!Array.isArray(bytes) || bytes.length !== 4) return null;
  if (bytes.some((b) => !Number.isInteger(b) || b < 0 || b > 255)) return null;
  return bytes.join('.');
}

// RFC 5952 text form: lower case, leading zeros dropped, the LONGEST run of two
// or more zero groups (the first, on a tie) collapsed to "::". One spelling per
// address, so the server's exact-match search finds it however it was typed.
function ipv6FromBytes(bytes) {
  if (!Array.isArray(bytes) || bytes.length !== 16) return null;
  if (bytes.some((b) => !Number.isInteger(b) || b < 0 || b > 255)) return null;
  const groups = [];
  for (let i = 0; i < 16; i += 2) groups.push((bytes[i] << 8) | bytes[i + 1]);
  let best = -1;
  let bestLen = 0;
  for (let i = 0; i < 8;) {
    if (groups[i] !== 0) { i += 1; continue; }
    let j = i;
    while (j < 8 && groups[j] === 0) j += 1;
    if (j - i > bestLen && j - i >= 2) { best = i; bestLen = j - i; }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (best < 0) return hex.join(':');
  return `${hex.slice(0, best).join(':')}::${hex.slice(best + bestLen).join(':')}`;
}

// Addresses that are never a device on the segment: this-network, loopback,
// multicast/broadcast, and IPv6 link-local/multicast (a router's neighbour
// cache is full of fe80:: entries that name no host anybody searches for).
// 169.254/16 is KEPT: an OT device that never got a DHCP lease sits there, and
// it is exactly the device this table is meant to find.
function usableIp(ip) {
  if (!ip) return false;
  if (ip.includes(':')) {
    const lower = ip.toLowerCase();
    return !(lower === '::' || lower === '::1' || /^fe[89ab]/.test(lower) || lower.startsWith('ff'));
  }
  const first = Number(ip.split('.')[0]);
  return !(first === 0 || first === 127 || first >= 224);
}

// A MAC worth reporting: six bytes, not all-zero (an incomplete entry), not
// broadcast, not multicast.
function arpMac(value) {
  const mac = toMac(value);
  if (!mac) return null;
  const first = parseInt(mac.slice(0, 2), 16);
  if (mac === '00:00:00:00:00:00' || mac === 'ff:ff:ff:ff:ff:ff' || (first & 1)) return null;
  return mac;
}

// ipNetToPhysicalTable index: <ifIndex>.<addrType>.<addrLen>.<bytes…>.
//
// InetAddress is a variable-length OCTET STRING, so a conforming agent puts the
// length in the index. A few implementations leave it out; when the component
// count only makes sense WITHOUT the length — and the first address byte is not
// itself the length, which would make a truncated prefixed index look like an
// unprefixed one — that is how it is read. Types:
// 1 ipv4 (4), 2 ipv6 (16), 3 ipv4z (8), 4 ipv6z (20). The zoned forms are
// link-scoped addresses with an interface zone — not a host anybody searches
// for — and are refused, like link-local IPv6.
function parseIpNetToPhysicalIndex(index) {
  const parts = String(index).split('.').map((p) => Number(p));
  if (parts.length < 3 || parts.some((n) => !Number.isInteger(n) || n < 0)) return null;
  const [ifIndex, type] = parts;
  const want = type === 1 ? 4 : (type === 2 ? 16 : null);
  if (!want || ifIndex <= 0) return null;
  let bytes = null;
  if (parts.length === 3 + want && parts[2] === want) bytes = parts.slice(3);
  else if (parts.length === 2 + want && parts[2] !== want) bytes = parts.slice(2);
  if (!bytes) return null;
  const ip = type === 1 ? ipv4FromBytes(bytes) : ipv6FromBytes(bytes);
  return ip ? { ifIndex, ip } : null;
}

// ipNetToMediaTable index: <ifIndex>.<a>.<b>.<c>.<d> — IPv4 only.
function parseIpNetToMediaIndex(index) {
  const parts = String(index).split('.').map((p) => Number(p));
  if (parts.length !== 5 || !Number.isInteger(parts[0]) || parts[0] <= 0) return null;
  const ip = ipv4FromBytes(parts.slice(1));
  return ip ? { ifIndex: parts[0], ip } : null;
}

// cdpCacheAddress, decoded by cdpCacheAddressType. The value is raw address
// BYTES, not text: 0a 0e 00 0b is 10.14.0.11, and reading it as a string gives
// "\n\u000e\u0000\u000b". Type 1 is ip, type 20 is ipv6; with no type the
// length decides (four or sixteen), and anything else is not reported rather
// than rendered as a plausible-looking wrong address.
function decodeCdpAddress(value, type) {
  if (value == null) return null;
  if (typeof value === 'string') {
    // Some test harnesses and a few agents hand the dotted form back as text.
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(value.trim()) ? value.trim() : null;
  }
  if (!Buffer.isBuffer(value)) return null;
  const bytes = [...value];
  const t = type == null ? null : Number(type);
  if ((t === 1 || t == null) && bytes.length === 4) return ipv4FromBytes(bytes);
  if ((t === 20 || t == null) && bytes.length === 16) return ipv6FromBytes(bytes);
  return null;
}

// A CDP cache index is <ifIndex>.<deviceIndex>.
function parseCdpIndex(index) {
  const parts = String(index).split('.').map((p) => Number(p));
  if (parts.length !== 2 || !parts.every((n) => Number.isInteger(n) && n >= 0)) return null;
  return parts[0] > 0 ? { ifIndex: parts[0], deviceIndex: parts[1] } : null;
}

// A string off the ENTITY-MIB or the system group: trimmed, bounded, and null
// for "no answer" and "blank" alike.
function boundedText(v, max = 255) {
  const s = toText(v);
  return s ? s.slice(0, max) : null;
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
// table, and a device with no LLDP must still yield its forwarding table. The
// same holds for everything added since: a switch that does not speak CDP, has
// no IP-MIB neighbour table or no ENTITY-MIB answers with an empty walk, and
// that is an empty answer, never an error.
//
// TWO PHASES, CORE FIRST. The interfaces, the forwarding table, LLDP and the
// VLAN names are what the topology rests on; CDP, the router's ARP table (up
// to 16 384 rows walked) and the ENTITY-MIB inventory were added on top, and
// a slow router answering all of them at once inside ONE per-device timeout
// used to lose the lot — the forwarding table included — whenever the extras
// pushed it over. So the core walks run on their own first, and the optional
// ones run afterwards in whatever is left of `timeoutMs`, less a reserve for
// building the report. An optional walk that runs out of time or fails is
// abandoned and NAMED in `partial` ({ kind, reason, rows?, error? }); the core
// tables are returned either way. What a partial answer is worth depends on
// how the server stores the table:
//   * arp    — upserted, never replaced: the rows read so far are kept, and
//              the table is marked truncated.
//   * cdp    — diffed against the previous poll: half a neighbour table would
//              announce the other half as removed, so a cut CDP walk reports
//              no CDP rows at all (which the server already reads as "not
//              walked this time", not "every neighbour left").
//   * entity — REPLACED on the server: half an inventory would erase the
//              other half, so a cut walk reports none.
// `timeoutMs` 0 means no time bound on the optional phase (a direct caller
// with no poller timeout around it).
//
// `session` is injectable so a test can serve varbinds shaped exactly as
// net-snmp hands them back, without the optional dependency or a device. It is
// closed either way: whoever calls this has handed it over.
//
// `vlanSession(device)` opens the session for one VLAN's forwarding table (the
// device with its community/context rewritten by vlanCredential); injectable
// so a test can serve a different recording per community. A caller that
// injects `session` but no `vlanSession` gets no per-VLAN walk: it would
// otherwise open real sockets beside its fake one.
async function defaultReadTables(snmp, {
  collect = ['if', 'fdb', 'lldp', 'vlan'], session: injected = null, timeoutMs = 0, now = Date.now,
  vlanSession = undefined, vlanCursor = vlanFdbCursor,
} = {}) {
  const started = now();
  const session = injected || openSession(snmp);
  const openVlanSession = vlanSession !== undefined ? vlanSession : (injected ? null : openSession);
  try {
    // sysUpTime FIRST, in one GET beside the device's own name. It is read on
    // every poll whatever else was asked for, because it is what says whether
    // the NEXT poll's counter delta is a measurement or an artefact of a
    // reboot — and reading it needs one round trip against a device we have
    // already opened a session to.
    const system = await getScalars(session, [SYS.sysUpTime, SYS.sysName, SYS.sysDescr])
      .catch(() => ({}));
    // The rest of the system group in a SECOND GET. On SNMPv1 one missing OID
    // fails the whole request (noSuchName), and a device that never set a
    // contact must not cost the uptime above. All three are mandatory in
    // RFC 3418, so on almost every device this is one cheap round trip.
    const about = await getScalars(session, [SYS.sysLocation, SYS.sysContact, SYS.sysObjectID])
      .catch(() => ({}));
    const safe = (oid, opts) => walkColumn(session, oid, opts).catch(() => ({}));
    const want = new Set(collect);
    // The port NAMES are wanted by everything that names a port: the inventory,
    // the forwarding table, a CDP neighbour and an ARP entry.
    const wantNames = want.has('if') || want.has('fdb') || want.has('cdp') || want.has('arp');
    const bounded = (rows) => ({ maxRows: rows });

    // --- phase 1: the core tables ------------------------------------------
    const [
      ifName, ifAlias, ifDescr, ifType, ifPhysAddress, ifAdminStatus, ifOperStatus, ifHighSpeed, ifMtu,
      basePortIfIndex,
      qFdbPort, qFdbStatus, dFdbPort, dFdbStatus,
      vlanName,
      lldpChassis, lldpChassisSubtype, lldpPort, lldpPortSubtype, lldpPortDesc, lldpSysName,
    ] = await Promise.all([
      wantNames ? safe(OID.ifName) : {},
      want.has('if') ? safe(OID.ifAlias) : {},
      // ifDescr is fetched whenever a name is wanted, because it is the
      // fallback when the device has no ifName at all.
      wantNames ? safe(OID.ifDescr) : {},
      want.has('if') ? safe(OID.ifType) : {},
      want.has('if') ? safe(OID.ifPhysAddress) : {},
      want.has('if') ? safe(OID.ifAdminStatus) : {},
      want.has('if') ? safe(OID.ifOperStatus) : {},
      want.has('if') ? safe(OID.ifHighSpeed) : {},
      // ifMtu is the port's OWN configured MTU. It is the other half of an MTU
      // fault: `path_mtu` measures what a path carries end to end, this says
      // what each port was configured to carry — and a link whose two ends
      // disagree is the cause that measurement is looking for.
      want.has('if') ? safe(OID.ifMtu) : {},
      // Without the bridge-port map the forwarding table cannot be resolved to
      // an interface, and an unresolved answer is the one thing this module
      // must not produce silently. An empty result is handled by buildTopology,
      // which reports `fdb` as unsupported rather than guessing.
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

    // Catalyst IOS implements no Q-BRIDGE-MIB: its VLAN names, and the VLAN
    // list the per-VLAN forwarding walk below needs, are in CISCO-VTP-MIB. Only
    // asked when Q-BRIDGE came back empty, so a device that has it pays nothing,
    // and one that has neither pays one empty walk.
    const noQNames = !Object.keys(vlanName).length;
    const noQFdb = !Object.keys(qFdbPort).length;
    const [vtpName, vtpState] = (want.has('vlan') && noQNames) || (want.has('fdb') && noQFdb)
      ? await Promise.all([safe(OID.vtpVlanName), safe(OID.vtpVlanState)])
      : [{}, {}];

    // --- phase 2: the optional tables, in the time that is left ------------
    const partial = [];
    const reserve = Math.min(OPTIONAL_RESERVE_MS, Math.floor(timeoutMs / 10));
    const optDeadline = timeoutMs > 0 ? started + timeoutMs - reserve : Infinity;
    // One walk against the shared deadline. A walk that would start with no
    // time left is not issued at all.
    const opt = (oid, rows = 0, on = session) => {
      const left = optDeadline - now();
      if (left <= 0) return Promise.resolve({ rows: {}, timedOut: true, error: null, skipped: true });
      return walkColumnWithin(on, oid, {
        maxRows: rows, timeoutMs: Number.isFinite(left) ? Math.max(1, Math.floor(left)) : 0,
      });
    };
    // How a kind's walks went, as one outcome: cut short, failed, or whole.
    const outcome = (results) => {
      if (results.some((r) => r.timedOut)) {
        return results.every((r) => r.skipped) ? 'no-time' : 'timeout';
      }
      return results.some((r) => r.error) ? 'error' : null;
    };
    const firstError = (results) => {
      const r = results.find((x) => x.error);
      return r ? String((r.error && r.error.message) || r.error).slice(0, 200) : null;
    };
    const mark = (kind, results, extra = {}) => {
      const reason = outcome(results);
      if (!reason) return false;
      const e = firstError(results);
      partial.push({ kind, reason, ...extra, ...(e ? { error: e } : {}) });
      return true;
    };
    const rowsOf = (r) => r.rows;
    const none = () => Promise.resolve([]);

    // ipNetToPhysicalTable first; ipNetToMediaTable only when the newer table
    // is empty. Asking for both on a device that has both would read every
    // IPv4 entry twice. A cut walk of the newer table is NOT a reason to fall
    // back: the older one is the same table again, in less time.
    async function readArp() {
      if (!want.has('arp')) return { source: null };
      const physPair = await Promise.all([
        opt(OID.ipNetToPhysicalPhysAddress, ARP_WALK_ROWS),
        opt(OID.ipNetToPhysicalState, ARP_WALK_ROWS),
      ]);
      const [phys, state] = physPair.map(rowsOf);
      const physCut = outcome(physPair);
      if (Object.keys(phys).length || physCut) {
        const cut = mark('arp', physPair, { rows: Object.keys(phys).length });
        return { source: 'ipNetToPhysical', phys, state, cut };
      }
      const mediaPair = await Promise.all([
        opt(OID.ipNetToMediaPhysAddress, ARP_WALK_ROWS),
        opt(OID.ipNetToMediaType, ARP_WALK_ROWS),
      ]);
      const [media, type] = mediaPair.map(rowsOf);
      const cut = mark('arp', mediaPair, { rows: Object.keys(media).length });
      return Object.keys(media).length || cut ? { source: 'ipNetToMedia', media, type, cut } : { source: null };
    }

    // Cisco's per-VLAN forwarding tables. IOS keeps one BRIDGE-MIB table per
    // VLAN and the default community reads only VLAN 1's — on the recorded
    // 3750, 15 MACs for a switch with 274 VLANs. Each VLAN's table (and its
    // own bridge-port map) is read under "community@<vlan>" (v3: context
    // "vlan-<vlan>"). Optional-phase work: it runs inside the same deadline
    // as CDP/ARP/ENTITY, so it can never cost the core tables, at most
    // MAX_VLAN_FDB_WALKS VLANs, and it stops after VLAN_FDB_GIVE_UP_AFTER
    // failures in a row (a device that does not index by community, or one
    // that stopped answering). The forwarding table
    // is upserted and aged out on the server, so the VLANs read before the
    // deadline are kept and the rest named in `partial`.
    async function readVlanFdb() {
      if (!want.has('fdb') || !noQFdb || typeof openVlanSession !== 'function') return [];
      const all = parseVtpVlans(vtpName, vtpState).map((v) => v.vlan);
      if (!all.length || !vlanCredential(snmp, all[0])) return [];
      // The first (default) VLAN every poll — its MACs must not flip between
      // "untagged" and "VLAN 1" — and the rest in rotation, picking up where
      // the previous poll of this device stopped.
      const [first, ...rest] = all;
      const cursorKey = `${snmp.deviceId ?? ''}|${snmp.host}|${snmp.port ?? 161}`;
      const start = rest.length ? (Number(vlanCursor.get(cursorKey)) || 0) % rest.length : 0;
      const rotated = rest.slice(start).concat(rest.slice(0, start));
      const ids = [first, ...rotated.slice(0, MAX_VLAN_FDB_WALKS - 1)];
      const tablesByVlan = [];
      const walked = [];
      let next = 0;
      let failures = 0;
      let answered = 0;
      let failedInARow = 0;
      const one = async (vlan) => {
        let vs;
        try {
          vs = openVlanSession(vlanCredential(snmp, vlan));
        } catch (err) {
          return [{ rows: {}, timedOut: false, error: err }];
        }
        try {
          const walks = await Promise.all([
            opt(OID.dot1dTpFdbPort, MAX_FDB_ENTRIES, vs),
            opt(OID.dot1dTpFdbStatus, MAX_FDB_ENTRIES, vs),
            opt(OID.dot1dBasePortIfIndex, 0, vs),
          ]);
          if (Object.keys(walks[0].rows).length) {
            tablesByVlan.push({ vlan, port: walks[0].rows, status: walks[1].rows, basePortIfIndex: walks[2].rows });
          }
          return walks;
        } finally {
          closeSession(vs);
        }
      };
      const worker = async () => {
        while (next < ids.length) {
          if (failedInARow >= VLAN_FDB_GIVE_UP_AFTER) return;
          if (optDeadline - now() <= 0) return;
          const vlan = ids[next];
          next += 1;
          // eslint-disable-next-line no-await-in-loop
          const walks = await one(vlan);
          walked.push(...walks);
          if (walks.some((w) => w.error || w.timedOut)) {
            failures += 1;
            failedInARow += 1;
          } else {
            answered += 1;
            failedInARow = 0;
          }
        }
      };
      await Promise.all(Array.from({ length: Math.min(VLAN_FDB_CONCURRENCY, ids.length) }, worker));
      // Advance past the rotating VLANs this poll actually dispatched (the
      // first one is not part of the rotation).
      const rotatedDone = Math.max(0, Math.min(next, ids.length) - 1);
      if (rest.length && rotatedDone > 0) vlanCursor.set(cursorKey, (start + rotatedDone) % rest.length);
      const notWalked = all.length - (answered + failures);
      const extra = { vlans: answered, of: all.length };
      if (!mark('fdb', walked, extra) && notWalked > 0) {
        // 'rotating': more VLANs than one poll reads — by design, the rest are
        // read on the following polls. 'no-time': the budget ran out.
        partial.push({ kind: 'fdb', reason: all.length > ids.length && answered + failures >= ids.length ? 'rotating' : 'no-time', ...extra });
      }
      tablesByVlan.sort((a, b) => a.vlan - b.vlan);
      return tablesByVlan;
    }

    const CDP_COLS = [OID.cdpCacheAddressType, OID.cdpCacheAddress, OID.cdpCacheDeviceId,
      OID.cdpCacheDevicePort, OID.cdpCachePlatform];
    const ENT_COLS = [OID.entPhysicalDescr, OID.entPhysicalClass, OID.entPhysicalName,
      OID.entPhysicalHardwareRev, OID.entPhysicalFirmwareRev, OID.entPhysicalSoftwareRev,
      OID.entPhysicalSerialNum, OID.entPhysicalMfgName, OID.entPhysicalModelName];

    const [cdpWalks, arp, entWalks, vlanFdb] = await Promise.all([
      want.has('cdp') ? Promise.all(CDP_COLS.map((oid) => opt(oid))) : none(),
      readArp().catch(() => ({ source: null })),
      want.has('entity') ? Promise.all(ENT_COLS.map((oid) => opt(oid, ENTITY_WALK_ROWS))) : none(),
      readVlanFdb().catch(() => []),
    ]);
    // All or nothing for these two — see above.
    const cdpCut = mark('cdp', cdpWalks);
    const entCut = mark('entity', entWalks);
    const [cdpAddressType, cdpAddress, cdpDeviceId, cdpDevicePort, cdpPlatform] = CDP_COLS
      .map((_, i) => (cdpCut || !cdpWalks[i] ? {} : cdpWalks[i].rows));
    const [
      entDescr, entClass, entName, entHardwareRev, entFirmwareRev, entSoftwareRev,
      entSerialNum, entMfgName, entModelName,
    ] = ENT_COLS.map((_, i) => (entCut || !entWalks[i] ? {} : entWalks[i].rows));

    return {
      // Hundredths of a second since the device last re-initialised, and what
      // the device calls itself. Null when it did not answer — an unknown
      // uptime must never read as "just booted".
      sysUpTimeTicks: toNumber(system[SYS.sysUpTime]),
      sysName: toText(system[SYS.sysName]),
      sysDescr: toText(system[SYS.sysDescr]),
      sysLocation: toText(about[SYS.sysLocation]),
      sysContact: toText(about[SYS.sysContact]),
      sysObjectId: toText(about[SYS.sysObjectID]),
      ifName, ifAlias, ifDescr, ifType, ifPhysAddress, ifAdminStatus, ifOperStatus, ifHighSpeed, ifMtu,
      basePortIfIndex,
      qFdbPort, qFdbStatus, dFdbPort, dFdbStatus,
      vlanFdb,
      vlanName,
      vtpVlanName: vtpName,
      vtpVlanState: vtpState,
      lldpChassis, lldpChassisSubtype, lldpPort, lldpPortSubtype, lldpPortDesc, lldpSysName,
      cdpAddressType, cdpAddress, cdpDeviceId, cdpDevicePort, cdpPlatform,
      arpPhys: arp.phys || {},
      arpState: arp.state || {},
      arpMedia: arp.media || {},
      arpMediaType: arp.type || {},
      arpWalkLimit: ARP_WALK_ROWS,
      arpPartial: !!arp.cut,
      entDescr, entClass, entName, entHardwareRev, entFirmwareRev, entSoftwareRev,
      entSerialNum, entMfgName, entModelName,
      partial,
    };
  } finally {
    closeSession(session);
  }
}

// Turns the raw walks into the rows the server stores. Pure — this is where
// every decision that could be got wrong lives, and it is tested against
// fixtures rather than a switch.
function buildTopology(tables, {
  maxFdb = MAX_FDB_ENTRIES, maxNeighbours = MAX_NEIGHBOURS, maxArp = MAX_ARP_ENTRIES,
} = {}) {
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

  // VLAN id -> name, for a UI that can say "VLAN 20 (Office)". Q-BRIDGE when
  // the device has it; Catalyst IOS has not, and names its VLANs in
  // CISCO-VTP-MIB instead (reserved 1002-1005 left out).
  const vlans = [];
  for (const [id, value] of Object.entries(t.vlanName || {})) {
    const vid = Number(id);
    const name = toStr(value);
    if (Number.isInteger(vid) && name) vlans.push({ vlan: vid, name });
  }
  if (!vlans.length) {
    for (const v of parseVtpVlans(t.vtpVlanName, t.vtpVlanState)) if (v.name) vlans.push(v);
  }

  // --- forwarding table ----------------------------------------------------
  //
  // Q-BRIDGE first. A device that answers both is read from the per-VLAN table
  // only: merging them would double every entry, since the same MAC appears in
  // both with the same bridge port.
  const rows = [];
  const seen = new Set();

  // MACs already reported from a VLAN-tagged table, so the untagged default
  // (VLAN 1) walk does not report the same address a second time as VLAN 0.
  const taggedMacs = new Set();

  function collectFdb(portTable, statusTable, statusNames, withVlan, { vlan = null, portMap = portToIfIndex } = {}) {
    for (const [index, portValue] of Object.entries(portTable || {})) {
      const parsed = parseFdbIndex(index, { withVlan });
      if (!parsed) continue;
      if (vlan != null) parsed.vlan = vlan;
      if (vlan == null && !withVlan && taggedMacs.has(parsed.mac)) continue;
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
      if (vlan != null) taggedMacs.add(parsed.mac);

      // A per-VLAN table resolves through ITS OWN bridge-port map, never the
      // default one: the two are different BRIDGE-MIB instances.
      const ifIndex = portMap.has(bridgePort) ? portMap.get(bridgePort) : null;
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
  let vlanPortMaps = 0;
  if (hasQBridge) {
    collectFdb(t.qFdbPort, t.qFdbStatus, FDB_STATUS, true);
  } else {
    // The per-VLAN tables first (tagged), then the default instance for what
    // they did not cover.
    for (const v of Array.isArray(t.vlanFdb) ? t.vlanFdb : []) {
      if (!v || !Number.isInteger(v.vlan) || v.vlan < 1 || v.vlan > 4094) continue;
      const portMap = new Map();
      for (const [bp, value] of Object.entries(v.basePortIfIndex || {})) {
        const n = Number(bp);
        const idx = toNum(value);
        if (Number.isInteger(n) && Number.isInteger(idx) && idx > 0) portMap.set(n, idx);
      }
      if (portMap.size) vlanPortMaps += 1;
      collectFdb(v.port, v.status, FDB_STATUS_BRIDGE, false, { vlan: v.vlan, portMap });
    }
    collectFdb(t.dFdbPort, t.dFdbStatus, FDB_STATUS_BRIDGE, false);
  }

  // How many MACs are on each port. THE field that turns a hit into an answer:
  // one MAC is an end device and a patch panel to walk to; forty is an uplink
  // and one more hop to go. Counted over EVERYTHING seen, before the cap, so a
  // truncated report still says honestly that a port is crowded.
  // Per INTERFACE where it resolved — the per-VLAN tables are separate bridge
  // instances, and one uplink carries MACs from all of them — and per bridge
  // port where it did not.
  const portKey = (r) => (r.ifIndex != null ? `if${r.ifIndex}` : `bp${r.bridgePort}`);
  const perPort = new Map();
  for (const r of rows) perPort.set(portKey(r), (perPort.get(portKey(r)) || 0) + 1);
  for (const r of rows) r.portMacCount = perPort.get(portKey(r)) || 1;

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
      protocol: 'lldp',
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

  // CDP, after LLDP and inside the same cap. The index's first component IS
  // the local ifIndex (no bridge-port indirection), and the device id is the
  // neighbour's hostname — the chassis identity CDP offers. A Cisco neighbour
  // running both protocols appears twice, once per protocol, on purpose: the
  // two rows carry different identities (a MAC versus a name) and the server
  // keys them apart by `protocol`.
  const lldpCount = neighbours.length;
  for (const [index, deviceIdValue] of Object.entries(t.cdpDeviceId || {})) {
    if (neighbours.length >= maxNeighbours) break;
    const parsed = parseCdpIndex(index);
    if (!parsed) continue;
    const remoteChassisId = decodeLldpId(deviceIdValue, null);
    if (!remoteChassisId) continue;
    const addressType = toNum(t.cdpAddressType ? t.cdpAddressType[index] : null);
    const remoteSysName = toStr(deviceIdValue);
    neighbours.push({
      protocol: 'cdp',
      localPort: parsed.ifIndex,
      localIfIndex: parsed.ifIndex,
      localIfName: realNameByIndex.get(parsed.ifIndex) || null,
      remoteChassisId,
      remotePortId: toStr(t.cdpDevicePort ? t.cdpDevicePort[index] : null),
      // CDP has no separate port description; the port id IS its name.
      remotePortDesc: null,
      // The device id is the neighbour's hostname, which is what the coverage
      // report and the topology graph match names against.
      remoteSysName: remoteSysName && /^[\x20-\x7e]+$/.test(remoteSysName) ? remoteSysName : null,
      remoteAddress: decodeCdpAddress(t.cdpAddress ? t.cdpAddress[index] : null, addressType),
      remotePlatform: boundedText(t.cdpPlatform ? t.cdpPlatform[index] : null),
    });
  }
  const cdpCount = neighbours.length - lldpCount;

  // --- ARP (IP-MIB) --------------------------------------------------------
  //
  // One row per IP. The newer ipNetToPhysicalTable when it answered, the
  // deprecated ipNetToMediaTable otherwise. An entry the device itself marks
  // invalid (or, in the newer table, still incomplete) is dropped: it names an
  // address the router is ASKING about, not one it has found.
  const arpRows = [];
  const arpSeen = new Set();
  const arpFrom = Object.keys(t.arpPhys || {}).length ? 'ipNetToPhysical'
    : (Object.keys(t.arpMedia || {}).length ? 'ipNetToMedia' : null);
  const pushArp = (parsed, value) => {
    if (!parsed || !usableIp(parsed.ip) || arpSeen.has(parsed.ip)) return;
    const mac = arpMac(value);
    if (!mac) return;
    arpSeen.add(parsed.ip);
    arpRows.push({
      ip: parsed.ip,
      mac,
      ifIndex: parsed.ifIndex,
      // The SVI or routed port the address was learned on ("Vlan20"), from the
      // device's own names — null rather than invented, as for the FDB.
      ifName: realNameByIndex.get(parsed.ifIndex) || null,
    });
  };
  if (arpFrom === 'ipNetToPhysical') {
    for (const [index, value] of Object.entries(t.arpPhys)) {
      const state = toNum(t.arpState ? t.arpState[index] : null);
      if (state === 5 || state === 7) continue; // invalid, incomplete
      pushArp(parseIpNetToPhysicalIndex(index), value);
    }
  } else if (arpFrom === 'ipNetToMedia') {
    for (const [index, value] of Object.entries(t.arpMedia)) {
      const type = toNum(t.arpMediaType ? t.arpMediaType[index] : null);
      if (type === 2) continue; // invalid
      pushArp(parseIpNetToMediaIndex(index), value);
    }
  }
  // A walk that stopped at its bound has not seen the whole table, so the
  // report says truncated even when the kept rows fit under the cap.
  const arpWalkLimit = Number(t.arpWalkLimit) || 0;
  const walkCut = arpWalkLimit > 0 && Math.max(
    Object.keys(t.arpPhys || {}).length, Object.keys(t.arpMedia || {}).length,
  ) >= arpWalkLimit;
  // So has a walk abandoned for time (`arpPartial`, set by the reader).
  const arpTruncated = walkCut || !!t.arpPartial || arpRows.length > maxArp;
  const arp = arpRows.length > maxArp ? arpRows.slice(0, maxArp) : arpRows;

  // --- inventory (ENTITY-MIB) ----------------------------------------------
  //
  // Every chassis, then the modules that say what they are (a model or a
  // serial) — a module with neither is a slot, and an inventory of empty
  // slots answers nothing. In index order, which is the device's own order:
  // the first chassis is the one the stack or the box is known by.
  const inventory = [];
  const entIndexes = Object.keys(t.entClass || {})
    .map((k) => Number(k)).filter((n) => Number.isInteger(n) && n > 0).sort((a, b) => a - b);
  const entRow = (idx, cls) => ({
    entIndex: idx,
    class: cls,
    name: boundedText(t.entName ? t.entName[idx] : null, 64),
    descr: boundedText(t.entDescr ? t.entDescr[idx] : null),
    model: boundedText(t.entModelName ? t.entModelName[idx] : null, 128),
    serial: boundedText(t.entSerialNum ? t.entSerialNum[idx] : null, 64),
    vendor: boundedText(t.entMfgName ? t.entMfgName[idx] : null, 128),
    hardwareRev: boundedText(t.entHardwareRev ? t.entHardwareRev[idx] : null, 64),
    firmwareRev: boundedText(t.entFirmwareRev ? t.entFirmwareRev[idx] : null, 64),
    softwareRev: boundedText(t.entSoftwareRev ? t.entSoftwareRev[idx] : null, 64),
  });
  let chassisCount = 0;
  let moduleCount = 0;
  for (const idx of entIndexes) {
    const cls = toNum(t.entClass[idx]);
    if (cls === ENT_CLASS_CHASSIS && chassisCount < MAX_CHASSIS) {
      inventory.push(entRow(idx, 'chassis'));
      chassisCount += 1;
    } else if (cls === ENT_CLASS_MODULE && moduleCount < MAX_MODULES) {
      const row = entRow(idx, 'module');
      if (row.model || row.serial) {
        inventory.push(row);
        moduleCount += 1;
      }
    }
  }

  // --- interfaces ----------------------------------------------------------
  const interfaces = [];
  for (const [idx, name] of ifNameByIndex.entries()) {
    const speed = toNum(t.ifHighSpeed ? t.ifHighSpeed[idx] : null);
    const type = toNum(t.ifType ? t.ifType[idx] : null);
    const mtu = toNum(t.ifMtu ? t.ifMtu[idx] : null);
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
      // The port's own configured MTU (ifMtu, RFC 2863). Null when the device
      // did not answer, never 0 — the same rule speed follows, and it matters
      // more here: the server compares the two ends of a link, and a 0 would
      // make every silent port look like a mismatch with its neighbour.
      // A loopback or tunnel interface reports its own small MTU legitimately,
      // which is why the comparison server-side is between LINKED ports and not
      // across a device's ports.
      mtu: Number.isInteger(mtu) && mtu > 0 ? mtu : null,
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
  if (fdb.length && (portToIfIndex.size || vlanPortMaps)) supported.push('fdb');
  if (lldpCount) supported.push('lldp');
  if (vlans.length) supported.push('vlan');
  if (cdpCount) supported.push('cdp');
  if (arp.length) supported.push('arp');
  if (inventory.length) supported.push('entity');

  return {
    // The device's own clock and name, straight through. sysUpTime is what the
    // server compares against the ELAPSED REAL TIME to decide whether a counter
    // delta survived a reboot — a device that restarted and came back up
    // between two polls has a RISING uptime that rose by less than the wall
    // clock did, which is the case everybody forgets.
    sysUpTimeTicks: t.sysUpTimeTicks ?? null,
    sysName: t.sysName ?? null,
    // What the device says it is (vendor, model, OS version). Already read in
    // the same GET as sysName; bounded because some vendors put a multi-line
    // banner here, and trimmed so "no answer" and "blank" both come out null.
    sysDescr: cleanSysDescr(t.sysDescr),
    // The rest of the system group. sysLocation is what the admin typed into
    // the switch — the room or the rack — and it is the only place a device
    // says where it is below the site. sysObjectID names the vendor and model
    // family as an OID. All three null when the device did not answer.
    sysLocation: cleanSysDescr(t.sysLocation),
    sysContact: cleanSysDescr(t.sysContact),
    sysObjectId: t.sysObjectId ? String(t.sysObjectId).trim().slice(0, 128) || null : null,
    interfaces,
    fdb,
    fdbTruncated,
    neighbours,
    vlans,
    supported,
    // Counted before the cap, so the server can show "5 000 of 21 480".
    fdbTotal: rows.length,
    // The router's ARP table, the table it came from, and whether it was cut.
    arp,
    arpSource: arpFrom,
    arpTruncated,
    arpTotal: arpRows.length,
    inventory,
    // The optional tables that were cut short or failed this poll, by kind
    // (see defaultReadTables). Only present when there are any; the server
    // ignores the key, and the poller uses it to keep `supported` honest.
    ...(Array.isArray(t.partial) && t.partial.length ? { partial: t.partial.map((p) => ({ ...p })) } : {}),
  };
}

const SYS_DESCR_MAX = 255;
function cleanSysDescr(v) {
  if (v == null) return null;
  const s = String(v).trim();
  return s ? s.slice(0, SYS_DESCR_MAX) : null;
}

// Polls one device. Returns { deviceId, ...topology } or throws with a coded
// error the caller turns into `last_error` on the device row.
//
// `timeoutMs` is the time the caller will give this device in all; the reader
// runs the core walks first and fits the optional ones into what is left.
async function pollSnmpTopology({
  device,
  readTables = defaultReadTables,
  maxFdb = MAX_FDB_ENTRIES,
  maxNeighbours = MAX_NEIGHBOURS,
  maxArp = MAX_ARP_ENTRIES,
  timeoutMs = 0,
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
    { collect, timeoutMs },
  );
  const topology = buildTopology(tables, { maxFdb, maxNeighbours, maxArp });
  return { deviceId: device.deviceId, ...topology };
}

module.exports = {
  pollSnmpTopology,
  buildTopology,
  parseFdbIndex,
  macFromOidParts,
  decodeLldpId,
  localPortFromLldpIndex,
  parseIpNetToPhysicalIndex,
  parseIpNetToMediaIndex,
  parseCdpIndex,
  decodeCdpAddress,
  parseVtpVlans,
  vlanCredential,
  ipv6FromBytes,
  defaultReadTables,
  OID,
  MAX_FDB_ENTRIES,
  MAX_NEIGHBOURS,
  MAX_ARP_ENTRIES,
  MAX_CHASSIS,
  MAX_MODULES,
  OPTIONAL_RESERVE_MS,
  MAX_VLAN_FDB_WALKS,
};
