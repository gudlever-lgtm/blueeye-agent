'use strict';

// Every OID this agent reads, in one place.
//
// WHY ONE FILE. Before this there were three copies: snmpMonitor.js (IF-MIB
// counters), snmpTopology.js (IF-MIB names, BRIDGE, Q-BRIDGE, LLDP) and
// traps/translate.js (trap OIDs). `ifName` was written out identically in two
// of them, and the third stage of this work was about to add a fourth copy. A
// dotted number is exactly the kind of constant that is silently wrong: nothing
// throws, a column just comes back empty and the device looks like it does not
// implement the MIB.
//
// Grouped by MIB, with the RFC, because that is how somebody verifies one.
// Trap OIDs stay in traps/translate.js: that is a ~40-entry lookup TABLE keyed
// by OID rather than a set of columns to walk, and merging the two would mean
// one map used two incompatible ways.

// IF-MIB (RFC 2863). The base interface table plus the high-capacity extension.
const IF_MIB = {
  // ifTable — the original 32-bit table. ifDescr is the name fallback; the
  // status and error columns have no high-capacity counterpart.
  ifDescr: '1.3.6.1.2.1.2.2.1.2',
  ifType: '1.3.6.1.2.1.2.2.1.3',
  ifMtu: '1.3.6.1.2.1.2.2.1.4',
  ifSpeed: '1.3.6.1.2.1.2.2.1.5', // bit/s, and it saturates at 4.29 Gbit/s
  ifPhysAddress: '1.3.6.1.2.1.2.2.1.6',
  ifAdminStatus: '1.3.6.1.2.1.2.2.1.7',
  ifOperStatus: '1.3.6.1.2.1.2.2.1.8',
  ifInOctets: '1.3.6.1.2.1.2.2.1.10', // 32-bit; see the note in counters.js
  ifInDiscards: '1.3.6.1.2.1.2.2.1.13',
  ifInErrors: '1.3.6.1.2.1.2.2.1.14',
  ifOutOctets: '1.3.6.1.2.1.2.2.1.16',
  ifOutDiscards: '1.3.6.1.2.1.2.2.1.19',
  ifOutErrors: '1.3.6.1.2.1.2.2.1.20',

  // ifXTable — the 64-bit counters and the name/alias columns. Preferred
  // everywhere: a 32-bit octet counter wraps in ~34 seconds on a saturated
  // gigabit port, which is faster than any polling interval worth having.
  ifName: '1.3.6.1.2.1.31.1.1.1.1',
  ifInMulticastPkts: '1.3.6.1.2.1.31.1.1.1.2',
  ifInBroadcastPkts: '1.3.6.1.2.1.31.1.1.1.3',
  ifOutMulticastPkts: '1.3.6.1.2.1.31.1.1.1.4',
  ifOutBroadcastPkts: '1.3.6.1.2.1.31.1.1.1.5',
  ifHCInOctets: '1.3.6.1.2.1.31.1.1.1.6',
  ifHCInUcastPkts: '1.3.6.1.2.1.31.1.1.1.7',
  ifHCInMulticastPkts: '1.3.6.1.2.1.31.1.1.1.8',
  ifHCInBroadcastPkts: '1.3.6.1.2.1.31.1.1.1.9',
  ifHCOutOctets: '1.3.6.1.2.1.31.1.1.1.10',
  ifHCOutUcastPkts: '1.3.6.1.2.1.31.1.1.1.11',
  ifHCOutMulticastPkts: '1.3.6.1.2.1.31.1.1.1.12',
  ifHCOutBroadcastPkts: '1.3.6.1.2.1.31.1.1.1.13',
  ifHighSpeed: '1.3.6.1.2.1.31.1.1.1.15', // Mbit/s, and it does not saturate
  ifAlias: '1.3.6.1.2.1.31.1.1.1.18',
};

// SNMPv2-MIB (RFC 3418). Scalars, so they are read with a GET rather than
// walked — sysUpTime is the one that says whether a counter delta is real.
const SYSTEM = {
  sysDescr: '1.3.6.1.2.1.1.1.0',
  sysObjectID: '1.3.6.1.2.1.1.2.0',
  sysUpTime: '1.3.6.1.2.1.1.3.0', // TimeTicks: hundredths of a second since boot
  sysContact: '1.3.6.1.2.1.1.4.0',
  sysName: '1.3.6.1.2.1.1.5.0',
  // Free text an admin typed into the switch — "Bygning 3, rum 2.14, rack B".
  // The only place a device says where it PHYSICALLY is, below the site.
  sysLocation: '1.3.6.1.2.1.1.6.0',
};

// EtherLike-MIB (RFC 3635). Indexed by the SAME ifIndex as IF-MIB, so it joins
// straight onto the row.
//
// A LATE COLLISION is one detected after the first 64 bytes have gone out — far
// too late for ordinary CSMA/CD contention. On a modern switched link it means
// one end runs half duplex while the other runs full: the full-duplex end
// transmits whenever it likes, and the half-duplex end sees that as a
// collision. Nothing is wrong until traffic flows both ways at once, and then
// everything is. It is the one counter that names that fault.
//
// FCS errors are the cable's own signature: a frame that arrived with a bad
// checksum was corrupted in flight. A rising FCS count on one port is a bad
// patch lead, a kinked fibre or a failing transceiver, and it is the counter
// that distinguishes those from congestion, which drops frames without
// corrupting them.
const ETHERLIKE = {
  dot3StatsAlignmentErrors: '1.3.6.1.2.1.10.7.2.1.2',
  dot3StatsFCSErrors: '1.3.6.1.2.1.10.7.2.1.3',
  dot3StatsLateCollisions: '1.3.6.1.2.1.10.7.2.1.8',
  dot3StatsCarrierSenseErrors: '1.3.6.1.2.1.10.7.2.1.11',
  dot3StatsDuplexStatus: '1.3.6.1.2.1.10.7.2.1.19', // 1=unknown 2=half 3=full
};

// BRIDGE-MIB (RFC 4188). dot1dBasePortIfIndex is the join without which every
// forwarding-table answer is a guess — a bridge port number is an index into
// dot1dBasePortTable, NOT the ifIndex that names an interface.
const BRIDGE = {
  dot1dBasePortIfIndex: '1.3.6.1.2.1.17.1.4.1.2',
  dot1dTpFdbPort: '1.3.6.1.2.1.17.4.3.1.2',
  dot1dTpFdbStatus: '1.3.6.1.2.1.17.4.3.1.3',
  // Spanning tree, for the loop work: the count of topology changes and how
  // long ago the last one was. A bridge that keeps reconverging says so here
  // before anything else notices.
  dot1dStpTopChanges: '1.3.6.1.2.1.17.2.4.0',
  dot1dStpTimeSinceTopologyChange: '1.3.6.1.2.1.17.2.3.0',
  dot1dStpPortState: '1.3.6.1.2.1.17.2.15.1.3', // 1=disabled 2=blocking ... 5=forwarding
};

// Q-BRIDGE-MIB (RFC 4363) — the forwarding table per VLAN. Preferred over
// BRIDGE-MIB's, because a MAC can legitimately be in two VLANs and the older
// table cannot say so.
const Q_BRIDGE = {
  dot1qTpFdbPort: '1.3.6.1.2.1.17.7.1.2.2.1.2',
  dot1qTpFdbStatus: '1.3.6.1.2.1.17.7.1.2.2.1.3',
  dot1qVlanStaticName: '1.3.6.1.2.1.17.7.1.4.3.1.1',
};

// LLDP-MIB (IEEE 802.1AB) — neighbours as seen BY THE SWITCH, a different and
// usually much larger set than the ones an agent host can see.
//
// The SUBTYPE columns are what say whether an id is a MAC or a name. Without
// them a 6-byte OCTET STRING is ambiguous — "Gi0/24" is exactly six bytes — and
// length alone renders a perfectly good port name as a MAC address.
const LLDP = {
  lldpLocPortIdSubtype: '1.0.8802.1.1.2.1.3.7.1.2',
  lldpRemChassisIdSubtype: '1.0.8802.1.1.2.1.4.1.1.4',
  lldpRemChassisId: '1.0.8802.1.1.2.1.4.1.1.5',
  lldpRemPortIdSubtype: '1.0.8802.1.1.2.1.4.1.1.6',
  lldpRemPortId: '1.0.8802.1.1.2.1.4.1.1.7',
  lldpRemPortDesc: '1.0.8802.1.1.2.1.4.1.1.8',
  lldpRemSysName: '1.0.8802.1.1.2.1.4.1.1.9',
};

// CISCO-CDP-MIB cdpCacheTable — Cisco's own neighbour protocol, which plenty
// of Cisco estates run INSTEAD of LLDP (it is on by default, LLDP is not). The
// index is <cdpCacheIfIndex>.<cdpCacheDeviceIndex>: unlike LLDP's local port
// number, the first component IS the ifIndex.
//
// cdpCacheAddress is a CiscoNetworkAddress — raw bytes whose meaning is given
// by cdpCacheAddressType (1 = ip, four bytes; 20 = ipv6, sixteen). Read as text
// it is four bytes of garbage, which is why the type column is walked too.
const CDP = {
  cdpCacheAddressType: '1.3.6.1.4.1.9.9.23.1.2.1.1.3',
  cdpCacheAddress: '1.3.6.1.4.1.9.9.23.1.2.1.1.4',
  cdpCacheDeviceId: '1.3.6.1.4.1.9.9.23.1.2.1.1.6',
  cdpCacheDevicePort: '1.3.6.1.4.1.9.9.23.1.2.1.1.7',
  cdpCachePlatform: '1.3.6.1.4.1.9.9.23.1.2.1.1.8',
};

// CISCO-VTP-MIB vtpVlanTable — where Catalyst IOS publishes its VLANs. IOS
// implements no Q-BRIDGE-MIB, so dot1qVlanStaticName is empty there and this
// table is the only place the VLAN names are. Index <managementDomain>.<vlanId>.
// vtpVlanState 1 = operational. VLANs 1002-1005 are the reserved FDDI/Token
// Ring defaults every IOS switch lists; they carry no Ethernet traffic.
//
// The same list is what the per-VLAN forwarding table walk iterates: IOS keeps
// one BRIDGE-MIB table per VLAN and serves it only under community string
// indexing ("community@vlanId"; SNMPv3 context "vlan-<id>").
const CISCO_VTP = {
  vtpVlanState: '1.3.6.1.4.1.9.9.46.1.3.1.1.2',
  vtpVlanName: '1.3.6.1.4.1.9.9.46.1.3.1.1.4',
};

// IP-MIB (RFC 4293) — the ARP table of a router or an L3 switch. In a flat OT
// network the router's table sees every device on the segment, including the
// PLC nobody installed an agent next to.
//
// ipNetToPhysicalTable is the current table (IPv4 and IPv6), indexed
// <ifIndex>.<addressType>.<addressLength>.<address bytes…> — the address is a
// variable-length InetAddress, so its length is part of the index.
// ipNetToMediaTable is the deprecated IPv4-only one, indexed
// <ifIndex>.<a>.<b>.<c>.<d>, and still the only one plenty of gear implements.
const IP_MIB = {
  ipNetToPhysicalPhysAddress: '1.3.6.1.2.1.4.35.1.4',
  ipNetToPhysicalState: '1.3.6.1.2.1.4.35.1.7', // 5 = invalid, 7 = incomplete
  ipNetToMediaPhysAddress: '1.3.6.1.2.1.4.22.1.2',
  ipNetToMediaType: '1.3.6.1.2.1.4.22.1.4', // 2 = invalid
};

// ENTITY-MIB (RFC 6933) entPhysicalTable — what the box IS: model, serial,
// firmware. sysDescr says roughly the same thing as one vendor-formatted
// string; this says it as fields, per chassis, which is what an RMA or a
// warranty lookup needs. Indexed by entPhysicalIndex.
const ENTITY = {
  entPhysicalDescr: '1.3.6.1.2.1.47.1.1.1.1.2',
  entPhysicalClass: '1.3.6.1.2.1.47.1.1.1.1.5', // 3 = chassis, 9 = module
  entPhysicalName: '1.3.6.1.2.1.47.1.1.1.1.7',
  entPhysicalHardwareRev: '1.3.6.1.2.1.47.1.1.1.1.8',
  entPhysicalFirmwareRev: '1.3.6.1.2.1.47.1.1.1.1.9',
  entPhysicalSoftwareRev: '1.3.6.1.2.1.47.1.1.1.1.10',
  entPhysicalSerialNum: '1.3.6.1.2.1.47.1.1.1.1.11',
  entPhysicalMfgName: '1.3.6.1.2.1.47.1.1.1.1.12',
  entPhysicalModelName: '1.3.6.1.2.1.47.1.1.1.1.13',
};

// IF-MIB ifAdminStatus / ifOperStatus, as the MIB numbers them. An unlisted
// value becomes null at the call site rather than a guess: an unknown status is
// not a status.
const IF_OPER_STATUS = {
  1: 'up', 2: 'down', 3: 'testing', 4: 'unknown', 5: 'dormant', 6: 'notPresent', 7: 'lowerLayerDown',
};
const IF_ADMIN_STATUS = { 1: 'up', 2: 'down', 3: 'testing' };
const DUPLEX_STATUS = { 1: 'unknown', 2: 'half', 3: 'full' };

module.exports = {
  IF_MIB,
  SYSTEM,
  ETHERLIKE,
  BRIDGE,
  Q_BRIDGE,
  LLDP,
  CDP,
  CISCO_VTP,
  IP_MIB,
  ENTITY,
  IF_OPER_STATUS,
  IF_ADMIN_STATUS,
  DUPLEX_STATUS,
};
