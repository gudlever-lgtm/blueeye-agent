'use strict';

// Maps a parsed syslog line onto an `event_type` and, where the line names one,
// an interface. Pure data + regex; no MIB files, no vendor SDK, no model.
//
// THE RULE THAT MATTERS: a line we do not recognise is classified `syslog.raw`
// and kept verbatim. It is never coerced to its nearest neighbour. A wrong
// event_type is worse than none, because the whole point of this table is that
// the correlator and the event timeline can trust the type — and a technician
// reading "ospf.adjacency_lost" on a line that said something else has been
// actively misled. The same rule the diagnose module applies to LLM output.
//
// The table is ordered: the first pattern that matches wins, so specific
// patterns are listed above the general ones they would otherwise be swallowed
// by (a Cisco %LINK-3-UPDOWN before the generic "link down").

// Interface names as the vendors spell them, longest-first so "GigabitEthernet"
// is not truncated to "Gi". Covers Cisco/Aruba/HPE long + short forms, Juniper
// (ge-0/0/1), Linux (eth0, ens192, bond0) and generic Port/Slot forms.
const IFACE_RE = new RegExp(
  '\\b(' +
  [
    'TenGigabitEthernet', 'GigabitEthernet', 'FastEthernet', 'FortyGigE',
    'HundredGigE', 'TwentyFiveGigE', 'Port-channel', 'PortChannel',
    'Bundle-Ether', 'Ethernet', 'Vlan', 'Loopback', 'Tunnel', 'Serial',
    'mgmt', 'Te', 'Gi', 'Fa', 'Eth', 'Po',
  ].join('|') +
  ')\\s?([0-9]+(?:[/:.][0-9]+)*)\\b' +
  '|\\b((?:ge|xe|et|em|fe|ae|irb)-[0-9]+/[0-9]+/[0-9]+(?:\\.[0-9]+)?)\\b' +
  '|\\b((?:eth|ens|enp|eno|bond|br|wlan)[0-9][0-9a-z.]*)\\b',
);

// Pulls the interface name out of a message, preserving the vendor's spelling.
// Returns null rather than guessing — an event with no interface is normal.
function extractInterface(text) {
  if (typeof text !== 'string') return null;
  const m = IFACE_RE.exec(text);
  if (!m) return null;
  if (m[1]) return `${m[1]}${m[2]}`;
  return m[3] || m[4] || null;
}

// Each rule: a type, a matcher against the TAG (cheap, vendor-specific and
// exact) and/or the MESSAGE (portable), and an optional `up` flag so the
// down/up pair of one mnemonic is one rule.
const RULES = [
  // --- physical link -------------------------------------------------------
  {
    type: 'link.down',
    tag: /^%?(LINK-\d-UPDOWN|LINEPROTO-\d-UPDOWN|IFNET-\d-IF_DOWN)/i,
    message: /changed state to (?:down|administratively down)|is down/i,
  },
  {
    type: 'link.up',
    tag: /^%?(LINK-\d-UPDOWN|LINEPROTO-\d-UPDOWN|IFNET-\d-IF_UP)/i,
    message: /changed state to up|is up/i,
  },
  { type: 'link.down', message: /\b(?:link|interface|port)\b[^.]{0,40}\b(?:went |is |changed to )?down\b/i },
  { type: 'link.up', message: /\b(?:link|interface|port)\b[^.]{0,40}\b(?:came |is |changed to )?up\b/i },

  // --- layer 2 -------------------------------------------------------------
  { type: 'stp.loop_detected', tag: /^%?(SPANTREE-\d-LOOPGUARD|SPANTREE-\d-BLOCK)/i },
  { type: 'stp.root_changed', tag: /^%?SPANTREE-\d-ROOTCHANGE/i },
  { type: 'stp.topology_change', tag: /^%?SPANTREE/i },
  { type: 'stp.topology_change', message: /spanning[- ]tree topology change/i },
  { type: 'mac.flapping', tag: /^%?(SW_MATM-\d-MACFLAP_NOTIF|MAC_MOVE|MACFLAP)/i },
  { type: 'mac.flapping', message: /\bmac (?:address )?(?:flap|move)\b/i },
  { type: 'port.err_disabled', tag: /^%?(PM-\d-ERR_DISABLE|ETHPORT-\d-IF_ERRDISABLE)/i },
  { type: 'port.err_disabled', message: /err-?disable/i },
  { type: 'duplex.mismatch', tag: /^%?CDP-\d-DUPLEX_MISMATCH/i },
  { type: 'duplex.mismatch', message: /duplex mismatch/i },
  { type: 'port.security_violation', tag: /^%?PORT_SECURITY/i },

  // --- routing -------------------------------------------------------------
  { type: 'ospf.adjacency_lost', tag: /^%?OSPF/i, message: /\bto (?:DOWN|INIT|EXSTART)\b|adjacency (?:lost|down)/i },
  { type: 'ospf.adjacency_up', tag: /^%?OSPF/i, message: /\bto FULL\b/i },
  { type: 'bgp.session_down', tag: /^%?BGP/i, message: /\b(?:down|closing|Idle|reset)\b/i },
  { type: 'bgp.session_up', tag: /^%?BGP/i, message: /\b(?:up|Established)\b/i },
  { type: 'hsrp.state_changed', tag: /^%?(HSRP|VRRP|STANDBY)/i },

  // --- addressing ----------------------------------------------------------
  { type: 'dhcp.pool_exhausted', message: /(?:dhcp|pool)[^.]{0,30}(?:exhaust|no (?:free|available) (?:address|lease))/i },
  { type: 'dhcp.conflict', message: /(?:address|ip) conflict|duplicate (?:ip )?address/i },
  { type: 'dhcp.pool_exhausted', tag: /^%?DHCPD?-\d-POOL/i },

  // --- security / access ---------------------------------------------------
  { type: 'auth.failure', tag: /^%?(SEC_LOGIN-\d-LOGIN_FAILED|AAA-\d-)/i },
  { type: 'auth.failure', message: /authentication failure|failed password|login failed|invalid user/i },
  { type: 'acl.denied', tag: /^%?SEC-\d-IPACCESSLOG/i },
  { type: 'vpn.negotiation_failed', message: /\b(?:ike|isakmp|ipsec)\b[^.]{0,40}\b(?:fail|error|no proposal|timeout)/i },

  // --- device health -------------------------------------------------------
  { type: 'device.rebooted', tag: /^%?SYS-\d-(RELOAD|RESTART)/i },
  { type: 'device.rebooted', message: /system (?:restarted|rebooted)|coldstart/i },
  { type: 'config.changed', tag: /^%?SYS-\d-CONFIG_I/i },
  { type: 'config.changed', message: /configured from (?:console|vty)/i },
  { type: 'power.supply_failed', message: /power supply[^.]{0,30}(?:fail|removed|not ok)/i },
  { type: 'fan.failed', message: /\bfan\b[^.]{0,30}(?:fail|removed|not ok)/i },
  { type: 'temperature.alarm', message: /(?:temperature|thermal)[^.]{0,30}(?:alarm|critical|exceed)/i },
  { type: 'ups.on_battery', message: /on battery|utility (?:power )?(?:fail|lost)/i },

  // --- capacity ------------------------------------------------------------
  { type: 'resource.exhausted', message: /\b(?:out of memory|memory (?:low|exhaust)|cpu (?:high|hog))/i },
];

const UNCLASSIFIED = 'syslog.raw';

// Classifies one parsed line. Returns { eventType, ifname }.
//
// `ifname` is extracted for EVERY line, classified or not: a raw line that
// happens to name an interface still belongs on that interface's timeline, and
// the extraction does not depend on recognising the event.
function classifySyslog(parsed) {
  if (!parsed || typeof parsed !== 'object') {
    return { eventType: UNCLASSIFIED, ifname: null };
  }
  const tag = typeof parsed.tag === 'string' ? parsed.tag : '';
  const message = typeof parsed.message === 'string' ? parsed.message : '';

  for (const rule of RULES) {
    if (rule.tag && !rule.tag.test(tag)) continue;
    if (rule.message && !rule.message.test(message)) continue;
    // A rule with neither matcher would match everything; the table has none,
    // and this guard keeps it that way if one is ever added by mistake.
    if (!rule.tag && !rule.message) continue;
    return { eventType: rule.type, ifname: extractInterface(message) };
  }
  return { eventType: UNCLASSIFIED, ifname: extractInterface(message) };
}

// The types this table can produce. Exported so the server's validation and the
// dashboard's filter list stay in step with the agent without duplicating the
// literals — and so a test can assert the two ends agree.
const EVENT_TYPES = Object.freeze(
  Array.from(new Set([UNCLASSIFIED, ...RULES.map((r) => r.type)])).sort(),
);

module.exports = { classifySyslog, extractInterface, EVENT_TYPES, UNCLASSIFIED };
