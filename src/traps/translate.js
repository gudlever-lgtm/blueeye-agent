'use strict';

// Turns an SNMP trap into the same row shape a syslog line produces.
//
// A TABLE, NOT A MIB COMPILER. Parsing MIB files at runtime would mean shipping
// a parser, a MIB repository and a resolution order, and getting all three
// right for every vendor — to answer a question that ~40 well-known OIDs
// already cover. The trap OIDs that matter in a fault are standardised
// (SNMPv2-MIB, BRIDGE-MIB, OSPF-MIB, BGP4-MIB, UPS-MIB, ENTITY-SENSOR-MIB) or
// belong to a handful of vendors, and they do not change.
//
// AN UNKNOWN TRAP IS KEPT AS ITS OID, with its varbinds, and shown raw. It is
// NEVER guessed at, and never mapped to its nearest neighbour — the same rule
// the syslog classifier and the diagnose module follow. A trap labelled
// `link.down` that was actually something else has actively misled somebody.

// The two varbinds every SNMPv2 trap carries, before the trap-specific ones.
const OID_SYSUPTIME = '1.3.6.1.2.1.1.3.0';
const OID_TRAP_OID = '1.3.6.1.6.3.1.1.4.1.0';
const OID_TRAP_ENTERPRISE = '1.3.6.1.6.3.1.1.4.3.0';

// IF-MIB varbinds a link trap carries, so the interface can be named.
const OID_IF_INDEX = '1.3.6.1.2.1.2.2.1.1';
const OID_IF_DESCR = '1.3.6.1.2.1.2.2.1.2';
const OID_IF_ADMIN_STATUS = '1.3.6.1.2.1.2.2.1.7';
const OID_IF_OPER_STATUS = '1.3.6.1.2.1.2.2.1.8';

// severity is syslog-NUMERIC (0 emerg … 7 debug), so a trap and a syslog line
// sort and filter on one scale. The server narrows both to CRIT/WARN/INFO in
// exactly one place (deviceEventCatalog.severityBand).
const TRAPS = {
  // --- SNMPv2-MIB generic ---------------------------------------------------
  '1.3.6.1.6.3.1.1.5.1': { type: 'device.rebooted', severity: 3, text: 'coldStart — the device restarted' },
  '1.3.6.1.6.3.1.1.5.2': { type: 'device.rebooted', severity: 4, text: 'warmStart — the device reinitialised' },
  '1.3.6.1.6.3.1.1.5.3': { type: 'link.down', severity: 2, text: 'linkDown' },
  '1.3.6.1.6.3.1.1.5.4': { type: 'link.up', severity: 5, text: 'linkUp' },
  '1.3.6.1.6.3.1.1.5.5': { type: 'auth.failure', severity: 4, text: 'authenticationFailure — an SNMP request used the wrong community' },
  '1.3.6.1.6.3.1.1.5.6': { type: 'routing.neighbor_lost', severity: 3, text: 'egpNeighborLoss' },

  // --- BRIDGE-MIB (spanning tree) ------------------------------------------
  '1.3.6.1.2.1.17.0.1': { type: 'stp.root_changed', severity: 4, text: 'newRoot — this bridge became the spanning-tree root' },
  '1.3.6.1.2.1.17.0.2': { type: 'stp.topology_change', severity: 5, text: 'topologyChange — the spanning tree reconverged' },

  // --- OSPF-MIB -------------------------------------------------------------
  '1.3.6.1.2.1.14.16.2.2': { type: 'ospf.adjacency_lost', severity: 3, text: 'ospfNbrStateChange' },
  '1.3.6.1.2.1.14.16.2.1': { type: 'ospf.adjacency_lost', severity: 4, text: 'ospfVirtNbrStateChange' },
  '1.3.6.1.2.1.14.16.2.4': { type: 'ospf.config_error', severity: 4, text: 'ospfIfConfigError' },
  '1.3.6.1.2.1.14.16.2.6': { type: 'auth.failure', severity: 4, text: 'ospfIfAuthFailure' },
  '1.3.6.1.2.1.14.16.2.16': { type: 'ospf.adjacency_lost', severity: 3, text: 'ospfNssaTranslatorStatusChange' },

  // --- BGP4-MIB -------------------------------------------------------------
  '1.3.6.1.2.1.15.7.1': { type: 'bgp.session_up', severity: 5, text: 'bgpEstablished — a BGP session came up' },
  '1.3.6.1.2.1.15.7.2': { type: 'bgp.session_down', severity: 2, text: 'bgpBackwardTransition — a BGP session went down' },

  // --- UPS-MIB (RFC 1628) ---------------------------------------------------
  '1.3.6.1.2.1.33.2.1': { type: 'ups.on_battery', severity: 2, text: 'upsTrapOnBattery — running on battery' },
  '1.3.6.1.2.1.33.2.3': { type: 'ups.alarm', severity: 3, text: 'upsTrapAlarmEntryAdded' },
  '1.3.6.1.2.1.33.2.6': { type: 'ups.alarm', severity: 2, text: 'upsTrapShutdownImminent — shutdown imminent' },

  // --- ENTITY-SENSOR / ENTITY-MIB ------------------------------------------
  '1.3.6.1.2.1.99.0.1': { type: 'sensor.threshold', severity: 3, text: 'entSensorThresholdNotification' },
  '1.3.6.1.2.1.47.2.0.1': { type: 'device.hardware_changed', severity: 5, text: 'entConfigChange — hardware inventory changed' },

  // --- POWER-ETHERNET-MIB ---------------------------------------------------
  '1.3.6.1.2.1.105.0.1': { type: 'poe.port_changed', severity: 5, text: 'pethPsePortOnOffNotification' },
  '1.3.6.1.2.1.105.0.2': { type: 'poe.budget_exceeded', severity: 3, text: 'pethMainPowerUsageOnNotification — PoE budget threshold crossed' },

  // --- DISMAN-PING / RMON ---------------------------------------------------
  '1.3.6.1.2.1.16.0.1': { type: 'resource.threshold', severity: 4, text: 'risingAlarm — an RMON threshold was crossed' },
  '1.3.6.1.2.1.16.0.2': { type: 'resource.threshold', severity: 5, text: 'fallingAlarm — an RMON threshold cleared' },

  // --- Cisco (enterprise 9) -------------------------------------------------
  '1.3.6.1.4.1.9.9.41.2.0.1': { type: 'syslog.raw', severity: 5, text: 'clogMessageGenerated — a syslog message, delivered as a trap' },
  '1.3.6.1.4.1.9.9.43.2.0.1': { type: 'config.changed', severity: 5, text: 'ciscoConfigManEvent — the configuration was changed' },
  '1.3.6.1.4.1.9.9.13.3.0.1': { type: 'sensor.threshold', severity: 3, text: 'ciscoEnvMonShutdownNotification' },
  '1.3.6.1.4.1.9.9.13.3.0.2': { type: 'temperature.alarm', severity: 3, text: 'ciscoEnvMonTemperatureNotification' },
  '1.3.6.1.4.1.9.9.13.3.0.3': { type: 'sensor.threshold', severity: 3, text: 'ciscoEnvMonVoltageNotification' },
  '1.3.6.1.4.1.9.9.13.3.0.4': { type: 'fan.failed', severity: 3, text: 'ciscoEnvMonFanNotification' },
  '1.3.6.1.4.1.9.9.13.3.0.5': { type: 'power.supply_failed', severity: 2, text: 'ciscoEnvMonRedundantSupplyNotification' },
  '1.3.6.1.4.1.9.9.46.2.0.1': { type: 'vlan.trunk_changed', severity: 5, text: 'vtpConfigRevNumberError' },
  '1.3.6.1.4.1.9.9.215.2.0.1': { type: 'mac.flapping', severity: 4, text: 'cmnMacChangedNotification — a MAC moved between ports' },
  '1.3.6.1.4.1.9.9.315.0.0.1': { type: 'port.security_violation', severity: 3, text: 'cpsSecureMacAddrViolation — port security violation' },

  // --- HPE / Aruba (enterprise 11 / 47196) ---------------------------------
  '1.3.6.1.4.1.11.2.14.11.5.1.7.1.29.1': { type: 'stp.loop_detected', severity: 2, text: 'hpicfLoopProtectPortLoopDetected' },
  '1.3.6.1.4.1.11.2.14.11.5.1.7.1.29.2': { type: 'port.err_disabled', severity: 3, text: 'hpicfLoopProtectPortDisabled' },

  // --- Juniper (enterprise 2636) -------------------------------------------
  '1.3.6.1.4.1.2636.4.1.1': { type: 'device.hardware_changed', severity: 4, text: 'jnxPowerSupplyFailure' },
  '1.3.6.1.4.1.2636.4.1.3': { type: 'temperature.alarm', severity: 3, text: 'jnxOverTemperature' },
  '1.3.6.1.4.1.2636.4.1.4': { type: 'fan.failed', severity: 3, text: 'jnxFanFailure' },

  // --- MIKROTIK / generic vendor link notifications ------------------------
  '1.3.6.1.4.1.14988.1.1.14.1': { type: 'device.rebooted', severity: 4, text: 'mtxrHlCoreVoltage / device notification' },
};

const UNKNOWN_TYPE = 'syslog.raw';

// ifOperStatus / ifAdminStatus values, so a linkDown that is actually an
// administrative shutdown reads as one. "Somebody turned this port off" and
// "this port fell over" send a technician to two different places.
const IF_STATUS = { 1: 'up', 2: 'down', 3: 'testing', 4: 'unknown', 5: 'dormant', 6: 'notPresent', 7: 'lowerLayerDown' };

function toStr(v) {
  if (v == null) return null;
  if (Buffer.isBuffer(v)) {
    const text = v.toString('utf8').replace(/\0+$/, '');
    // eslint-disable-next-line no-control-regex
    return /^[\x20-\x7e]*$/.test(text) ? (text.trim() || null) : v.toString('hex');
  }
  const s = String(v).trim();
  return s || null;
}

function toNum(v) {
  // An integer varbind as bytes (Counter64, or any BER integer the decoder
  // leaves raw). ALL bytes, big-endian: reading only the first six read a
  // seven-byte Counter64 256x low — the same bug snmp/session.js had.
  if (Buffer.isBuffer(v)) {
    if (!v.length) return null;
    let n = 0n;
    for (const b of v) n = (n << 8n) | BigInt(b);
    return Number(n);
  }
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

// Strips a trailing instance suffix so a columnar OID matches its column.
// `1.3.6.1.2.1.2.2.1.1.10002` is ifIndex for interface 10002.
function columnOf(oid, base) {
  const o = String(oid || '');
  return o === base || o.startsWith(`${base}.`) ? o.slice(base.length + 1) || '0' : null;
}

// Pulls the trap identity out of the varbinds. SNMPv2c puts it in
// snmpTrapOID.0; a v1 trap that net-snmp has already converted carries the same
// varbind, so there is one path rather than two.
function trapOidOf(varbinds) {
  // A varbind list arrives from a decoder fed by an untrusted datagram, so an
  // entry can be anything — including null. Skipped, not thrown on: a
  // malformed trap must cost itself, never the receiver.
  for (const vb of Array.isArray(varbinds) ? varbinds : []) {
    if (vb && vb.oid === OID_TRAP_OID) return toStr(vb.value);
  }
  return null;
}

// Translates one decoded trap into the device-event row shape.
//
// `resolveIfName` is injected: the agent knows the interface names from its own
// SNMP topology poll (stage 02), so a trap saying "ifIndex 1" can be shown as
// "GigabitEthernet0/1". Without it the index is kept as-is rather than guessed.
function translateTrap({ varbinds = [], sourceIp, receivedAt, resolveIfName = null } = {}) {
  const vbs = Array.isArray(varbinds) ? varbinds : [];
  const trapOid = trapOidOf(vbs);

  const known = trapOid ? TRAPS[trapOid] : null;

  // Trap-specific varbinds: everything that is not the two every trap carries.
  const detailVarbinds = [];
  let ifIndex = null;
  let ifDescr = null;
  let operStatus = null;
  let adminStatus = null;
  let upTimeTicks = null;

  for (const vb of vbs) {
    if (!vb || typeof vb !== 'object') continue; // see the note in trapOidOf
    const oid = String(vb.oid || '');
    if (oid === OID_TRAP_OID || oid === OID_TRAP_ENTERPRISE) continue;
    if (oid === OID_SYSUPTIME) { upTimeTicks = toNum(vb.value); continue; }

    if (columnOf(oid, OID_IF_INDEX) != null) ifIndex = toNum(vb.value);
    else if (columnOf(oid, OID_IF_DESCR) != null) ifDescr = toStr(vb.value);
    else if (columnOf(oid, OID_IF_OPER_STATUS) != null) operStatus = toNum(vb.value);
    else if (columnOf(oid, OID_IF_ADMIN_STATUS) != null) adminStatus = toNum(vb.value);

    detailVarbinds.push({ oid, value: toStr(vb.value) });
    if (detailVarbinds.length >= 32) break; // a bounded record, not a transcript
  }

  // Name the interface from what stage 02 already polled off this device. A
  // resolver that does not know it returns null, and the index is shown
  // instead — an honest "ifIndex 1" beats a confident wrong name.
  let ifname = ifDescr;
  if (!ifname && ifIndex != null && typeof resolveIfName === 'function') {
    try { ifname = resolveIfName(ifIndex) || null; } catch { ifname = null; }
  }

  let eventType = known ? known.type : UNKNOWN_TYPE;
  let severity = known ? known.severity : 5;
  let summary;

  if (known) {
    const where = ifname ? ` on ${ifname}` : (ifIndex != null ? ` on ifIndex ${ifIndex}` : '');
    summary = `${known.text}${where}`;
    // A linkDown whose ifAdminStatus is also down is an administrative
    // shutdown, not a fault. Somebody turned this port off; that sends a
    // technician somewhere entirely different from a port that fell over.
    if (eventType === 'link.down' && adminStatus === 2) {
      eventType = 'link.admin_down';
      severity = 5;
      summary = `${known.text}${where} — administratively down`;
    } else if (eventType === 'link.down' && operStatus != null && IF_STATUS[operStatus]) {
      summary = `${known.text}${where} — now ${IF_STATUS[operStatus]}`;
    }
  } else {
    // Unknown: say what arrived, as it arrived. Never a guess.
    summary = trapOid ? `Unrecognised trap ${trapOid}` : 'Unrecognised trap (no trap OID)';
  }

  return {
    sourceIp,
    receivedAt: new Date(receivedAt).toISOString(),
    // A trap carries no wall-clock time of its own — only sysUpTime, which is
    // an uptime, not a date. NULL rather than a fabricated timestamp, and so
    // clock skew is null too, which is correct: there is no device clock to
    // compare against.
    deviceTime: null,
    clockSkewMs: null,
    transport: 'trap',
    facility: null,
    severity,
    eventType,
    host: null,
    tag: trapOid || null,
    ifname,
    summary: summary.slice(0, 512),
    raw: trapOid ? `snmpTrapOID=${trapOid}` : 'snmpTrap',
    detail: {
      trapOid: trapOid || null,
      upTimeTicks,
      varbinds: detailVarbinds,
    },
    occurrences: 1,
  };
}

// Exported so a test can assert the table's shape, and so the server's
// catalogue and this table can be compared rather than drifting.
const KNOWN_TRAP_OIDS = Object.freeze(Object.keys(TRAPS).sort());
const TRAP_EVENT_TYPES = Object.freeze(
  Array.from(new Set([UNKNOWN_TYPE, 'link.admin_down', ...Object.values(TRAPS).map((t) => t.type)])).sort(),
);

module.exports = {
  translateTrap,
  trapOidOf,
  TRAPS,
  KNOWN_TRAP_OIDS,
  TRAP_EVENT_TYPES,
  UNKNOWN_TYPE,
};
