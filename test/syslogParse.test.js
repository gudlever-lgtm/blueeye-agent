'use strict';

// Unit tests for the syslog line parser (src/syslog/parse.js) and the
// classifier that reads its output (src/syslog/classify.js).
//
// Both are pure, so every dialect a switch might speak is testable without
// binding a port or owning the switch. `receivedAt` is passed explicitly rather
// than read from the clock, which is what makes the year-resolution rule (a
// December stamp read in January) testable at all.

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { parseSyslogLine } = require('../src/syslog/parse');
const { classifySyslog, extractInterface, EVENT_TYPES, UNCLASSIFIED } = require('../src/syslog/classify');
const { maskSyslogMessage } = require('../src/syslog/mask');

// 2026-09-20T09:42:00Z — after every sample stamp below, so no year rollback.
const RECV = Date.UTC(2026, 8, 20, 9, 42, 0);

test('parses an RFC 3164 line from a Cisco switch', () => {
  const r = parseSyslogLine(
    '<186>Sep 20 09:41:09 sw-core-1 %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down',
    { receivedAt: RECV },
  );
  assert.equal(r.format, 'rfc3164');
  assert.equal(r.facility, 23); // 186 >> 3
  assert.equal(r.severity, 2); // 186 & 7
  assert.equal(r.severityName, 'crit');
  assert.equal(r.host, 'sw-core-1');
  assert.equal(r.tag, '%LINK-3-UPDOWN');
  assert.equal(r.message, 'Interface GigabitEthernet0/1, changed state to down');
  assert.equal(r.deviceTime.toISOString(), '2026-09-20T09:41:09.000Z');
});

test('parses an RFC 5424 line', () => {
  const r = parseSyslogLine(
    '<34>1 2026-09-20T09:41:09.123Z sw-core-1 sshd 1234 ID47 [origin ip="10.0.0.1"] Failed login',
    { receivedAt: RECV },
  );
  assert.equal(r.format, 'rfc5424');
  assert.equal(r.facility, 4);
  assert.equal(r.severity, 2);
  assert.equal(r.host, 'sw-core-1');
  assert.equal(r.tag, 'sshd');
  assert.equal(r.procId, '1234');
  assert.equal(r.msgId, 'ID47');
  assert.equal(r.message, 'Failed login');
  assert.equal(r.deviceTime.toISOString(), '2026-09-20T09:41:09.123Z');
});

test('RFC 5424 nil values become null, not the literal dash', () => {
  const r = parseSyslogLine('<34>1 2026-09-20T09:41:09Z - - - - - hello', { receivedAt: RECV });
  assert.equal(r.host, null);
  assert.equal(r.tag, null);
  assert.equal(r.procId, null);
  assert.equal(r.msgId, null);
  assert.equal(r.message, 'hello');
});

test('parses the Cisco dialect: sequence number, host first, sub-second stamp, zone', () => {
  const r = parseSyslogLine(
    '<189>4521: sw-acc-2: Sep 20 09:41:09.123 CEST: %SPANTREE-5-TOPOTRAP: Topology change on Gi0/24',
    { receivedAt: RECV },
  );
  assert.equal(r.host, 'sw-acc-2');
  assert.equal(r.tag, '%SPANTREE-5-TOPOTRAP');
  assert.equal(r.message, 'Topology change on Gi0/24');
  assert.equal(r.deviceTime.toISOString(), '2026-09-20T09:41:09.123Z');
});

test('a space-padded single-digit day parses', () => {
  const r = parseSyslogLine('<14>Sep  9 04:05:06 host tag: msg', { receivedAt: RECV });
  assert.equal(r.deviceTime.toISOString(), '2026-09-09T04:05:06.000Z');
});

test('a stamp far in the future belongs to the previous year', () => {
  // Received 2 January 2026; the device says 31 December. Without the rollback
  // the event would be filed 12 months ahead and vanish from every window.
  const jan = Date.UTC(2026, 0, 2, 0, 30, 0);
  const r = parseSyslogLine('<14>Dec 31 23:59:00 host tag: msg', { receivedAt: jan });
  assert.equal(r.deviceTime.getUTCFullYear(), 2025);
});

test('a line with a PRI but nothing else recognisable is still kept', () => {
  const r = parseSyslogLine('<14>something entirely custom', { receivedAt: RECV });
  assert.equal(r.format, 'pri-only');
  assert.equal(r.severity, 6);
  assert.equal(r.deviceTime, null);
  assert.equal(r.message, 'something entirely custom');
});

test('a line with no PRI is not syslog and returns null', () => {
  // Inventing a facility and severity would be worse than dropping the line:
  // a severity nobody measured cannot be filtered on honestly.
  assert.equal(parseSyslogLine('Sep 20 09:41:09 host tag: msg', { receivedAt: RECV }), null);
  assert.equal(parseSyslogLine('', { receivedAt: RECV }), null);
  assert.equal(parseSyslogLine('   ', { receivedAt: RECV }), null);
  assert.equal(parseSyslogLine(null, { receivedAt: RECV }), null);
  assert.equal(parseSyslogLine(12345, { receivedAt: RECV }), null);
});

test('an out-of-range PRI is refused rather than clamped', () => {
  assert.equal(parseSyslogLine('<999>Sep 20 09:41:09 h t: m', { receivedAt: RECV }), null);
  assert.equal(parseSyslogLine('<192>Sep 20 09:41:09 h t: m', { receivedAt: RECV }), null);
  // 191 is the largest legal value (facility 23, severity 7) and must pass.
  assert.equal(parseSyslogLine('<191>x', { receivedAt: RECV }).facility, 23);
});

test('a NUL-stuffed line does not break the parser', () => {
  const r = parseSyslogLine('<14>Sep 20 09:41:09 host tag: mes\0sage', { receivedAt: RECV });
  assert.equal(r.message, 'message');
});

// --- classification --------------------------------------------------------

test('classifies the faults a technician actually chases', () => {
  const cases = [
    ['<186>Sep 20 09:41:09 sw-core-1 %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down', 'link.down', 'GigabitEthernet0/1'],
    ['<186>Sep 20 09:41:30 sw-core-1 %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to up', 'link.up', 'GigabitEthernet0/1'],
    ['<189>Sep 20 09:41:12 sw-core-1 %OSPF-5-ADJCHG: Nbr 10.14.0.9 on Gi0/1 from FULL to DOWN', 'ospf.adjacency_lost', 'Gi0/1'],
    ['<189>Sep 20 09:45:12 sw-core-1 %OSPF-5-ADJCHG: Nbr 10.14.0.9 on Gi0/1 from LOADING to FULL', 'ospf.adjacency_up', 'Gi0/1'],
    ['<189>Sep 20 09:41:15 sw-acc-2 %SPANTREE-5-TOPOTRAP: Topology change on Gi0/24', 'stp.topology_change', 'Gi0/24'],
    ['<188>Sep 20 09:41:15 sw-acc-2 %PM-4-ERR_DISABLE: bpduguard error detected on Gi0/7', 'port.err_disabled', 'Gi0/7'],
    ['<188>Sep 20 09:41:15 sw-acc-2 %CDP-4-DUPLEX_MISMATCH: duplex mismatch discovered on Gi0/3', 'duplex.mismatch', 'Gi0/3'],
    ['<188>Sep 20 09:41:15 sw-acc-2 %SW_MATM-4-MACFLAP_NOTIF: Host 0011.2233.4455 in vlan 20 is flapping', 'mac.flapping', null],
    ['<189>Sep 20 09:41:15 rtr-1 %SYS-5-CONFIG_I: Configured from console by admin', 'config.changed', null],
    ['<38>Sep 20 09:41:15 fw-1 sshd: authentication failure for user root', 'auth.failure', null],
    ['<187>Sep 20 09:41:15 ups-1 upsd: on battery, 22 minutes remaining', 'ups.on_battery', null],
  ];
  for (const [line, expectedType, expectedIface] of cases) {
    const parsed = parseSyslogLine(line, { receivedAt: RECV });
    const { eventType, ifname } = classifySyslog(parsed);
    assert.equal(eventType, expectedType, `expected ${expectedType} for: ${line}`);
    assert.equal(ifname, expectedIface, `expected iface ${expectedIface} for: ${line}`);
  }
});

test('an unrecognised line is kept raw, never coerced to a neighbour', () => {
  const parsed = parseSyslogLine(
    '<190>Sep 20 09:41:15 sw-acc-2 %VENDOR-6-SOMETHING: a message we have never seen',
    { receivedAt: RECV },
  );
  assert.equal(classifySyslog(parsed).eventType, UNCLASSIFIED);
});

test('an interface is extracted even from an unclassified line', () => {
  // A line nobody recognises still belongs on that interface's timeline.
  const parsed = parseSyslogLine(
    '<190>Sep 20 09:41:15 sw-1 %VENDOR-6-ODD: counters reset on GigabitEthernet1/0/5',
    { receivedAt: RECV },
  );
  const r = classifySyslog(parsed);
  assert.equal(r.eventType, UNCLASSIFIED);
  assert.equal(r.ifname, 'GigabitEthernet1/0/5');
});

test('classify survives junk input', () => {
  for (const bad of [null, undefined, 42, 'string', {}]) {
    assert.equal(classifySyslog(bad).eventType, UNCLASSIFIED);
  }
});

test('interface extraction covers the vendor spellings', () => {
  assert.equal(extractInterface('on TenGigabitEthernet1/0/1 something'), 'TenGigabitEthernet1/0/1');
  assert.equal(extractInterface('port Gi0/1 down'), 'Gi0/1');
  assert.equal(extractInterface('interface ge-0/0/1 flapped'), 'ge-0/0/1');
  assert.equal(extractInterface('link eth0 lost carrier'), 'eth0');
  assert.equal(extractInterface('Port-channel12 member left'), 'Port-channel12');
  assert.equal(extractInterface('nothing here'), null);
  assert.equal(extractInterface(null), null);
});

test('the exported event-type list is the table, deduped and sorted', () => {
  assert.ok(EVENT_TYPES.includes('link.down'));
  assert.ok(EVENT_TYPES.includes(UNCLASSIFIED));
  assert.deepEqual([...EVENT_TYPES].sort(), [...EVENT_TYPES]);
  assert.equal(new Set(EVENT_TYPES).size, EVENT_TYPES.length);
});

// --- masking ---------------------------------------------------------------

test('credentials are redacted before the line leaves the agent', () => {
  assert.equal(
    maskSyslogMessage('login with password hunter2 failed'),
    'login with password [redacted] failed',
  );
  assert.equal(maskSyslogMessage('snmp community public'), 'snmp community [redacted]');
  assert.equal(maskSyslogMessage('Authorization: Basic abcdef'), 'Authorization: [redacted]');
  assert.equal(
    maskSyslogMessage('token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K'),
    'token [redacted]',
  );
});

test('IP addresses survive masking, because in syslog they ARE the message', () => {
  // The server masks IPs out of device CONFIG. Doing it here would leave a line
  // that says a neighbour went down and refuses to say which one.
  const msg = 'Nbr 10.14.0.9 on Gi0/1 from FULL to DOWN';
  assert.equal(maskSyslogMessage(msg), msg);
});

test('masking leaves ordinary text untouched and survives junk', () => {
  assert.equal(maskSyslogMessage('Interface Gi0/1 changed state to down'), 'Interface Gi0/1 changed state to down');
  assert.equal(maskSyslogMessage(''), '');
  assert.equal(maskSyslogMessage(null), null);
  assert.equal(maskSyslogMessage(undefined), undefined);
});
