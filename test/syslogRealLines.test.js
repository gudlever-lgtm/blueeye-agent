'use strict';

// Syslog lines that were not written for this codebase: datagrams captured
// from util-linux logger and rsyslog, and Cisco/Juniper text copied from
// vendor-published sources (test/fixtures/syslog/README.md). Each line runs the
// agent's whole line path — parse → classify → mask — and is checked against
// the "# expect:" annotation above it in the fixture.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { parseSyslogLine } = require('../src/syslog/parse');
const { classifySyslog, EVENT_TYPES } = require('../src/syslog/classify');
const { maskSyslogMessage } = require('../src/syslog/mask');

const RECEIVED_AT = Date.UTC(2026, 8, 24, 2, 0, 0);
const DIR = path.join(__dirname, 'fixtures', 'syslog');

// Reads a fixture into [{ line, expect, lineNo }]. "# expect: k=v k2="a b""
// applies to the next non-comment line.
function loadFixture(name) {
  const out = [];
  let pending = null;
  fs.readFileSync(path.join(DIR, name), 'utf8').split('\n').forEach((text, i) => {
    if (!text) return;
    if (text.startsWith('#')) {
      const m = /^# expect:\s*(.*)$/.exec(text);
      if (m) {
        pending = {};
        for (const kv of m[1].matchAll(/(\w+)=(?:"([^"]*)"|(\S+))/g)) pending[kv[1]] = kv[2] ?? kv[3];
      }
      return;
    }
    out.push({ line: text, expect: pending || {}, lineNo: i + 1 });
    pending = null;
  });
  return out;
}

function check(entry, where) {
  const { line, expect: want } = entry;
  const p = parseSyslogLine(line, { receivedAt: RECEIVED_AT });
  assert.ok(p, `${where}: parsed at all`);
  const c = classifySyslog(p);
  const masked = maskSyslogMessage(p.message);

  // Invariants that hold for every real line.
  assert.equal(p.raw, line.trim(), where);
  assert.ok(Number.isInteger(p.facility) && p.facility >= 0 && p.facility <= 23, where);
  assert.ok(Number.isInteger(p.severity) && p.severity >= 0 && p.severity <= 7, where);
  assert.equal(Number(/^<(\d+)>/.exec(line)[1]), p.facility * 8 + p.severity, `${where}: PRI round-trips`);
  assert.ok(typeof p.message === 'string' && p.message.length > 0, `${where}: a message survives`);
  assert.ok(!p.message.startsWith('<'), `${where}: PRI not left in the message`);
  if (p.deviceTime) assert.ok(!Number.isNaN(p.deviceTime.getTime()), `${where}: a device time is a real date`);
  assert.ok(EVENT_TYPES.includes(c.eventType), where);
  if (p.tag) assert.ok(!/^\d{4}-\d{2}-\d{2}T/.test(p.tag), `${where}: a timestamp is never the tag`);

  // The annotated expectations.
  const eq = (key, actual) => {
    if (!(key in want)) return;
    const expected = want[key] === 'null' ? null : want[key];
    assert.equal(actual == null ? null : String(actual), expected, `${where}: ${key}`);
  };
  eq('format', p.format);
  eq('facility', p.facility);
  eq('severity', p.severity);
  eq('host', p.host);
  eq('tag', p.tag);
  eq('procId', p.procId);
  eq('msgId', p.msgId);
  eq('message', p.message);
  eq('time', p.deviceTime ? p.deviceTime.toISOString() : null);
  eq('eventType', c.eventType);
  eq('ifname', c.ifname);
  // Masking: a named secret is gone, metadata named by `keep` survives it.
  if (want.secret) {
    assert.ok(p.message.includes(want.secret), `${where}: fixture really carries the secret`);
    assert.ok(!masked.includes(want.secret), `${where}: secret masked`);
    assert.match(masked, /\[redacted\]/);
  }
  if (want.keep) assert.ok(masked.includes(want.keep), `${where}: ${want.keep} kept through masking`);
}

for (const file of ['real-captured.txt', 'vendor-documented.txt', 'cisco-shapes.txt']) {
  const entries = loadFixture(file);

  test(`${file}: every line is annotated`, () => {
    assert.ok(entries.length >= 7, `${entries.length} lines`);
    for (const e of entries) assert.ok(Object.keys(e.expect).length > 0, `${file}:${e.lineNo} has an # expect:`);
  });

  for (const e of entries) {
    test(`${file}:${e.lineNo} ${e.line.slice(0, 70)}`, () => check(e, `${file}:${e.lineNo}`));
  }
}

test('one rsyslog message in all three stock templates parses to the same host/tag/pid/message', () => {
  const cron = loadFixture('real-captured.txt').filter((e) => /CRON/.test(e.line))
    .map((e) => parseSyslogLine(e.line, { receivedAt: RECEIVED_AT }));
  assert.equal(cron.length, 3);
  for (const p of cron) {
    assert.equal(p.host, 'vm');
    assert.equal(p.tag, 'CRON');
    assert.equal(p.procId, '15734');
    assert.equal(p.message, '(root) CMD (run-parts /etc/cron.hourly)');
    assert.equal(p.facility, 9);
    assert.equal(p.severity, 6);
  }
});

test('a real linkDown pair (LINEPROTO then LINK) lands on one interface', () => {
  const lines = loadFixture('vendor-documented.txt').map((e) => e.line).filter((l) => /GigabitEthernet1\/0\/5/.test(l));
  const rows = lines.map((l) => classifySyslog(parseSyslogLine(l, { receivedAt: RECEIVED_AT })));
  assert.equal(rows.length, 2);
  assert.deepEqual(rows.map((r) => [r.eventType, r.ifname]), [
    ['link.down', 'GigabitEthernet1/0/5'], ['link.down', 'GigabitEthernet1/0/5'],
  ]);
});

// The generic "interface … down" wording rule: its window was 40 characters,
// and "Interface GigabitEthernet1/0/11, changed state to down" puts 41 between
// the two words. Classified as the MESSAGE alone (no Cisco mnemonic anywhere)
// so only the generic rule can match.
test('generic link wording reaches a long interface name, but never across a sentence', () => {
  const cls = (msg) => classifySyslog({ tag: 'ifmgr', message: msg }).eventType;
  assert.equal(cls('Interface GigabitEthernet1/0/11, changed state to down'), 'link.down');
  assert.equal(cls('Interface TenGigabitEthernet1/0/11, changed state to up'), 'link.up');
  // "down" in the next sentence is not this interface's state.
  assert.equal(cls('Interface GigabitEthernet1/0/11 renamed. Upstream went down'), 'syslog.raw');
  // Still bounded: 70 characters between the two words is too far.
  assert.equal(cls(`port 7 ${'x'.repeat(70)} down`), 'syslog.raw');
});

test('a Cisco mnemonic opening the message is only lifted when it is a real %FAC-SEV-MNEMONIC', () => {
  const c = (tag, message) => classifySyslog({ tag, message }).eventType;
  assert.equal(c('switch', '%LINK-3-UPDOWN: Interface Gi1/0/1, changed state to down'), 'link.down');
  assert.equal(c('sw-core-1', '%SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: x]'), 'auth.failure');
  // No leading %, no severity digit, or no colon: not a mnemonic, nothing lifted.
  assert.equal(c('switch', 'LINK-3-UPDOWN: something happened'), 'syslog.raw');
  assert.equal(c('switch', '%LINK-X-UPDOWN: something happened'), 'syslog.raw');
  assert.equal(c('switch', 'progress 100% SPANTREE-2-BLOCK here'), 'syslog.raw');
  // A tag that already IS the mnemonic wins over one quoted in the message.
  assert.equal(c('%SYS-5-CONFIG_I', '%LINK-3-UPDOWN: quoted'), 'config.changed');
});
