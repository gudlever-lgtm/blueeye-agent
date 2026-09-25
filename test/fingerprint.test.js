'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { normalizeFingerprint } = require('../src/fingerprint');

test('normalizeFingerprint canonicalises valid SHA-256 inputs', () => {
  const hex = 'ab'.repeat(32); // 64 hex chars
  const colon = 'AB:'.repeat(31) + 'AB';
  assert.equal(normalizeFingerprint(hex), colon);
  assert.equal(normalizeFingerprint('AB:' + 'ab'.repeat(31)), colon);
  assert.equal(normalizeFingerprint('sha256:' + hex), colon);
  assert.equal(normalizeFingerprint('SHA-256 ' + hex), colon);
});

test('normalizeFingerprint rejects non-SHA-256 values', () => {
  assert.equal(normalizeFingerprint(''), '');
  assert.equal(normalizeFingerprint(null), '');
  assert.equal(normalizeFingerprint('ab:cd'), ''); // too short
  assert.equal(normalizeFingerprint('zz'.repeat(32)), ''); // non-hex
});

test('normalizeFingerprint is idempotent', () => {
  const once = normalizeFingerprint('ef'.repeat(32));
  assert.equal(normalizeFingerprint(once), once);
});

// Certificate ROTATION: a pin is to one leaf certificate, so the day the
// server's certificate is replaced every pinned agent fails closed — and the
// only thing that could fix it is the server it can no longer reach. Holding
// both pins across the renewal is the way out, so the list form has to work.
test('several pins are accepted so a certificate can be renewed', () => {
  const { normalizeFingerprints } = require('../src/fingerprint');
  const a = 'ab'.repeat(32);
  const b = 'cd'.repeat(32);
  assert.deepEqual(normalizeFingerprints(''), []);
  assert.equal(normalizeFingerprints(`${a},${b}`).length, 2);
  assert.equal(normalizeFingerprints(`${a} ${b}`).length, 2, 'whitespace separates too');
  assert.equal(normalizeFingerprints([a, a]).length, 1, 'duplicates collapse');
  assert.equal(normalizeFingerprints(`${a},nonsense`).length, 1, 'one bad entry never takes the good pin with it');
  assert.equal(normalizeFingerprints(a)[0], 'AB'.concat(':AB'.repeat(31)));
});

test('checkPin accepts any of the configured pins and refuses the rest', () => {
  const { checkPin } = require('../src/httpsClient');
  const a = 'ab'.repeat(32);
  const b = 'cd'.repeat(32);
  const check = checkPin([a, b]);
  assert.equal(check('h', { fingerprint256: b }), undefined, 'the next certificate is already trusted');
  assert.equal(check('h', { fingerprint256: a }), undefined, 'and so is the current one');
  const err = check('h', { fingerprint256: 'ef'.repeat(32) });
  assert.equal(err && err.code, 'CERT_FINGERPRINT_MISMATCH');
  assert.equal(checkPin('')('h', { fingerprint256: a }), undefined, 'no pin configured still accepts');
});

test('config reads a pin list and keeps the first for single-pin callers', () => {
  const { loadConfig } = require('../src/config');
  const a = 'ab'.repeat(32);
  const b = 'cd'.repeat(32);
  const cfg = loadConfig({ env: { BLUEEYE_SERVER_CERT_FINGERPRINT: `${a},${b}`, BLUEEYE_AGENT_CONFIG: '/nonexistent/blueeye.json' } });
  assert.equal(cfg.serverCertFingerprints.length, 2);
  assert.equal(cfg.serverCertFingerprint, cfg.serverCertFingerprints[0]);
});

test('an update window is evaluated in local time, and a wrapping one is not empty', () => {
  const { parseWindow, isWithinWindow } = require('../src/updateWindow');
  assert.deepEqual(parseWindow('02:00-04:00'), { startMin: 120, endMin: 240 });
  assert.equal(parseWindow('02:00-02:00'), null, 'a zero-length window is not "always"');
  assert.equal(parseWindow('nonsense'), null);
  assert.equal(parseWindow('25:00-26:00'), null);
  const at = (h, m = 0) => new Date(2026, 0, 15, h, m);
  assert.equal(isWithinWindow('02:00-04:00', at(3)), true);
  assert.equal(isWithinWindow('02:00-04:00', at(4)), false, 'the end is exclusive');
  assert.equal(isWithinWindow('22:00-04:00', at(23)), true, 'a window may wrap midnight');
  assert.equal(isWithinWindow('22:00-04:00', at(2)), true);
  assert.equal(isWithinWindow('22:00-04:00', at(12)), false);
  assert.equal(isWithinWindow('', at(12)), true, 'no window means no restriction');
});
