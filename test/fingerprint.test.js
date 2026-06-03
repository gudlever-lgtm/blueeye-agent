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
