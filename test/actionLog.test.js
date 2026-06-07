'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { createActionLog } = require('../src/actionLog');

test('the local action log redacts secrets and appends a line', () => {
  const lines = [];
  const log = createActionLog({ path: '/tmp/actions.log', fsImpl: { appendFileSync: (p, line) => lines.push(line) }, clock: () => 'T0' });
  log.log('update.start', { version: '0.3.0', token: 'TOPSECRET', signature: 'SIGBYTES' });
  assert.equal(lines.length, 1);
  assert.match(lines[0], /^T0 update\.start /);
  assert.match(lines[0], /"version":"0.3.0"/);
  assert.match(lines[0], /"token":"\[redacted\]"/);
  assert.match(lines[0], /"signature":"\[redacted\]"/);
  assert.doesNotMatch(lines[0], /TOPSECRET|SIGBYTES/); // never in cleartext
});

test('the action log is a no-op (and never throws) without a path', () => {
  const lines = [];
  const log = createActionLog({ path: '', fsImpl: { appendFileSync: (p, line) => lines.push(line) } });
  log.log('x', { a: 1 });
  assert.equal(lines.length, 0);
});

test('long values are capped', () => {
  const captured = [];
  const log = createActionLog({ path: '/x', fsImpl: { appendFileSync: (p, line) => captured.push(line) }, clock: () => 'T' });
  log.log('e', { detail: 'a'.repeat(500) });
  const parsed = JSON.parse(captured[0].slice('T e '.length));
  assert.ok(parsed.detail.length <= 201); // 200 + ellipsis
});
