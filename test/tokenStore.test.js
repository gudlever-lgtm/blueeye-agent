'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { readToken, saveToken } = require('../src/tokenStore');

function tmpTokenPath() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'blueeye-agent-tok-'));
  // nested dir to also exercise mkdir -p
  return path.join(dir, 'data', 'token');
}

test('saveToken writes with 0600 permissions and readToken reads it back', () => {
  const tokenPath = tmpTokenPath();
  saveToken(tokenPath, { agentId: 7, token: 'secret-token' });

  const mode = fs.statSync(tokenPath).mode & 0o777;
  assert.equal(mode, 0o600);

  assert.deepEqual(readToken(tokenPath), { agentId: 7, token: 'secret-token' });
});

test('readToken returns null when the file is missing', () => {
  assert.equal(readToken(path.join(os.tmpdir(), `missing-${Date.now()}`)), null);
});

test('readToken returns null on a malformed file', () => {
  const tokenPath = tmpTokenPath();
  fs.mkdirSync(path.dirname(tokenPath), { recursive: true });
  fs.writeFileSync(tokenPath, 'not-json');
  assert.equal(readToken(tokenPath), null);
});
