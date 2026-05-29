'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { loadConfig, clearEnrollmentCode } = require('../src/config');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'blueeye-agent-cfg-'));
}

test('loadConfig merges file then env (env wins)', () => {
  const configPath = path.join(tmpDir(), 'config.json');
  fs.writeFileSync(
    configPath,
    JSON.stringify({ serverUrl: 'http://file:1', enrollmentCode: 'fc', tokenPath: '/t/tok', heartbeatMs: 5000 })
  );

  const cfg = loadConfig({
    env: { BLUEEYE_AGENT_CONFIG: configPath, BLUEEYE_SERVER_URL: 'http://env:2' },
  });

  assert.equal(cfg.serverUrl, 'http://env:2'); // env overrides file
  assert.equal(cfg.enrollmentCode, 'fc'); // from file
  assert.equal(cfg.tokenPath, '/t/tok'); // from file
  assert.equal(cfg.heartbeatMs, 5000);
});

test('loadConfig falls back to defaults without a file', () => {
  const configPath = path.join(tmpDir(), 'absent.json');
  const cfg = loadConfig({ env: { BLUEEYE_AGENT_CONFIG: configPath } });

  assert.equal(cfg.serverUrl, 'http://localhost:3000');
  assert.equal(cfg.enrollmentCode, null);
  assert.ok(cfg.tokenPath.endsWith(path.join('.blueeye-agent', 'token')));
  assert.equal(cfg.backoff.factor, 2);
});

test('clearEnrollmentCode removes only the code, preserving other fields', () => {
  const configPath = path.join(tmpDir(), 'config.json');
  fs.writeFileSync(
    configPath,
    JSON.stringify({ serverUrl: 'http://x', enrollmentCode: 'secret', tokenPath: '/t' })
  );
  const cfg = loadConfig({ env: { BLUEEYE_AGENT_CONFIG: configPath } });

  assert.equal(clearEnrollmentCode(cfg), true);

  const after = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  assert.equal('enrollmentCode' in after, false);
  assert.equal(after.serverUrl, 'http://x');
  assert.equal(after.tokenPath, '/t');
});

test('clearEnrollmentCode is a no-op when there is no config file', () => {
  const cfg = loadConfig({ env: { BLUEEYE_AGENT_CONFIG: path.join(tmpDir(), 'none.json') } });
  assert.equal(clearEnrollmentCode(cfg), false);
});
