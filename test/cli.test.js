'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { parseArgs, runEnroll } = require('../src/cli');
const { readToken } = require('../src/tokenStore');
const { startFakeServer } = require('../test-support/fakeServer');
const { silentLogger } = require('../src/logger');

const systemInfo = { hostname: 'cli-host', platform: 'linux', arch: 'x64' };
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'blueeye-cli-'));
const cfg = (dir, over = {}) => ({ configPath: path.join(dir, 'config.json'), tokenPath: path.join(dir, 'token'), serverUrl: 'http://localhost:3000', serverCertFingerprint: '', enrollmentCode: null, ...over });

// ---- parseArgs -------------------------------------------------------------
test('parseArgs reads the command and flags', () => {
  assert.deepEqual(parseArgs(['node', 'x', 'enroll', '--code', 'C', '--server', 'http://s', '--fingerprint', 'F']),
    { cmd: 'enroll', opts: { code: 'C', server: 'http://s', fingerprint: 'F' } });
  assert.deepEqual(parseArgs(['node', 'x']), { cmd: null, opts: {} });
  assert.deepEqual(parseArgs(['node', 'x', '--help']), { cmd: null, opts: { help: true } });
  assert.equal(parseArgs(['node', 'x', 'enroll', '--force']).opts.force, true);
  assert.equal(parseArgs(['node', 'x', 'enroll', '--cert-fingerprint', 'Z']).opts.fingerprint, 'Z');
});

// ---- runEnroll over HTTP ---------------------------------------------------
test('runEnroll exchanges a code, stores the token, and persists serverUrl', async () => {
  const server = await startFakeServer({ acceptCode: 'good', issuedToken: 'tok-7', issuedAgentId: 7 });
  try {
    const dir = tmp();
    const config = cfg(dir);
    const res = await runEnroll({ opts: { code: 'good', server: server.url }, config, systemInfo, logger: silentLogger });
    assert.equal(res.ok, true);
    assert.equal(res.agentId, 7);
    const stored = readToken(config.tokenPath);
    assert.equal(stored.token, 'tok-7');
    assert.equal(fs.statSync(config.tokenPath).mode & 0o777, 0o600);
    // serverUrl persisted so the service reaches the right server.
    const written = JSON.parse(fs.readFileSync(config.configPath, 'utf8'));
    assert.equal(written.serverUrl, server.url);
    assert.equal(server.enrollments[0].hostname, 'cli-host');
  } finally {
    await server.close();
  }
});

test('runEnroll throws on an invalid code and stores NO token', async () => {
  const server = await startFakeServer({ acceptCode: 'good' });
  try {
    const dir = tmp();
    const config = cfg(dir);
    await assert.rejects(
      runEnroll({ opts: { code: 'WRONG', server: server.url }, config, systemInfo, logger: silentLogger }),
      (err) => err.code === 'ENROLL_FAILED'
    );
    assert.equal(readToken(config.tokenPath), null);
  } finally {
    await server.close();
  }
});

test('runEnroll requires a code', async () => {
  const dir = tmp();
  await assert.rejects(
    runEnroll({ opts: { server: 'http://localhost:3000' }, config: cfg(dir), systemInfo, logger: silentLogger }),
    (err) => err.code === 'NO_CODE'
  );
});

test('runEnroll is idempotent: skips when a token already exists', async () => {
  const server = await startFakeServer({ acceptCode: 'good' });
  try {
    const dir = tmp();
    const config = cfg(dir);
    fs.writeFileSync(config.tokenPath, JSON.stringify({ agentId: 3, token: 'existing' }));
    const res = await runEnroll({ opts: { code: 'good', server: server.url }, config, systemInfo, logger: silentLogger });
    assert.equal(res.already, true);
    assert.equal(server.enrollments.length, 0); // never contacted the server
  } finally {
    await server.close();
  }
});
