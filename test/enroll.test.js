'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { startFakeServer } = require('../test-support/fakeServer');
const { ensureToken } = require('../src/bootstrap');
const { silentLogger } = require('../src/logger');

const systemInfo = { hostname: 'test-host', platform: 'linux', arch: 'x64' };

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'blueeye-agent-enroll-'));
}

test('ensureToken enrolls, stores token (0600) and clears the code', async () => {
  const server = await startFakeServer({ acceptCode: 'good-code', issuedToken: 'tok-xyz', issuedAgentId: 55 });
  try {
    const dir = tmpDir();
    const configPath = path.join(dir, 'config.json');
    const tokenPath = path.join(dir, '.blueeye-agent', 'token');
    fs.writeFileSync(
      configPath,
      JSON.stringify({ serverUrl: server.url, enrollmentCode: 'good-code', tokenPath })
    );
    const config = { configPath, serverUrl: server.url, enrollmentCode: 'good-code', tokenPath };

    const creds = await ensureToken({ config, systemInfo, logger: silentLogger });

    assert.equal(creds.token, 'tok-xyz');
    assert.equal(creds.agentId, 55);
    assert.equal(fs.statSync(tokenPath).mode & 0o777, 0o600); // restrictive perms
    const cfgAfter = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    assert.equal('enrollmentCode' in cfgAfter, false); // code cleared
    assert.equal(server.enrollments.length, 1);
    assert.equal(server.enrollments[0].hostname, 'test-host'); // system info sent
    assert.equal(server.enrollments[0].arch, 'x64');
  } finally {
    await server.close();
  }
});

test('ensureToken skips enrollment when a token already exists', async () => {
  const server = await startFakeServer();
  try {
    const dir = tmpDir();
    const tokenPath = path.join(dir, 'token');
    fs.writeFileSync(tokenPath, JSON.stringify({ agentId: 9, token: 'existing-token' }));
    const config = {
      configPath: path.join(dir, 'config.json'),
      serverUrl: server.url,
      enrollmentCode: 'good-code',
      tokenPath,
    };

    const creds = await ensureToken({ config, systemInfo, logger: silentLogger });

    assert.equal(creds.token, 'existing-token');
    assert.equal(server.enrollments.length, 0); // never contacted enroll
  } finally {
    await server.close();
  }
});

test('ensureToken throws (no retry) when the code is rejected', async () => {
  const server = await startFakeServer({ acceptCode: 'good-code' });
  try {
    const dir = tmpDir();
    const config = {
      configPath: path.join(dir, 'config.json'),
      serverUrl: server.url,
      enrollmentCode: 'WRONG-CODE',
      tokenPath: path.join(dir, 'token'),
    };
    await assert.rejects(
      ensureToken({ config, systemInfo, logger: silentLogger }),
      (err) => err.code === 'ENROLL_FAILED'
    );
  } finally {
    await server.close();
  }
});

test('ensureToken throws when there is neither a token nor a code', async () => {
  const dir = tmpDir();
  const config = {
    configPath: path.join(dir, 'config.json'),
    serverUrl: 'http://127.0.0.1:1',
    enrollmentCode: null,
    tokenPath: path.join(dir, 'token'),
  };
  await assert.rejects(
    ensureToken({ config, systemInfo, logger: silentLogger }),
    (err) => err.code === 'NO_CREDENTIALS'
  );
});
