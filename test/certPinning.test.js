'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { X509Certificate } = require('crypto');

const { requestJson, makePinnedFetch, checkPin } = require('../src/httpsClient');
const { createAgentClient } = require('../src/agentClient');
const { runEnroll } = require('../src/cli');
const { readToken } = require('../src/tokenStore');
const { startFakeServer } = require('../test-support/fakeServer');
const { silentLogger } = require('../src/logger');
const selfsigned = require('../test-support/selfsigned');

const REAL_FP = new X509Certificate(selfsigned.cert).fingerprint256; // "AB:CD:…"
const WRONG_FP = 'ab'.repeat(32);
const systemInfo = { hostname: 'tls-host', platform: 'linux', arch: 'x64' };
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'blueeye-tls-'));

function tlsServer(opts = {}) {
  return startFakeServer({ tls: { key: selfsigned.key, cert: selfsigned.cert }, ...opts });
}

// ---- checkPin --------------------------------------------------------------
test('checkPin accepts a matching cert and rejects a mismatch', () => {
  const fakeCert = { fingerprint256: REAL_FP };
  assert.equal(checkPin(REAL_FP)('host', fakeCert), undefined);
  const err = checkPin(WRONG_FP)('host', fakeCert);
  assert.ok(err instanceof Error);
  assert.equal(err.code, 'CERT_FINGERPRINT_MISMATCH');
  // No pin configured -> accept anything.
  assert.equal(checkPin('')('host', fakeCert), undefined);
});

// ---- requestJson pinning over real HTTPS -----------------------------------
test('requestJson resolves over HTTPS with the correct pinned fingerprint', async () => {
  const server = await tlsServer({ certFingerprint: REAL_FP, publicUrl: 'https://blueeye.test' });
  try {
    const res = await requestJson({ url: `${server.url}/enroll/config`, fingerprint: REAL_FP });
    assert.equal(res.status, 200);
    assert.equal(res.json.certFingerprint, REAL_FP);
  } finally {
    await server.close();
  }
});

test('requestJson rejects over HTTPS when the fingerprint does not match', async () => {
  const server = await tlsServer();
  try {
    await assert.rejects(requestJson({ url: `${server.url}/enroll/config`, fingerprint: WRONG_FP }));
  } finally {
    await server.close();
  }
});

test('makePinnedFetch exposes a fetch-like shape', async () => {
  const server = await tlsServer({ certFingerprint: REAL_FP });
  try {
    const f = makePinnedFetch(REAL_FP);
    const res = await f(`${server.url}/enroll/config`);
    assert.equal(res.ok, true);
    const body = await res.json();
    assert.equal(body.certFingerprint, REAL_FP);
  } finally {
    await server.close();
  }
});

// ---- runEnroll cert pinning end-to-end -------------------------------------
test('runEnroll enrolls over HTTPS when the pinned fingerprint matches', async () => {
  const server = await tlsServer({ acceptCode: 'good', issuedToken: 'tok-tls', issuedAgentId: 12 });
  try {
    const dir = tmp();
    const config = { configPath: path.join(dir, 'c.json'), tokenPath: path.join(dir, 'token'), serverUrl: server.url, serverCertFingerprint: '' };
    const res = await runEnroll({ opts: { code: 'good', server: server.url, fingerprint: REAL_FP }, config, systemInfo, logger: silentLogger });
    assert.equal(res.ok, true);
    assert.equal(res.fingerprintPinned, true);
    assert.equal(readToken(config.tokenPath).token, 'tok-tls');
  } finally {
    await server.close();
  }
});

test('runEnroll REJECTS a server whose cert fingerprint mismatches (no token stored)', async () => {
  const server = await tlsServer({ acceptCode: 'good' });
  try {
    const dir = tmp();
    const config = { configPath: path.join(dir, 'c.json'), tokenPath: path.join(dir, 'token'), serverUrl: server.url, serverCertFingerprint: '' };
    await assert.rejects(
      runEnroll({ opts: { code: 'good', server: server.url, fingerprint: WRONG_FP }, config, systemInfo, logger: silentLogger })
    );
    assert.equal(readToken(config.tokenPath), null); // nothing persisted on failure
    assert.equal(server.enrollments.length, 0);
  } finally {
    await server.close();
  }
});

// ---- WebSocket pinning -----------------------------------------------------
const delay = (ms) => new Promise((r) => setTimeout(r, ms));

test('agentClient connects over wss when the pin matches', async () => {
  const server = await tlsServer({ issuedToken: 'ws-tok', validTokens: ['ws-tok'] });
  try {
    const client = createAgentClient({ serverUrl: server.url, token: 'ws-tok', logger: silentLogger, certFingerprint: REAL_FP, heartbeatMs: 10000, backoff: { baseMs: 50, maxMs: 200, factor: 2 } });
    await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('did not open')), 3000);
      client.on('open', () => { clearTimeout(t); resolve(); });
      client.start();
    });
    client.stop();
  } finally {
    await server.close();
  }
});

test('agentClient refuses a wss server whose cert does not match the pin', async () => {
  const server = await tlsServer({ issuedToken: 'ws-tok', validTokens: ['ws-tok'] });
  try {
    const client = createAgentClient({ serverUrl: server.url, token: 'ws-tok', logger: silentLogger, certFingerprint: WRONG_FP, heartbeatMs: 10000, backoff: { baseMs: 50, maxMs: 100, factor: 2 } });
    let opened = false;
    client.on('open', () => { opened = true; });
    client.start();
    await delay(700); // enough for a connect attempt (and a reconnect) to fail
    client.stop();
    assert.equal(opened, false);
  } finally {
    await server.close();
  }
});

test('runEnroll can discover the fingerprint via /enroll/config (trust-on-first-use)', async () => {
  const server = await tlsServer({ acceptCode: 'good', issuedToken: 'tok-tofu', issuedAgentId: 21 });
  try {
    const dir = tmp();
    const config = { configPath: path.join(dir, 'c.json'), tokenPath: path.join(dir, 'token'), serverUrl: server.url, serverCertFingerprint: '' };
    // requestImpl stands in for the (unpinned) discovery call, returning the fp;
    // the actual enroll POST is then pinned to it.
    const res = await runEnroll({
      opts: { code: 'good', server: server.url }, config, systemInfo, logger: silentLogger,
      requestImpl: async () => ({ status: 200, json: { certFingerprint: REAL_FP } }),
    });
    assert.equal(res.ok, true);
    assert.equal(res.fingerprintPinned, true);
    assert.equal(readToken(config.tokenPath).token, 'tok-tofu');
  } finally {
    await server.close();
  }
});
