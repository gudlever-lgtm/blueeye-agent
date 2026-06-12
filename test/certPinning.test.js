'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { X509Certificate } = require('crypto');

const crypto = require('crypto');

const { requestJson, makePinnedFetch, checkPin } = require('../src/httpsClient');
const { createAgentClient } = require('../src/agentClient');
const { runEnroll } = require('../src/cli');
const { readToken } = require('../src/tokenStore');
const { runSpeedtest } = require('../src/speedtest');
const { createSelfUpdater } = require('../src/selfUpdate');
const { canonicalize } = require('../src/release/canonicalize');
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

// ---- makePinnedFetch fetch-compatibility (binary + headers) ----------------
// selfUpdate and speedtest run through the pinned fetch on hardened deployments
// and need arrayBuffer()/headers.get() plus byte-exact bodies in both
// directions — these are the regression tests for that contract.

// Every byte value 0x00-0xFF: any utf8 round-trip would mangle 0x80-0xFF.
const ALL_BYTES = Buffer.from(Array.from({ length: 256 }, (_, i) => i));

test('makePinnedFetch downloads binary byte-exactly and exposes response headers', async () => {
  const server = await tlsServer({ agentSource: ALL_BYTES });
  try {
    const f = makePinnedFetch(REAL_FP);
    const res = await f(`${server.url}/enroll/agent-source.tgz`);
    assert.equal(res.ok, true);
    assert.equal(res.headers.get('Content-Type'), 'application/gzip'); // case-insensitive lookup
    assert.equal(res.headers.get('x-missing-header'), null);
    const got = Buffer.from(await res.arrayBuffer());
    assert.deepEqual(got, ALL_BYTES); // byte-exact, no utf8 mangling
  } finally {
    await server.close();
  }
});

test('makePinnedFetch uploads a Buffer body verbatim (no JSON re-encoding)', async () => {
  const server = await tlsServer({ validTokens: ['tok'] });
  try {
    const payload = crypto.randomBytes(4096);
    const f = makePinnedFetch(REAL_FP);
    const res = await f(`${server.url}/speedtest/upload`, {
      method: 'POST',
      headers: { Authorization: 'Bearer tok', 'Content-Type': 'application/octet-stream' },
      body: payload,
    });
    assert.equal(res.ok, true);
    // The server counted exactly the bytes we sent — a JSON.stringify(Buffer)
    // accident would inflate this several-fold.
    assert.deepEqual(await res.json(), { bytes: 4096 });
  } finally {
    await server.close();
  }
});

test('runSpeedtest measures end-to-end over a pinned TLS connection', async () => {
  const server = await tlsServer({ validTokens: ['tok'] });
  try {
    const r = await runSpeedtest({ serverUrl: server.url, token: 'tok', bytes: 64 * 1024, fetchImpl: makePinnedFetch(REAL_FP) });
    assert.equal(r.ok, true, r.detail || 'speed test failed');
    assert.equal(r.downBytes, 64 * 1024);
    assert.equal(r.upBytes, 64 * 1024);
    assert.ok(r.downMbps > 0 && r.upMbps > 0);
  } finally {
    await server.close();
  }
});

test('selfUpdate verifies a legacy source bundle downloaded through a pinned fetch', async () => {
  const tarball = Buffer.concat([ALL_BYTES, Buffer.from('agent-source')]);
  const sha = crypto.createHash('sha256').update(tarball).digest('hex');
  const server = await tlsServer({ agentSource: tarball });
  try {
    const writes = [];
    const fsImpl = {
      mkdtempSync: () => '/tmp/blueeye-update-pin',
      writeFileSync: (p, buf) => writes.push({ p, buf }),
      rmSync() {},
    };
    const updater = createSelfUpdater({ installDir: '/opt/x', exec: () => ({ status: 0 }), fsImpl, logger: silentLogger });
    const out = await updater.update({ serverUrl: server.url, token: 'tok', expectedSha: sha, fetchImpl: makePinnedFetch(REAL_FP) });
    assert.equal(out.ok, true);
    assert.equal(out.sha, sha); // checksum over the bytes that travelled pinned
    assert.deepEqual(writes[0].buf, tarball); // written to disk byte-exactly
  } finally {
    await server.close();
  }
});

test('selfUpdate verifies a SIGNED release downloaded through a pinned fetch (manifest headers)', async () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' });
  const tarball = Buffer.concat([ALL_BYTES, Buffer.from('signed-release')]);
  const manifest = { version: '9.9.9', sha256: crypto.createHash('sha256').update(tarball).digest('hex'), size: tarball.length };
  const signature = crypto.sign(null, Buffer.from(canonicalize(manifest)), privateKey).toString('base64');
  const server = await tlsServer({
    agentRelease: { buffer: tarball, version: manifest.version, signature, manifestB64: Buffer.from(JSON.stringify(manifest)).toString('base64') },
  });
  try {
    const fsImpl = { mkdtempSync: () => '/tmp/blueeye-update-pin2', writeFileSync() {}, rmSync() {} };
    const updater = createSelfUpdater({ installDir: '/opt/x', exec: () => ({ status: 0 }), fsImpl, logger: silentLogger });
    const out = await updater.update({
      serverUrl: server.url, token: 'tok', expectedVersion: '9.9.9',
      signature, publicKey: pubPem, fetchImpl: makePinnedFetch(REAL_FP),
    });
    assert.equal(out.ok, true);
    assert.equal(out.version, '9.9.9'); // read from the X-Release-Manifest header
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
