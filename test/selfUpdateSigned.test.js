'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

const { createSelfUpdater } = require('../src/selfUpdate');
const { canonicalize } = require('../src/release/canonicalize');

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const pubPem = publicKey.export({ type: 'spki', format: 'pem' });
const sign = (obj) => crypto.sign(null, Buffer.from(canonicalize(obj)), privateKey).toString('base64');
const sha = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
const quietLog = { info() {}, error() {}, warn() {} };

// A fake /enroll/agent-release.tgz response: the tarball bytes + the signed
// manifest and signature in headers, exactly as the server serves them.
function fakeRelease(tarball, manifest, sig) {
  return {
    ok: true,
    status: 200,
    headers: {
      get(name) {
        const k = String(name).toLowerCase();
        if (k === 'x-release-manifest') return Buffer.from(JSON.stringify(manifest)).toString('base64');
        if (k === 'x-release-signature') return sig;
        return null;
      },
    },
    arrayBuffer: async () => Uint8Array.from(tarball).buffer,
  };
}

// Records exec() calls (tar/npm) and reports success, so we can assert whether
// extraction was reached without touching the disk.
function recordingUpdater() {
  const calls = [];
  const updater = createSelfUpdater({
    exec: (cmd) => { calls.push(cmd); return { status: 0, stdout: '', stderr: '' }; },
    fsImpl: { mkdtempSync: () => '/tmp/u', writeFileSync() {}, rmSync() {} },
    logger: quietLog,
  });
  return { updater, calls };
}

test('a signed update verifies the signature, then extracts', async () => {
  const tarball = Buffer.from('agent-release-bytes');
  const manifest = { version: '0.3.0', sha256: sha(tarball), size: tarball.length };
  const sig = sign(manifest);
  const { updater, calls } = recordingUpdater();
  const r = await updater.update({
    serverUrl: 'http://s', token: 't', expectedVersion: '0.3.0', signature: sig, publicKey: pubPem,
    fetchImpl: async () => fakeRelease(tarball, manifest, sig),
  });
  assert.equal(r.ok, true);
  assert.ok(calls.includes('tar')); // it reached extraction
});

test('a signed update REFUSES a bad signature and never extracts', async () => {
  const tarball = Buffer.from('agent-release-bytes');
  const manifest = { version: '0.3.0', sha256: sha(tarball), size: tarball.length };
  const wrongSig = sign({ ...manifest, version: '9.9.9' }); // signature over a DIFFERENT manifest
  const { updater, calls } = recordingUpdater();
  await assert.rejects(
    () => updater.update({ serverUrl: 'http://s', token: 't', signature: wrongSig, publicKey: pubPem, fetchImpl: async () => fakeRelease(tarball, manifest, wrongSig) }),
    /signature did not verify/i
  );
  assert.equal(calls.includes('tar'), false);
});

test('a signed update refuses a tarball that does not match the signed sha256', async () => {
  const signedBytes = Buffer.from('the-signed-bytes');
  const manifest = { version: '0.3.0', sha256: sha(signedBytes), size: signedBytes.length };
  const sig = sign(manifest);
  const served = Buffer.from('TAMPERED-bytes'); // different bytes than the manifest binds
  const { updater, calls } = recordingUpdater();
  await assert.rejects(
    () => updater.update({ serverUrl: 'http://s', token: 't', signature: sig, publicKey: pubPem, fetchImpl: async () => fakeRelease(served, manifest, sig) }),
    /CHECKSUM_MISMATCH|checksum/i
  );
  assert.equal(calls.includes('tar'), false);
});

test('a signed update fails closed when no public key is configured', async () => {
  const tarball = Buffer.from('x');
  const manifest = { version: '0.3.0', sha256: sha(tarball), size: 1 };
  const sig = sign(manifest);
  const { updater } = recordingUpdater();
  await assert.rejects(
    () => updater.update({ serverUrl: 'http://s', token: 't', signature: sig, publicKey: '', fetchImpl: async () => fakeRelease(tarball, manifest, sig) }),
    /no release public key|NO_PUBLIC_KEY/i
  );
});

test('a signed update refuses a version mismatch vs. what was commanded', async () => {
  const tarball = Buffer.from('x');
  const manifest = { version: '0.3.0', sha256: sha(tarball), size: 1 };
  const sig = sign(manifest);
  const { updater } = recordingUpdater();
  await assert.rejects(
    () => updater.update({ serverUrl: 'http://s', token: 't', expectedVersion: '0.4.0', signature: sig, publicKey: pubPem, fetchImpl: async () => fakeRelease(tarball, manifest, sig) }),
    /version mismatch/i
  );
});

test('an unsigned update still uses the source bundle + sha256 (back-compat)', async () => {
  const tarball = Buffer.from('source-bundle');
  const { updater, calls } = recordingUpdater();
  const r = await updater.update({
    serverUrl: 'http://s', token: 't', expectedSha: sha(tarball),
    fetchImpl: async (url) => { assert.match(url, /agent-source\.tgz$/); return { ok: true, status: 200, headers: { get: () => null }, arrayBuffer: async () => Uint8Array.from(tarball).buffer }; },
  });
  assert.equal(r.ok, true);
  assert.ok(calls.includes('tar'));
});
