'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const { verifyManifest } = require('../src/release/verifyManifest');

// End-to-end: scripts/sign-release.js must produce a manifest + signature that
// the agent's own verifier (and therefore the server's identical verifyProof)
// accepts — proving the build-host signing and the install-time verification
// agree byte-for-byte.
test('scripts/sign-release.js signs a tarball so the agent verifier accepts it', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const keyB64 = Buffer.from(privateKey.export({ type: 'pkcs8', format: 'pem' })).toString('base64');
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' });

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'blueeye-sign-'));
  try {
    const tgz = path.join(dir, 'blueeye-agent-0.9.0.tgz');
    const bytes = Buffer.from('pretend-this-is-a-gzipped-agent');
    fs.writeFileSync(tgz, bytes);

    execFileSync('node', ['scripts/sign-release.js', tgz, '0.9.0'], {
      cwd: path.join(__dirname, '..'),
      env: { ...process.env, AGENT_RELEASE_SIGNING_KEY: keyB64 },
      stdio: 'ignore',
    });

    const manifest = JSON.parse(fs.readFileSync(`${tgz}.manifest.json`, 'utf8'));
    const signature = fs.readFileSync(`${tgz}.sig`, 'utf8').trim();

    assert.equal(manifest.version, '0.9.0');
    assert.equal(manifest.size, bytes.length);
    assert.equal(manifest.sha256, crypto.createHash('sha256').update(bytes).digest('hex'));
    assert.equal(verifyManifest(manifest, signature, pubPem), true);
    // Wrong key must NOT verify.
    const otherPub = crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' });
    assert.equal(verifyManifest(manifest, signature, otherPub), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
