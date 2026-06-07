'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

const { verifyManifest } = require('../src/release/verifyManifest');
const { canonicalize } = require('../src/release/canonicalize');
const { resolveReleasePublicKey } = require('../src/release/publicKey');

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const pubPem = publicKey.export({ type: 'spki', format: 'pem' });
const sign = (obj) => crypto.sign(null, Buffer.from(canonicalize(obj)), privateKey).toString('base64');

test('verifyManifest accepts a valid signature and rejects tampering / wrong key', () => {
  const manifest = { version: '0.3.0', sha256: 'abc', size: 10 };
  const sig = sign(manifest);
  assert.equal(verifyManifest(manifest, sig, pubPem), true);

  assert.equal(verifyManifest({ ...manifest, sha256: 'xyz' }, sig, pubPem), false); // tampered payload
  assert.equal(verifyManifest(manifest, Buffer.from('nope').toString('base64'), pubPem), false); // garbage sig
  const otherPub = crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' });
  assert.equal(verifyManifest(manifest, sig, otherPub), false); // wrong key
  assert.equal(verifyManifest(null, sig, pubPem), false); // missing manifest
  assert.equal(verifyManifest(manifest, sig, ''), false); // missing key
});

test('resolveReleasePublicKey reads env PEM/base64, else returns empty for the placeholder', () => {
  assert.equal(resolveReleasePublicKey({ BLUEEYE_RELEASE_PUBLIC_KEY: pubPem }), pubPem);
  assert.equal(resolveReleasePublicKey({ BLUEEYE_RELEASE_PUBLIC_KEY: Buffer.from(pubPem).toString('base64') }), pubPem);
  assert.equal(resolveReleasePublicKey({}), ''); // embedded placeholder -> "not configured"
});
