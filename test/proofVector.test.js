'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { canonicalize } = require('../src/release/canonicalize');
const { verifyManifest } = require('../src/release/verifyManifest');
const { PROTOCOL_VERSION } = require('../src/protocol');

// Golden cross-repo vector: the IDENTICAL fixture is committed to blueeye-server
// (src/license/__tests__/proof-vector.json) and blueeye-licens
// (test/proof-vector.json). The agent verifies SIGNED release manifests with the
// same canonicalize() + Ed25519 primitive as the license proof, so it MUST agree
// on these exact bytes — otherwise it would reject a validly-signed release. A
// failure here means the agent has drifted from the server/licens signed-bytes
// contract — fix the code, do not regenerate the fixture on one side.
const vector = require('./proof-vector.json');

test('agent canonicalize reproduces the shared golden vector byte-for-byte', () => {
  assert.equal(canonicalize(vector.payload), vector.canonical);
});

test('agent verifyManifest accepts the shared golden vector and rejects tampering', () => {
  assert.equal(verifyManifest(vector.payload, vector.signatureBase64, vector.publicKeyPem), true);
  const tampered = { ...vector.payload, zulu: 'changed' };
  assert.equal(verifyManifest(tampered, vector.signatureBase64, vector.publicKeyPem), false);
});

test('agent PROTOCOL_VERSION matches the shared contract vector', () => {
  assert.equal(PROTOCOL_VERSION, vector.protocolVersion);
});
