'use strict';

// GATE · CROSS-REPO CONTRACT — blueeye-agent's half.
//
// The agent verifies two things it did not sign: release manifests and (when
// signed) privileged commands. Both are Ed25519 over canonicalize()'s bytes,
// produced on the server. If this repo's copy of canonicalize drifts, the agent
// stops being able to install ANY signed release — and because unsigned updates
// still work, the symptom is not "update failed" but "the fleet quietly stopped
// taking signed updates".
//
// It also keeps its own copy of the evidence allowlist, deliberately, as
// defense in depth. Defense in depth only works while both copies say the same
// thing. See test/gate/_contracts.js.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const {
  CANONICALIZE_DIGEST, CANONICALIZE_VECTORS, PROTOCOL_VERSION,
  EVIDENCE_ITEMS, digestOf,
} = require('./_contracts');

const { canonicalize } = require('../../src/release/canonicalize');
const { verifyManifest } = require('../../src/release/verifyManifest');
const protocol = require('../../src/protocol');
const { READ_ONLY_ITEMS, isAllowed } = require('../../src/evidenceCollector');

const CANONICALIZE_PATH = path.join(__dirname, '..', '..', 'src', 'release', 'canonicalize.js');

test('canonicalize produces the exact bytes a signed release is verified against', () => {
  for (const { input, expected } of CANONICALIZE_VECTORS) {
    assert.equal(
      canonicalize(input), expected,
      'canonicalize drifted. The server signs release manifests over these bytes — if the\n' +
      'agent produces different ones it can no longer install ANY signed release, and the\n' +
      `symptom is silent. Input: ${JSON.stringify(input)}`
    );
  }
});

test('the canonicalize implementation still matches the pinned cross-repo digest', () => {
  const actual = digestOf(fs.readFileSync(CANONICALIZE_PATH, 'utf8'));
  assert.equal(
    actual, CANONICALIZE_DIGEST,
    'src/release/canonicalize.js changed.\n' +
    'It is duplicated byte-for-byte in blueeye-server (src/lib/canonicalize.js) and\n' +
    'blueeye-licens (src/lib/canonicalize.js). Apply the SAME change there, then\n' +
    `update CANONICALIZE_DIGEST in all three copies of test/gate/_contracts.js to:\n  ${actual}`
  );
});

test('PROTOCOL_VERSION matches the pin the server is held to', () => {
  assert.equal(
    protocol.PROTOCOL_VERSION, PROTOCOL_VERSION,
    'src/protocol.js changed. blueeye-server/src/protocol.js must change with it, and\n' +
    'PROTOCOL_VERSION in all three copies of test/gate/_contracts.js must be updated.'
  );
});

test("the agent's own evidence allowlist matches the server's, so defense in depth still holds", () => {
  assert.deepEqual(
    [...READ_ONLY_ITEMS].sort(), EVIDENCE_ITEMS,
    'src/evidenceCollector.js READ_ONLY_ITEMS changed. The server keeps its own copy\n' +
    '(blueeye-server/src/evidence/commandAllowlist.js). An item the server sends but this\n' +
    'list omits is refused on every agent; an item this list keeps but the server dropped\n' +
    'is still collectable. Change both, then the pins.'
  );
  for (const name of ['reboot', 'iface.set', 'snmp.write', '../etc/passwd', '']) {
    assert.equal(isAllowed(name), false, `${name} must never be allowed`);
  }
});

// verifyManifest is the agent's whole defence against installing code it cannot
// authenticate — and against a signed COMMAND it cannot authenticate, since
// commandAuth.js reuses it. It must fail closed on every malformed input, and
// it must never throw: a throw inside the command dispatcher is an error reply,
// but a throw inside selfUpdate is a half-installed release.
test('verifyManifest accepts a genuine signature over the canonical bytes', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const manifest = { version: '0.32.1', sha256: 'a'.repeat(64) };
  const pem = publicKey.export({ type: 'spki', format: 'pem' });
  const sig = crypto.sign(null, Buffer.from(canonicalize(manifest), 'utf8'), privateKey).toString('base64');
  assert.equal(verifyManifest(manifest, sig, pem), true);
});

test('verifyManifest rejects a tampered manifest, a foreign key and a malformed signature — and never throws', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const { publicKey: foreign } = crypto.generateKeyPairSync('ed25519');
  const pem = publicKey.export({ type: 'spki', format: 'pem' });
  const foreignPem = foreign.export({ type: 'spki', format: 'pem' });
  const manifest = { version: '0.32.1', sha256: 'a'.repeat(64) };
  const sig = crypto.sign(null, Buffer.from(canonicalize(manifest), 'utf8'), privateKey).toString('base64');

  // The one that matters: swapping the tarball hash after signing.
  assert.equal(verifyManifest({ ...manifest, sha256: 'b'.repeat(64) }, sig, pem), false);
  assert.equal(verifyManifest(manifest, sig, foreignPem), false);

  for (const bad of [null, undefined, '', 'not-base64!!', 'AAAA', 123, {}]) {
    assert.equal(verifyManifest(manifest, bad, pem), false, `signature ${JSON.stringify(bad)} must be rejected`);
  }
  for (const bad of [null, undefined, '', 'not-a-key']) {
    assert.equal(verifyManifest(manifest, sig, bad), false, 'an unusable key is never "verified"');
  }
});
