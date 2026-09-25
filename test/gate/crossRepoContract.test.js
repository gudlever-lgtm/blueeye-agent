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
  EVIDENCE_ITEMS, FINGERPRINT_DIGEST, VENDOR_ROOT_PUBLIC_KEY, digestOf,
  UPDATE_WINDOW_DIGEST, VERSION_COMPARE_DIGEST,
} = require('./_contracts');

const { canonicalize } = require('../../src/release/canonicalize');
const { publicKeyFingerprint } = require('../../src/release/fingerprint');
const { EMBEDDED_VENDOR_ROOT_PUBLIC_KEY } = require('../../src/license/vendorRoot');
const { verifyManifest } = require('../../src/release/verifyManifest');
const protocol = require('../../src/protocol');
const { READ_ONLY_ITEMS, isAllowed } = require('../../src/evidenceCollector');

const CANONICALIZE_PATH = path.join(__dirname, '..', '..', 'src', 'release', 'canonicalize.js');
const FINGERPRINT_PATH = path.join(__dirname, '..', '..', 'src', 'release', 'fingerprint.js');

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

test('the fingerprint implementation still matches the pinned cross-repo digest', () => {
  const actual = digestOf(fs.readFileSync(FINGERPRINT_PATH, 'utf8'));
  assert.equal(
    actual, FINGERPRINT_DIGEST,
    'src/release/fingerprint.js changed.\n' +
    'blueeye-licens signs the fingerprint it computes into the licence proof, and this\n' +
    'agent compares it with the fingerprint of the key a server offers. If the two\n' +
    'implementations disagree, NO agent accepts ANY key. Apply the same change in\n' +
    'blueeye-licens (src/lib/fingerprint.js) and blueeye-server (src/lib/fingerprint.js),\n' +
    `then update FINGERPRINT_DIGEST in all three copies of _contracts.js to:\n  ${actual}`
  );
});

test('a fingerprint is of the key, whatever encoding it arrived in', () => {
  // The property the whole chain rests on: the vendor hashes a PEM it was sent,
  // the agent hashes a PEM it is offered, and the two must agree even though
  // nothing guarantees the bytes took the same route.
  const pem = crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const fp = publicKeyFingerprint(pem);
  assert.match(fp, /^[0-9a-f]{64}$/);
  for (const shape of [pem.replace(/\n/g, '\r\n'), pem.trimEnd(), `${pem}\n\n`, Buffer.from(pem).toString('base64')]) {
    assert.equal(publicKeyFingerprint(shape), fp);
  }
});

test('the embedded vendor root is the key blueeye-server embeds', () => {
  assert.equal(
    EMBEDDED_VENDOR_ROOT_PUBLIC_KEY.trim(), VENDOR_ROOT_PUBLIC_KEY.trim(),
    'src/license/vendorRoot.js no longer carries the same key as blueeye-server\n' +
    "(src/license/publicKey.js). That key is what a vendor authorisation is verified\n" +
    'against, so a divergence means every rekey this fleet is offered is refused.'
  );
});

// ---- the two files that decide WHEN and WHETHER an agent updates -----------
//
// Both are evaluated on BOTH sides, and a divergence is silent on each of them:
// the window decides when an agent may restart itself (only the agent knows its
// own local time, so only the agent can evaluate it), and the version compare
// decides what "behind" means (the server picks the agents a rollout touches,
// the agent decides whether to ask). Disagreement means a fleet that updates at
// lunchtime, or one that never updates, with nothing to see from either copy.

test('the update-window implementation still matches the pinned cross-repo digest', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', '..', 'src', 'updateWindow.js'), 'utf8');
  const actual = digestOf(source);
  assert.equal(
    actual, UPDATE_WINDOW_DIGEST,
    'the update window changed here but not in the server.\n'
    + `Update UPDATE_WINDOW_DIGEST in all three copies of test/gate/_contracts.js to:\n  ${actual}`
  );
});

test('the version comparison still matches the pinned cross-repo digest', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', '..', 'src', 'version.js'), 'utf8');
  const actual = digestOf(source);
  assert.equal(
    actual, VERSION_COMPARE_DIGEST,
    '"behind" changed here but not in the server.\n'
    + `Update VERSION_COMPARE_DIGEST in all three copies of test/gate/_contracts.js to:\n  ${actual}`
  );
});

test('a window that wraps midnight is not an empty one, on both sides', () => {
  const { parseWindow, isWithinWindow } = require('../../src/updateWindow');
  const at = (h, m = 0) => new Date(2026, 0, 15, h, m);
  assert.equal(isWithinWindow('22:00-04:00', at(23)), true);
  assert.equal(isWithinWindow('22:00-04:00', at(2)), true);
  assert.equal(isWithinWindow('22:00-04:00', at(12)), false);
  assert.equal(isWithinWindow('', at(12)), true, 'an unset window restricts nothing');
  assert.equal(parseWindow('02:00-02:00'), null, 'a zero-length window is not "always"');
});

test('only a strictly newer, parseable version counts as behind, on both sides', () => {
  const { isNewer } = require('../../src/version');
  assert.equal(isNewer('1.0.1', '1.0.0'), true);
  assert.equal(isNewer('1.0.0', '1.0.0'), false);
  assert.equal(isNewer('0.9.0', '1.0.0'), false, 'a downgrade is not an update');
  assert.equal(isNewer('nonsense', '1.0.0'), false, 'unparseable is never "update available"');
  assert.equal(isNewer('1.0.0', ''), false);
});
