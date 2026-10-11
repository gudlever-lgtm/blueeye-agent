'use strict';

const crypto = require('crypto');
const { canonicalize } = require('./canonicalize');

// Verifies an Ed25519 signature over the canonical bytes of a release `manifest`
// using the agent's embedded release public key. This mirrors blueeye-server's
// verifyProof and blueeye-licens' verifyPayload EXACTLY, so a signature produced
// on the build host validates here. Any error (bad key, bad encoding, tampering)
// is treated as "not verified" — the agent fails CLOSED and never installs code
// it cannot authenticate.
function verifyManifest(manifest, signatureBase64, publicKey) {
  try {
    if (!manifest || typeof signatureBase64 !== 'string' || !publicKey) return false;
    const message = Buffer.from(canonicalize(manifest), 'utf8');
    return crypto.verify(null, message, publicKey, Buffer.from(signatureBase64, 'base64'));
  } catch {
    return false;
  }
}

// WHAT A SIGNATURE IS FOR.
//
// One key signs four different things on this chain: a release manifest, a
// privileged command, an evidence request and (on the server side) a NIS2
// export. Nothing in a bare Ed25519 signature says which, so a signature made
// for one purpose is cryptographically indistinguishable from one made for
// another — and the only reason that has not been exploitable is that the four
// payload SHAPES happen to differ. "Happens to differ" is not a security
// property; it is one refactor away from not being true.
//
// So the purpose rides INSIDE the signed payload, and every verifier states
// which one it is checking. A captured command signature can then never satisfy
// a release check, whatever shape the attacker gives the bytes.
//
// `required` is the compatibility seam, and it differs per shape on purpose:
//   * commands — required. This agent already refuses a signed command with no
//     commandId (0.48.0), so a server new enough to sign is new enough to stamp
//     both.
//   * release manifests — NOT required. Releases already published and cached
//     on servers were signed without it, and refusing them would mean a fleet
//     that cannot update to anything that already exists. A WRONG purpose is
//     still refused, which is the part that matters.
//   * evidence — not required, same reason, and the payload is rebuilt here
//     from the command's own fields, so it carries the purpose exactly when the
//     server sent one.
function purposeOk(payload, expected, { required = false } = {}) {
  const claimed = payload && payload.purpose;
  if (claimed == null) return !required;
  return claimed === expected;
}

module.exports = { verifyManifest, purposeOk };
