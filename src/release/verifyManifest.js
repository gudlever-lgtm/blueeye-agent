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

module.exports = { verifyManifest };
