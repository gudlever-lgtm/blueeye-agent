'use strict';

const crypto = require('crypto');

// THE fingerprint of a public key, for the whole product.
//
// Three repos hash public keys, and until now each hashed the PEM *string*:
// SHA-256 over text that carries line endings, trailing newlines and a header.
// That is deterministic only for as long as every producer happens to export
// the key the same way — a fingerprint that depends on formatting is a
// fingerprint that can disagree with itself, and this one decides whether an
// agent accepts a key.
//
// So: SHA-256 over the key's SPKI **DER bytes** — the key itself, not its
// transport encoding. The same key yields the same fingerprint whether it
// arrived as PEM, as base64-of-PEM, with CRLF, or with no trailing newline.
//
// MUST stay byte-identical in blueeye-licens, blueeye-server and blueeye-agent:
// the licence proof says which fingerprint is authorised and the agent computes
// the fingerprint of the key it is offered. A divergence here means no agent
// accepts any key. The cross-repo gate test pins it.
function publicKeyFingerprint(key) {
  const publicKey = toPublicKey(key);
  if (!publicKey) return '';
  const der = publicKey.export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex');
}

// Accepts a KeyObject, a PEM string, or base64-of-PEM (the form the agent's
// systemd unit carries). Returns null for anything unusable — callers fail
// closed on a falsy fingerprint rather than on an exception.
function toPublicKey(key) {
  if (!key) return null;
  if (typeof key === 'object' && typeof key.export === 'function') return key;
  const text = String(key);
  const pem = text.includes('BEGIN PUBLIC KEY') ? text : decodeBase64Pem(text);
  if (!pem) return null;
  try {
    return crypto.createPublicKey({ key: pem, format: 'pem' });
  } catch {
    return null;
  }
}

function decodeBase64Pem(value) {
  try {
    const decoded = Buffer.from(value.trim(), 'base64').toString('utf8');
    return decoded.includes('BEGIN PUBLIC KEY') ? decoded : null;
  } catch {
    return null;
  }
}

// True when `value` is the shape a fingerprint must have: 64 lowercase hex
// characters. Used at every boundary that accepts one from outside.
function isFingerprint(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

// Normalises a public key to its canonical PEM, or '' when it is not one. An
// Ed25519 check is the caller's business (see the agent's keyStore) — this
// module only cares about "is this a public key, and what is its fingerprint".
function canonicalPem(key) {
  const publicKey = toPublicKey(key);
  if (!publicKey) return '';
  return publicKey.export({ type: 'spki', format: 'pem' }).toString();
}

module.exports = { publicKeyFingerprint, isFingerprint, canonicalPem, toPublicKey };
