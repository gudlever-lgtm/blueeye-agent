'use strict';

// The vendor's Ed25519 PUBLIC key — this agent's permanent trust anchor.
//
// Everything else the agent trusts is derived from it. The on-prem BlueEyes
// server signs the releases and the privileged commands this agent acts on, but
// WHICH key it may sign with is decided by a vendor-signed licence proof, and
// this constant is what that signature is checked against.
//
// It is embedded in the source rather than fetched, configured or learned. That
// is the whole point: an on-prem server — including one that has been taken
// over — must not be able to change what this agent verifies against. A key
// that arrives over the same channel as the thing it authenticates proves
// nothing.
//
// MUST be the same key blueeye-server embeds in src/license/publicKey.js and
// blueeye-licens publishes in docs/public-key.md. The cross-repo gate test pins
// the two copies together; a divergence means no agent accepts any key.
//
// Public keys are not secret, so committing the real one is correct and is the
// only way to keep the anchor out of the operator's hands.
const EMBEDDED_VENDOR_ROOT_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAZpCaHLTayNw1SOfTRSoWKfUZWC2RJrUK7yoLdVhCyxo=
-----END PUBLIC KEY-----`;

// The override exists for local development, the demo stack and the test suite,
// where the vendor key is generated on the fly. It is a DEVELOPMENT tool: in
// production the operator setting it is the same party the trust chain is meant
// to constrain, so it is ignored there unless the same deliberate
// acknowledgement blueeye-server requires is also present (trustAnchorGuard.js
// there, this function here — the two must agree in spirit).
const OVERRIDE_ACK_TOKEN = 'i-accept-the-risk';

function looksLikePem(value) {
  return typeof value === 'string' && value.includes('BEGIN PUBLIC KEY');
}

function isOverrideAllowed(env) {
  if ((env.NODE_ENV || 'development') !== 'production') return true;
  return String(env.BLUEEYE_TRUST_ANCHOR_OVERRIDE_ACK || '').trim().toLowerCase() === OVERRIDE_ACK_TOKEN;
}

// Resolves the vendor root: the embedded constant, or BLUEEYE_VENDOR_ROOT_-
// PUBLIC_KEY (PEM or base64-of-PEM) where the override is allowed. Returns ''
// only if the embedded constant has been emptied — callers fail closed.
function resolveVendorRoot(env = process.env) {
  const raw = env.BLUEEYE_VENDOR_ROOT_PUBLIC_KEY;
  if (raw && String(raw).trim() && isOverrideAllowed(env)) {
    if (looksLikePem(raw)) return String(raw);
    try {
      const decoded = Buffer.from(String(raw).trim(), 'base64').toString('utf8');
      if (looksLikePem(decoded)) return decoded;
    } catch { /* fall through to the embedded key */ }
  }
  return looksLikePem(EMBEDDED_VENDOR_ROOT_PUBLIC_KEY) ? EMBEDDED_VENDOR_ROOT_PUBLIC_KEY : '';
}

module.exports = { EMBEDDED_VENDOR_ROOT_PUBLIC_KEY, resolveVendorRoot, OVERRIDE_ACK_TOKEN };
