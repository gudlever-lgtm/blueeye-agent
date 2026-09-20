'use strict';

const crypto = require('crypto');
const { canonicalize } = require('../release/canonicalize');
const { publicKeyFingerprint, isFingerprint } = require('../release/fingerprint');
const { resolveVendorRoot } = require('./vendorRoot');

// Deciding whether to trust a server's release key, without taking that
// server's word for anything.
//
// The on-prem server fetches a vendor-signed licence proof and relays it here
// unchanged. Inside it — inside the SIGNATURE — the vendor names the key
// fingerprint that server is authorised to sign with. This agent embeds the
// vendor's public key, so it can check that claim against a signature the
// server cannot produce and cannot alter.
//
// Every step below is a REJECT on failure. There is no "unknown key, trust it
// this once" path: that is the property the whole chain exists to provide, and
// one fallback would undo all of it.
//
//   verify vendor signature   → no signature we can check is a rejection
//   licence / customer match  → customer A's proof cannot authorise customer B
//   validity window           → an authorisation is not valid for ever
//   sequence (anti-rollback)  → an old captured proof cannot re-authorise a
//                               key that has since been replaced
//   fingerprint match         → the key offered must be the key authorised
//
// Reason codes are stable strings, because they are logged and an operator
// reads them: LICENSE_PROOF_INVALID, LICENSE_PROOF_EXPIRED, LICENSE_PROOF_-
// ROLLBACK, LICENSE_CUSTOMER_MISMATCH, SERVER_KEY_MISMATCH.

// Tolerance for the agent's own clock against the proof's window. An on-prem
// host can be minutes out without anything being wrong; hours out is a fault
// that should surface rather than be absorbed.
const MAX_CLOCK_SKEW_MS = 10 * 60 * 1000;

function fail(code, detail) {
  return { ok: false, code, detail };
}

// Verifies a vendor-signed proof and decides whether `offeredKey` may be
// trusted. Pure — it reads no files and mutates nothing; the caller persists
// the accepted state. Never throws.
//
//   proof       { payload, signature }  as the vendor signed it
//   offeredKey  the PEM the server wants this agent to pin
//   expected    { licenseId?, customerId?, sequence? } what this agent already
//               knows: the identity it was provisioned with (or has accepted
//               before) and the highest sequence it has seen.
function verifyTrustProof({
  proof,
  offeredKey,
  expected = {},
  vendorRoot = resolveVendorRoot(),
  now = () => Date.now(),
  maxSkewMs = MAX_CLOCK_SKEW_MS,
} = {}) {
  if (!vendorRoot) return fail('LICENSE_PROOF_INVALID', 'no vendor root key is embedded in this agent');
  if (!proof || typeof proof !== 'object') return fail('LICENSE_PROOF_INVALID', 'no proof supplied');

  const { payload, signature } = proof;
  if (!payload || typeof payload !== 'object' || typeof signature !== 'string' || !signature) {
    return fail('LICENSE_PROOF_INVALID', 'proof is missing its payload or signature');
  }

  // 1. The vendor signature, over the exact bytes the vendor signed. Nothing
  //    below this line means anything until it passes.
  let verified = false;
  try {
    verified = crypto.verify(
      null,
      Buffer.from(canonicalize(payload), 'utf8'),
      vendorRoot,
      Buffer.from(signature, 'base64')
    );
  } catch {
    verified = false;
  }
  if (!verified) return fail('LICENSE_PROOF_INVALID', 'vendor signature did not verify');

  const trust = payload.trust;
  if (!trust || typeof trust !== 'object') {
    return fail('LICENSE_PROOF_INVALID', 'proof authorises no release key');
  }
  const authorized = trust.server && trust.server.release_key;
  if (!authorized || !isFingerprint(authorized.fingerprint)) {
    return fail('LICENSE_PROOF_INVALID', 'proof carries no usable key fingerprint');
  }
  if (authorized.algorithm && authorized.algorithm !== 'Ed25519') {
    return fail('LICENSE_PROOF_INVALID', `unsupported key algorithm ${authorized.algorithm}`);
  }

  // 2. Customer binding. A valid proof belonging to somebody else authorises
  //    nothing here — otherwise one compromised customer's server could
  //    re-anchor another customer's fleet.
  const license = trust.license || {};
  if (expected.licenseId != null && String(license.id) !== String(expected.licenseId)) {
    return fail('LICENSE_CUSTOMER_MISMATCH', `proof is for licence ${license.id}, this agent belongs to ${expected.licenseId}`);
  }
  if (expected.customerId != null && String(license.customer_id) !== String(expected.customerId)) {
    return fail('LICENSE_CUSTOMER_MISMATCH', `proof is for customer ${license.customer_id}, this agent belongs to ${expected.customerId}`);
  }

  // 3. Validity. Checked against THIS host's clock, which is the only clock
  //    that matters for the decision this host is making.
  const t = now();
  const validUntil = Date.parse(payload.valid_until || '');
  if (!Number.isFinite(validUntil)) return fail('LICENSE_PROOF_INVALID', 'proof has no valid_until');
  if (t - maxSkewMs > validUntil) {
    return fail('LICENSE_PROOF_EXPIRED', `proof expired at ${payload.valid_until}`);
  }
  const issuedAt = Date.parse(payload.proof_issued_at || '');
  if (Number.isFinite(issuedAt) && issuedAt - maxSkewMs > t) {
    return fail('LICENSE_PROOF_INVALID', `proof is dated in the future (${payload.proof_issued_at})`);
  }

  // 4. Anti-rollback. A vendor-signed proof stays valid bytes for ever; the
  //    sequence is what stops yesterday's authorisation re-authorising a key
  //    that has since been replaced.
  const sequence = Number(trust.sequence);
  if (!Number.isInteger(sequence) || sequence < 0) {
    return fail('LICENSE_PROOF_INVALID', 'proof carries no usable sequence');
  }
  if (expected.sequence != null && sequence < Number(expected.sequence)) {
    return fail('LICENSE_PROOF_ROLLBACK', `proof sequence ${sequence} is older than the accepted ${expected.sequence}`);
  }

  // 5. The key actually offered must be the key the vendor authorised. The
  //    server can send whatever it likes; only this comparison decides.
  const offeredFingerprint = publicKeyFingerprint(offeredKey);
  if (!offeredFingerprint) return fail('SERVER_KEY_MISMATCH', 'the offered key is not a usable public key');
  if (offeredFingerprint !== authorized.fingerprint) {
    return fail('SERVER_KEY_MISMATCH',
      `the offered key (${offeredFingerprint.slice(0, 16)}…) is not the one the vendor authorised (${authorized.fingerprint.slice(0, 16)}…)`);
  }

  return {
    ok: true,
    fingerprint: offeredFingerprint,
    sequence,
    licenseId: license.id != null ? String(license.id) : null,
    customerId: license.customer_id != null ? String(license.customer_id) : null,
    serverId: trust.server && trust.server.id != null ? String(trust.server.id) : null,
    validUntil: payload.valid_until,
  };
}

module.exports = { verifyTrustProof, MAX_CLOCK_SKEW_MS };
