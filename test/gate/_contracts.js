'use strict';

// CROSS-REPO CONTRACTS — the shared definitions blueeye-server, blueeye-agent
// and blueeye-licens each keep their OWN copy of.
//
// Four things are duplicated across the three repos today, each carrying a
// comment that says some version of "MUST stay identical, keep in sync":
//
//   canonicalize()      the exact bytes a licence proof / release manifest /
//                       privileged command is signed over. licens signs them,
//                       server and agent reproduce them to verify.
//   PROTOCOL_VERSION    the agent↔server wire-contract version.
//   the evidence        what an evidence snapshot may ask an agent to collect.
//   allowlist           The agent enforces its own copy as defense in depth.
//   verifyProof/        same Ed25519 check, same "any error is not verified"
//   verifyPayload       semantics, on both ends of the licence.
//
// A comment is not an enforcement mechanism. Nothing stopped a well-meaning
// edit to one copy, and the failure modes are quiet and severe: a canonicalize
// that diverges by one byte makes EVERY licence proof fail to verify on every
// customer install, and an allowlist that diverges is a security control that no
// longer matches its counterpart.
//
// So this module pins them, and each repo's gate asserts its own copies against
// the same pins. Two layers, because they catch different things:
//
//   BEHAVIOUR — fixed vectors through canonicalize(). This is what actually
//     breaks signatures, and it is checked without needing the sibling repos on
//     disk. A refactor that keeps the output identical passes, correctly.
//
//   SOURCE DIGEST — the implementation with comments and whitespace removed.
//     The three copies differ only in their header comments, so normalising
//     those away gives ONE digest for all three. This catches an edit that
//     happens to keep the vectors passing but changes the code anyway, and it
//     makes the sync deliberate: change the function and this repo's gate fails
//     until you update the pin — at which point the OTHER two repos' gates fail
//     until they are updated too. That is exactly the handshake the comments
//     were asking for.
//
// Changing a pin is a cross-repo change. Do all three, in one go.

const crypto = require('crypto');

// ---------------------------------------------------------------- the pins

// sha256 of canonicalize.js with comments + whitespace stripped (see digestOf).
// Shared by blueeye-server/src/lib/canonicalize.js,
// blueeye-licens/src/lib/canonicalize.js and
// blueeye-agent/src/release/canonicalize.js.
const CANONICALIZE_DIGEST = 'e703fc7c35b09e3a8a9c161122cc0ab25988a1b3175dfbf521714a4964b577d7';

// src/release/fingerprint.js — THE definition of a public key's fingerprint for
// the whole product: SHA-256 over the key's SPKI DER bytes. blueeye-licens signs
// that fingerprint into the licence proof and this agent computes it over the key
// a server offers, so a divergence means no agent accepts any key. Duplicated
// byte-for-byte in blueeye-licens (src/lib/fingerprint.js) and blueeye-server
// (src/lib/fingerprint.js).
const FINGERPRINT_DIGEST = '22351ca4ca228ed751f8c80c9202c14665885e551e56a003336a09b6a0b5e661';

// The vendor's public key, as embedded in this agent (src/license/vendorRoot.js)
// and in blueeye-server (src/license/publicKey.js). It is the permanent trust
// anchor: the agent verifies the licence proof that authorises a server's release
// key against it. The two copies must be the same key, or an agent rejects every
// authorisation its own server relays.
const VENDOR_ROOT_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAZpCaHLTayNw1SOfTRSoWKfUZWC2RJrUK7yoLdVhCyxo=
-----END PUBLIC KEY-----`;

// blueeye-server/src/protocol.js and blueeye-agent/src/protocol.js.
const PROTOCOL_VERSION = 1;

// blueeye-server/src/evidence/commandAllowlist.js and the agent's own copy in
// blueeye-agent/src/evidenceCollector.js. Sorted; order is not part of the
// contract, membership is.
const EVIDENCE_ITEMS = ['agent.state', 'arp.table', 'iface.counters', 'snmp.reads'];
const EVIDENCE_COMMAND_SET_VERSION = 'evidence-v1';

// Fixed inputs whose canonical bytes are the whole point. These cover the
// properties the signature depends on: recursive key sorting, no whitespace,
// array order PRESERVED (sorting an array would change meaning), nested
// objects inside arrays, and the JSON primitives.
const CANONICALIZE_VECTORS = [
  { input: {}, expected: '{}' },
  { input: { b: 1, a: 2 }, expected: '{"a":2,"b":1}' },
  { input: { z: { y: 1, x: 2 }, a: 3 }, expected: '{"a":3,"z":{"x":2,"y":1}}' },
  // Array order is meaningful and must survive untouched.
  { input: { list: [3, 1, 2] }, expected: '{"list":[3,1,2]}' },
  { input: { list: [{ b: 1, a: 2 }] }, expected: '{"list":[{"a":2,"b":1}]}' },
  { input: { n: null, t: true, f: false, s: 'x', i: 0 }, expected: '{"f":false,"i":0,"n":null,"s":"x","t":true}' },
  // Unicode and escapes: the signed bytes are UTF-8, and JSON.stringify's own
  // escaping is part of the contract.
  { input: { k: 'æøå' }, expected: '{"k":"æøå"}' },
  { input: { k: 'a"b\\c' }, expected: '{"k":"a\\"b\\\\c"}' },
  // A realistic licence-proof shape, so the vectors fail on a change that only
  // shows up on nested real data.
  {
    input: {
      valid: true, plan_key: 'professional', max_agents: 25,
      features: { rbac: true, alerts_email: true },
      releases: { server: { version: '0.168.1' }, agent: { version: '0.32.1' } },
      issued_at: '2026-01-01T00:00:00.000Z',
    },
    expected: '{"features":{"alerts_email":true,"rbac":true},"issued_at":"2026-01-01T00:00:00.000Z","max_agents":25,"plan_key":"professional","releases":{"agent":{"version":"0.32.1"},"server":{"version":"0.168.1"}},"valid":true}',
  },
];

// ------------------------------------------------------------- the digest

// Strips comments and ALL whitespace, then hashes. Comments are where the three
// copies legitimately differ (each explains itself to its own repo), so they
// must not be part of the digest; everything else must.
//
// Deliberately simple: a real tokeniser would be more correct about `//` inside
// a string literal, and canonicalize.js contains none. If that ever stops being
// true the digest changes and the gate says so, which is the right failure.
function digestOf(source) {
  const stripped = String(source)
    .replace(/\/\*[\s\S]*?\*\//g, '')   // block comments
    .replace(/(^|[^:])\/\/[^\n]*/g, '$1') // line comments (not a :// URL)
    .replace(/\s+/g, '');                 // all whitespace
  return crypto.createHash('sha256').update(stripped, 'utf8').digest('hex');
}

module.exports = {
  FINGERPRINT_DIGEST,
  VENDOR_ROOT_PUBLIC_KEY,
  CANONICALIZE_DIGEST,
  CANONICALIZE_VECTORS,
  PROTOCOL_VERSION,
  EVIDENCE_ITEMS,
  EVIDENCE_COMMAND_SET_VERSION,
  digestOf,
};
