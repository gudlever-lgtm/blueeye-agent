'use strict';

// Deterministic JSON serialisation used to verify signed release manifests.
//
// Rules: object keys sorted alphabetically (recursively), no whitespace, UTF-8.
// This MUST be byte-for-byte identical to blueeye-server's src/lib/canonicalize.js
// and blueeye-licens' src/lib/canonicalize.js, so the bytes signed on the build
// host reproduce exactly here and the Ed25519 signature verifies. Keep in sync.
function canonicalize(value) {
  return JSON.stringify(sortDeep(value));
}

function sortDeep(value) {
  if (Array.isArray(value)) {
    return value.map(sortDeep);
  }
  if (value !== null && typeof value === 'object') {
    return Object.keys(value)
      .sort()
      .reduce((acc, key) => {
        acc[key] = sortDeep(value[key]);
        return acc;
      }, {});
  }
  return value;
}

module.exports = { canonicalize };
