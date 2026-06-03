'use strict';

// Normalises a TLS certificate fingerprint to upper-case hex pairs joined by
// ':' so inputs like "ab:cd…", "ABCD…" or "sha256:AB:CD…" all compare equal.
// Returns '' for anything that isn't a SHA-256 digest (32 bytes).
function normalizeFingerprint(input) {
  if (!input) return '';
  let s = String(input).trim();
  const prefix = /^sha-?256[:/=\s]+/i.exec(s);
  if (prefix) s = s.slice(prefix[0].length);
  s = s.replace(/[^0-9a-fA-F]/g, '').toUpperCase();
  if (s.length !== 64) return '';
  return s.match(/.{2}/g).join(':');
}

module.exports = { normalizeFingerprint };
