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

// The same, for a SET of pins — which is what certificate RENEWAL needs. A pin
// is to one leaf certificate, so the day the server's certificate is replaced
// every pinned agent fails closed, and the thing that could fix it (the server)
// is exactly what it can no longer reach. Holding the next certificate's
// fingerprint ALONGSIDE the current one turns a renewal into a non-event: both
// are accepted, the old one is dropped afterwards.
//
// Accepts an array, or one string carrying several pins separated by comma,
// semicolon, whitespace or newline. Order is preserved, duplicates dropped, and
// anything that is not a SHA-256 digest is skipped (a single bad entry must not
// take the good pins with it). Returns [].
function normalizeFingerprints(input) {
  if (!input) return [];
  const parts = Array.isArray(input) ? input : splitPins(String(input));
  const out = [];
  for (const part of parts) {
    const fp = normalizeFingerprint(part);
    if (fp && !out.includes(fp)) out.push(fp);
  }
  return out;
}

// A colon-separated digest is itself full of separators, so a list cannot simply
// be split on ':' — only on the separators BETWEEN pins.
function splitPins(value) {
  return value.split(/[\s,;]+/).filter(Boolean);
}

module.exports = { normalizeFingerprint, normalizeFingerprints };
