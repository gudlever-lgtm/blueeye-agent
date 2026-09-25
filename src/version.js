'use strict';

// Version comparison for "is an update available?" checks.
//
// Byte-identical to blueeye-server's src/lib/version.js, and to the dashboard's
// compareVersions: only the numeric release core is compared, any pre-release or
// build suffix is ignored. That matters here because the agent now decides for
// itself whether it is behind, and an agent that disagreed with the server about
// what "behind" means would either never update or ask forever.
const VERSION_RE = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;

function isValidVersion(value) {
  return typeof value === 'string' && VERSION_RE.test(value.trim());
}

// -1 / 0 / 1 — a before b, equal, a after b.
function compareVersions(a, b) {
  const parse = (s) => String(s).split(/[-+]/)[0].split('.').map((n) => Number.parseInt(n, 10) || 0);
  const pa = parse(a);
  const pb = parse(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i += 1) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

// True only when `candidate` is STRICTLY newer than `current`, and both are
// usable versions. Anything unparseable is "no update" — a malformed version
// must never produce a phantom "update available" badge.
function isNewer(candidate, current) {
  if (!isValidVersion(candidate) || !isValidVersion(current)) return false;
  return compareVersions(candidate, current) > 0;
}

module.exports = { isValidVersion, compareVersions, isNewer, VERSION_RE };
