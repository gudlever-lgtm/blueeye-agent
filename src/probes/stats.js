'use strict';

// Shared helpers for the active probes. Kept tiny + pure so each probe module
// stays independently testable.

function clampInt(v, def, min, max) {
  const n = Number.parseInt(v, 10);
  if (!Number.isInteger(n)) return def;
  return Math.max(min, Math.min(max, n));
}

const round = (n) => (n == null ? null : Math.round(n * 100) / 100);

// Builds a normalized probe result from the successful RTTs (ms) out of
// `attempts` tries. loss% from the misses; jitter = mean absolute difference of
// consecutive RTTs (the RFC3550-style inter-packet variation).
function summarize(type, target, rtts, attempts, extra = {}) {
  const success = rtts.length;
  const lossPct = attempts > 0 ? round(((attempts - success) / attempts) * 100) : 0;
  let rttMs = null;
  let minMs = null;
  let maxMs = null;
  let jitterMs = null;
  if (success) {
    rttMs = round(rtts.reduce((s, v) => s + v, 0) / success);
    minMs = round(Math.min(...rtts));
    maxMs = round(Math.max(...rtts));
    let jsum = 0;
    for (let i = 1; i < rtts.length; i += 1) jsum += Math.abs(rtts[i] - rtts[i - 1]);
    jitterMs = rtts.length > 1 ? round(jsum / (rtts.length - 1)) : 0;
  }
  return { type, target, ok: success > 0, attempts, success, rttMs, minMs, maxMs, jitterMs, lossPct, ...extra };
}

function fail(type, target, error) {
  return { type, target, ok: false, attempts: 0, success: 0, rttMs: null, minMs: null, maxMs: null, jitterMs: null, lossPct: 100, error: String(error) };
}

// Validates a host/target that will be handed to a system tool (ping,
// traceroute) as an argv element. execFile means there is no shell, so the only
// residual risk is a target that the tool itself parses as an OPTION — e.g. a
// host of `-f` becoming a flood-ping flag. We reject anything with a leading `-`
// and anything outside the hostname/IPv4/IPv6 character set. Returns the trimmed
// host, or null when unsafe. Callers should ALSO place the host after a `--`
// end-of-options marker in argv (belt-and-braces on Unix tools).
function safeHost(raw) {
  const host = String(raw == null ? '' : raw).trim();
  if (!host || host.length > 255) return null;
  if (host.startsWith('-')) return null;
  // Letters, digits, dot, hyphen (hostnames); colon + brackets + percent (IPv6
  // with optional zone id). Nothing that a shell or option parser would treat
  // specially.
  if (!/^[A-Za-z0-9._:%[\]-]+$/.test(host)) return null;
  return host;
}

module.exports = { clampInt, round, summarize, fail, safeHost };
