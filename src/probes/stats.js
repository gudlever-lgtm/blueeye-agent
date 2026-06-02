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

module.exports = { clampInt, round, summarize, fail };
