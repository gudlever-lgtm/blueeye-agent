'use strict';

// Exponential backoff with full-ish jitter (between 50% and 100% of the
// computed delay) and a hard cap. attempt starts at 1.
function computeBackoff(attempt, { baseMs = 1000, maxMs = 30000, factor = 2 } = {}) {
  const exp = Math.min(maxMs, baseMs * factor ** Math.max(0, attempt - 1));
  const jittered = exp / 2 + Math.random() * (exp / 2);
  return Math.round(jittered);
}

module.exports = { computeBackoff };
