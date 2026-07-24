'use strict';

// A simple paced rate limiter for the discovery scan. `acquire()` resolves when
// the caller may issue the next probe, spacing grants evenly at `ratePerSec`
// (default 50/s). Clock + sleep are injectable so the pacing is deterministically
// testable without real timers.

function createRateLimiter({ ratePerSec = 50, now = () => Date.now(), sleep = (ms) => new Promise((r) => setTimeout(r, ms)) } = {}) {
  const rate = Number(ratePerSec) > 0 ? Number(ratePerSec) : 50;
  const intervalMs = 1000 / rate;
  let nextAt = null;

  async function acquire() {
    const t = now();
    if (nextAt == null) nextAt = t;
    const wait = Math.max(0, nextAt - t);
    if (wait > 0) await sleep(wait);
    const grantedAt = now();
    nextAt = Math.max(nextAt, grantedAt) + intervalMs;
    return grantedAt;
  }

  return { acquire, intervalMs, ratePerSec: rate };
}

module.exports = { createRateLimiter };
