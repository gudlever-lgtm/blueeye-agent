'use strict';

// A simple paced rate limiter for the discovery scan. `acquire()` resolves when
// the caller may issue the next probe, spacing grants evenly at `ratePerSec`
// (default 50/s). Clock + sleep are injectable so the pacing is deterministically
// testable without real timers.
//
// Concurrent callers are SERIALISED, and that is the whole difficulty. Reserving
// the slot after the sleep looks right and is not: several workers arriving while
// the slot is in the future each read the same `nextAt`, each compute the same
// wait, and all wake together — so a scan with portConcurrency 6 fires six probes
// in one millisecond and the rate limit means nothing. It fails intermittently
// rather than always, because whether the workers interleave that way depends on
// timing, which is the worst way for a rate limit on someone else's network to be
// wrong.
//
// So the slot is CLAIMED before the sleep, synchronously, and each acquire waits
// for the one before it. A caller then sleeps until its own slot, not until a
// slot another caller is also waiting for.
function createRateLimiter({ ratePerSec = 50, now = () => Date.now(), sleep = (ms) => new Promise((r) => setTimeout(r, ms)) } = {}) {
  const rate = Number(ratePerSec) > 0 ? Number(ratePerSec) : 50;
  const intervalMs = 1000 / rate;
  let nextAt = null;
  // The tail of the queue: every acquire chains onto it, so claims happen one at
  // a time and in arrival order.
  let tail = Promise.resolve();

  async function acquire() {
    const mine = tail.then(async () => {
      const t = now();
      // The slot is claimed here, before any waiting, so the next caller cannot
      // claim the same one.
      const slot = nextAt == null ? t : Math.max(nextAt, t);
      nextAt = slot + intervalMs;
      const wait = slot - t;
      if (wait > 0) await sleep(wait);
      return now();
    });
    // The next caller queues behind this one's claim. `catch` keeps one caller's
    // failure from poisoning the queue for everyone after it.
    tail = mine.then(() => {}, () => {});
    return mine;
  }

  return { acquire, intervalMs, ratePerSec: rate };
}

module.exports = { createRateLimiter };
