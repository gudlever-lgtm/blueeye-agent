'use strict';

// Measurements the server could not take, held until it can.
//
// A measurement is taken at a moment that will not come back. When the submit
// failed — the server restarting, the proxy in front of it down, the path gone
// for ninety seconds — the agent used to log the failure and throw the reading
// away, so an outage left a hole in the history of exactly the period someone
// would later want to look at. The spool keeps those readings and re-submits
// them, oldest first, on the next attempt that gets through.
//
// It is deliberately in MEMORY and deliberately BOUNDED:
//
//   * in memory, because the results carry the customer's network metadata and
//     the agent's disk state is provisioned to hold a token, a config and an
//     action log — not an unbounded queue of measurements nobody is reading;
//   * bounded, because an agent that cannot reach its server for a day must not
//     become the host's memory problem. Past `max` batches the OLDEST go, and
//     the count of what was dropped is kept so the agent can say so.
//
// Ordering is the reason a caller should always go through `deliver`: a fresh
// result submitted while older ones are still spooled would land out of order,
// and the server's per-agent series would jump back and forth in time.
function createResultSpool({ max = 240, logger = null } = {}) {
  const queue = []; // [{ kind, items, at }]
  let dropped = 0;

  function add(kind, items) {
    if (!Array.isArray(items) || !items.length) return false;
    if (max <= 0) return false; // spooling disabled
    queue.push({ kind, items, at: Date.now() });
    while (queue.length > max) {
      queue.shift();
      dropped += 1;
      if (dropped === 1 && logger && typeof logger.warn === 'function') {
        logger.warn(`Result spool is full (${max} batches); the oldest measurements are being dropped.`);
      }
    }
    return true;
  }

  // Submits everything spooled for `kind`, oldest first, through `submit`.
  // Stops at the FIRST failure and leaves that batch (and everything after it)
  // in place, in order — a server that just refused one batch is not going to
  // take the next five, and trying anyway turns one failure into six.
  // Rethrows that failure so the caller keeps its existing error handling
  // (notably a 401, which pauses the agent).
  async function flush(kind, submit) {
    let sent = 0;
    while (true) {
      const index = queue.findIndex((entry) => entry.kind === kind);
      if (index < 0) break;
      const [entry] = queue.splice(index, 1);
      try {
        await submit(entry.items);
        sent += 1;
      } catch (err) {
        queue.splice(index, 0, entry); // back where it was; order is preserved
        err.spooled = pending(kind);
        throw err;
      }
    }
    return sent;
  }

  // The path callers use: spool the new batch, then flush the kind in order. On
  // success everything that was waiting has gone out with it; on failure
  // everything — including the new batch — is still spooled and the error is
  // rethrown for the caller to report.
  async function deliver(kind, items, submit) {
    if (max <= 0) {
      await submit(items);
      return { sent: 1, spooled: 0 };
    }
    add(kind, items);
    const sent = await flush(kind, submit);
    return { sent, spooled: pending(kind) };
  }

  function pending(kind) {
    return kind ? queue.filter((entry) => entry.kind === kind).length : queue.length;
  }

  return {
    add,
    flush,
    deliver,
    pending,
    get size() { return queue.length; },
    get dropped() { return dropped; },
    // For the diagnose snapshot: what is waiting, and how old the oldest is.
    stats() {
      const oldest = queue.length ? queue[0].at : null;
      return {
        batches: queue.length,
        dropped,
        oldestAgeMs: oldest == null ? null : Date.now() - oldest,
        max,
      };
    },
  };
}

module.exports = { createResultSpool };
