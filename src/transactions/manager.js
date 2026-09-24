'use strict';

const { runTransaction } = require('./executors');
const { shouldCapture, shouldKeep, captureSeconds } = require('./capturePolicy');
const { observedPortsOf } = require('../capture');

const silentLogger = { info() {}, warn() {}, error() {} };

// Ties the transaction executor set to the WS channel:
//   - receives pushed config (applyConfig) and persists it locally,
//   - schedules each enabled test on its own interval_sec with ±10% jitter so
//     tests don't clump,
//   - runs the executor, buffers the result, and flushes the buffer as a batch
//     `transaction_result` frame (whenever a send succeeds, and on reconnect),
//   - optionally captures the packet HEADERS of the traffic the run itself
//     generates, keeping them only when the run went wrong (see capturePolicy.js),
//   - on restart (start() with no pushed config yet) it loads the persisted
//     config so tests keep running without server contact.
//
// RESULTS ARE BUFFERED; CAPTURES ARE NOT. A result is small and still worth
// having after a reconnect — it is the measurement. A capture is large and
// perishable: by the time a disconnected agent comes back, the fault its packets
// describe is history, and the result row it belongs to already carries the
// verdict. So a capture is sent best-effort on the socket that is open now, or
// dropped. Buffering them would trade the thing that matters (results survive an
// outage) for the thing that does not.
//
// `send(obj) -> boolean` is client.send (true when delivered). Timers/RNG are
// injectable for deterministic tests.
function createTransactionManager({
  send,
  configStore,
  buffer,
  executorDeps = {},
  logger = silentLogger,
  run = runTransaction,
  setTimeoutFn = setTimeout,
  clearTimeoutFn = clearTimeout,
  random = Math.random,
  // Optional: the header-capture runner (src/capture). Absent (or unavailable on
  // this host) means every run simply proceeds without one — a capture is an
  // extra, and a test must never fail to run because it could not be captured.
  capture = null,
}) {
  let tests = [];
  let started = false;
  const timers = new Map(); // testId -> timer
  // On-demand runs in flight. A second "run it now" for the same test while the
  // first is still going would double the traffic and interleave two captures
  // into one — the same reason a burst refuses to run twice.
  const running = new Set();

  // interval_sec ± 10%, in ms. Guards against a missing/small interval.
  function jitteredMs(intervalSec) {
    const sec = Number.isFinite(intervalSec) && intervalSec >= 5 ? intervalSec : 60;
    return Math.round(sec * 1000 * (0.9 + random() * 0.2));
  }

  function unrefed(handle) { if (handle && typeof handle.unref === 'function') handle.unref(); return handle; }

  // Runs one test once, with a capture around it when the test asks for one.
  // Never throws: a failure here must become a result, not an unhandled
  // rejection in a timer chain.
  //
  // The capture is started BEFORE the executor and stopped after, so the SYN
  // that opens the connection is inside the window. A capture that cannot start
  // (no tcpdump, no privilege, a target that will not resolve) is logged once at
  // debug and the run proceeds — the reason is already visible in capabilities.
  async function runOnce(test, { force = false } = {}) {
    const id = test.id;
    let session = null;
    if (capture && (force || shouldCapture(test))) {
      try {
        const started = await capture.start(test, { seconds: captureSeconds(test) });
        if (started.ok) session = started.session;
        else logger.info(`capture not started for test ${id}: ${started.reason}`);
      } catch (err) {
        logger.warn(`capture failed to start for test ${id}: ${err && err.message}`);
      }
    }

    let result;
    try {
      result = await run(test, executorDeps);
    } catch (err) {
      result = { test_id: id, time: new Date().toISOString(), status: 'error', latency_ms: 0, detail: { phase: 'error', errno: (err && err.code) || 'RUN_ERROR' } };
    }

    if (session) {
      const decision = force ? { keep: true, reason: 'requested' } : shouldKeep(test, result);
      try {
        const cap = await session.stop({ keep: decision.keep, observedPorts: observedPortsOf(result) });
        if (cap && cap.kept && cap.packets.length) {
          sendCapture(test, result, cap, decision.reason);
          result = { ...result, captured: cap.packets.length };
        }
      } catch (err) {
        logger.warn(`capture failed to stop for test ${id}: ${err && err.message}`);
        try { await capture.cancel(); } catch { /* best-effort */ }
      }
    }
    return result;
  }

  // Ships one capture on the socket that is open now. Matched to its result row
  // on the server by (test_id, agent_id, time) — the same three columns the
  // result carries — so neither frame has to arrive before the other.
  function sendCapture(test, result, cap, reason) {
    try {
      send({
        type: 'transaction_capture',
        test_id: test.id,
        time: result.time,
        capture: {
          reason,
          iface: cap.iface,
          filter: cap.filter,
          snaplen: cap.snaplen,
          duration_ms: cap.durationMs,
          observed: cap.observed,
          dropped: cap.dropped,
          foreign: cap.foreign,
          truncated: cap.truncated,
          packets: cap.packets,
        },
      });
    } catch (err) {
      logger.warn(`could not send capture for test ${test.id}: ${err && err.message}`);
    }
  }

  function scheduleTest(test) {
    const id = test.id;
    let handle = null; // this chain's live timer; identity marks chain ownership
    const tick = async () => {
      const result = await runOnce(test);
      buffer.push(result);
      flush();
      // Reschedule only if still active AND this chain still owns the id.
      // applyConfig() can replace the schedule while run() is awaited; the
      // map then holds the replacement's handle, and rescheduling here would
      // leave two live timer chains racing for one id (duplicate results +
      // the stale test definition kept alive). The replacement chain owns it.
      if (started && timers.get(id) === handle) {
        handle = unrefed(setTimeoutFn(tick, jitteredMs(test.interval_sec)));
        timers.set(id, handle);
      }
    };
    if (timers.has(id)) clearTimeoutFn(timers.get(id));
    handle = unrefed(setTimeoutFn(tick, jitteredMs(test.interval_sec)));
    timers.set(id, handle);
  }

  function clearAllTimers() {
    for (const h of timers.values()) clearTimeoutFn(h);
    timers.clear();
  }

  // Sends everything buffered as one batch. Only clears the buffer on a
  // successful send; on failure the rows are put back (honouring the overflow cap).
  function flush() {
    if (buffer.size() === 0) return false;
    const batch = buffer.drain();
    let delivered = false;
    try { delivered = !!send({ type: 'transaction_result', results: batch }); } catch { delivered = false; }
    if (!delivered) { buffer.pushAll(batch); return false; }
    return true;
  }

  // Applies a freshly pushed config: persist, drop timers for removed tests,
  // (re)schedule the rest.
  function applyConfig(newTests) {
    tests = Array.isArray(newTests) ? newTests : [];
    configStore.save(tests);
    const keep = new Set(tests.filter((t) => t.enabled !== false).map((t) => t.id));
    for (const id of [...timers.keys()]) {
      if (!keep.has(id)) { clearTimeoutFn(timers.get(id)); timers.delete(id); }
    }
    if (started) for (const t of tests) if (t.enabled !== false) scheduleTest(t);
    logger.info(`transaction config applied: ${tests.length} test(s).`);
  }

  function start() {
    started = true;
    // No pushed config yet (e.g. offline restart): run the persisted one.
    if (!tests.length) tests = configStore.load();
    for (const t of tests) if (t.enabled !== false) scheduleTest(t);
  }

  function stop() {
    started = false;
    clearAllTimers();
    // A capture must never outlive the manager that started it.
    if (capture) { try { Promise.resolve(capture.cancel()).catch(() => {}); } catch { /* best-effort */ } }
  }

  // Runs one assigned test NOW, out of band, and returns its result. This is
  // what a "test it while I watch" from the dashboard drives: the fault is
  // happening, and waiting out the interval is waiting out the fault. The result
  // goes through the same buffer as a scheduled run, so it lands in the same
  // history rather than in a parallel one.
  //
  // `capture: true` forces the packets to be kept whatever the test's own mode
  // says — somebody asked for this run specifically, and it is the one run where
  // the answer is wanted whether or not it failed.
  async function runNow(testId, { capture: forceCapture = false } = {}) {
    const id = Number(testId);
    const test = tests.find((t) => Number(t.id) === id);
    if (!test) return { ok: false, error: 'this agent is not assigned that test' };
    if (running.has(id)) return { ok: false, error: 'that test is already running on this agent' };
    running.add(id);
    try {
      const result = await runOnce(test, { force: !!forceCapture });
      buffer.push(result);
      flush();
      return { ok: true, result };
    } finally {
      running.delete(id);
    }
  }

  return { applyConfig, flush, start, stop, runNow, _tests: () => tests, _timerCount: () => timers.size };
}

module.exports = { createTransactionManager };
