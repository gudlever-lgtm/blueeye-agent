'use strict';

const { runTransaction } = require('./executors');

const silentLogger = { info() {}, warn() {}, error() {} };

// Ties the transaction executor set to the WS channel:
//   - receives pushed config (applyConfig) and persists it locally,
//   - schedules each enabled test on its own interval_sec with ±10% jitter so
//     tests don't clump,
//   - runs the executor, buffers the result, and flushes the buffer as a batch
//     `transaction_result` frame (whenever a send succeeds, and on reconnect),
//   - on restart (start() with no pushed config yet) it loads the persisted
//     config so tests keep running without server contact.
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
}) {
  let tests = [];
  let started = false;
  const timers = new Map(); // testId -> timer

  // interval_sec ± 10%, in ms. Guards against a missing/small interval.
  function jitteredMs(intervalSec) {
    const sec = Number.isFinite(intervalSec) && intervalSec >= 5 ? intervalSec : 60;
    return Math.round(sec * 1000 * (0.9 + random() * 0.2));
  }

  function unrefed(handle) { if (handle && typeof handle.unref === 'function') handle.unref(); return handle; }

  function scheduleTest(test) {
    const id = test.id;
    const tick = async () => {
      let result;
      try {
        result = await run(test, executorDeps);
      } catch (err) {
        result = { test_id: id, time: new Date().toISOString(), status: 'error', latency_ms: 0, detail: { phase: 'error', errno: (err && err.code) || 'RUN_ERROR' } };
      }
      buffer.push(result);
      flush();
      // Reschedule only if still active and not replaced/removed.
      if (started && timers.has(id)) timers.set(id, unrefed(setTimeoutFn(tick, jitteredMs(test.interval_sec))));
    };
    if (timers.has(id)) clearTimeoutFn(timers.get(id));
    timers.set(id, unrefed(setTimeoutFn(tick, jitteredMs(test.interval_sec))));
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
  }

  return { applyConfig, flush, start, stop, _tests: () => tests, _timerCount: () => timers.size };
}

module.exports = { createTransactionManager };
