'use strict';

const { pollSnmpTopology } = require('./snmpTopology');
const { pollSnmpCounters } = require('./snmp/counters');

const silentLogger = { info() {}, warn() {}, error() {}, debug() {} };

// Polls the switches the server assigned to THIS agent, alongside the agent's
// own traffic sampling.
//
// WHAT THIS REPLACES. SNMP was bound 1:1 — `monitorConfig.source = 'snmp'` makes
// the whole agent poll one remote device INSTEAD of its own /proc, so a site
// with twelve switches needed twelve agents. This poller takes a LIST
// (`snmpTargets` in the server-assigned config) and polls all of them without
// touching the traffic source, so one agent covers a wiring closet.
//
// `monitorConfig` is untouched: an agent already deployed with
// `source: 'snmp'` keeps doing exactly what it did, and an agent too old to
// know `snmpTargets` ignores the unknown key — the backward-compatibility
// contract this repo already relies on.
//
// EACH DEVICE IS INDEPENDENT. One switch timing out, refusing the community or
// answering garbage must cost that device's turn and nothing else. A cycle
// reports every result it got plus a per-device error for the ones it did not,
// so the dashboard can say "sw-lager-1: timeout, 41 minutes ago" instead of
// showing a blank where four switches used to be.

// A device's own interval is respected, but never faster than this: a full
// bridge-table walk is the expensive call on this path and a tight loop against
// a production switch is a way to become the outage.
const MIN_INTERVAL_SEC = 60;

// The COUNTER cycle is a different shape from the topology cycle, and that is
// the point of having two.
//
// A forwarding table is a snapshot of where things are; polling it every five
// minutes is generous. Interface counters are a TIME SERIES, and the gap
// between samples is the measurement's resolution — a 5-minute counter cannot
// show a two-minute error burst at all. So counters run on their own, faster
// interval.
//
// Which immediately hits the wall the audit called out: the topology cycle is
// deliberately SEQUENTIAL, and twenty devices at a 30-second timeout is ten
// minutes in the worst case, against a wanted interval of sixty seconds. One
// minute of polling for twenty switches cannot be done one at a time.
//
// So the counter cycle runs a BOUNDED number at once. Not Promise.all over
// everything — that is the burst that looks like a scan, and it is exactly what
// the sequential rule was protecting against. Four at a time is enough to fit
// twenty devices into a minute with a 30-second worst case, and small enough
// that the traffic out of one agent still looks like monitoring.
const COUNTER_MIN_INTERVAL_SEC = 30;
const COUNTER_DEFAULT_INTERVAL_SEC = 60;
const COUNTER_CONCURRENCY = 4;

// How long one device gets before its turn is abandoned. A switch that has
// stopped answering must not hold the cycle open for the others.
const DEFAULT_TIMEOUT_MS = 30000;

// NOT unref'd, deliberately — unlike the long-running timers elsewhere in this
// runtime. This timer exists to ABANDON a hung poll, so it has to keep the
// event loop alive until it fires: an unref'd one lets the loop drain while a
// device that never answers leaves the cycle open forever. It is bounded
// (30 s by default) and always cleared in the finally, so it can never linger.
function withTimeout(promise, ms, host) {
  let timer = null;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      const err = new Error(`SNMP poll of ${host} timed out after ${ms}ms.`);
      err.code = 'SNMP_TIMEOUT';
      reject(err);
    }, ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

// A target the server sent WITHOUT a credential, and why.
//
// The server resolves one credential per device — the device's own, the
// community it names, its site's communities in order, the global default —
// and an agent may only walk with a community assigned to it. When none of
// that lands, the device is still sent, because "sw-lager-1: no SNMP
// community assigned" on the dashboard is worth far more than a switch that
// silently never appears.
//
// It is checked HERE rather than left to the session: this cycle knows which
// of the two reasons it is, and "this agent is not assigned it" sends an admin
// to a different screen than "this site has none configured". Nothing is sent
// on the wire either way — a walk with a guessed community string is a scan.
function credentialError(device) {
  if (device.community || (device.v3 && device.v3.user)) return null;
  const err = new Error(device.credentialBlocked
    ? `No SNMP community: this agent is not assigned one that covers ${device.host}.`
    : `No SNMP community is configured for ${device.host}.`);
  err.code = 'SNMP_NO_CREDENTIAL';
  return err;
}

function createSnmpPoller({
  submit,
  // Counters go to their own endpoint at their own cadence. Null disables the
  // counter cycle entirely, which is what an older server (or a fleet that does
  // not want the volume) gets.
  submitCounters = null,
  logger = silentLogger,
  poll = pollSnmpTopology,
  pollCounters = pollSnmpCounters,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  counterConcurrency = COUNTER_CONCURRENCY,
  now = () => Date.now(),
} = {}) {
  let targets = [];
  // deviceId -> ms epoch of the last attempt (success or failure). A device
  // that keeps failing waits out its own interval like any other, rather than
  // being retried every tick.
  const lastAttempt = new Map();
  // The same, for the counter cycle. Kept apart on purpose: a device whose
  // bridge-table walk is timing out may well still answer a counter read, and
  // one cycle's bad luck must not stall the other's schedule.
  const lastCounterAttempt = new Map();
  let timer = null;
  let counterTimer = null;
  let running = false;
  let counterRunning = false;

  // Replaces the target list. Devices that disappeared from the config lose
  // their schedule state with them.
  function setTargets(list) {
    const next = Array.isArray(list) ? list.filter((d) => d && typeof d.host === 'string' && d.host) : [];
    targets = next;
    const live = new Set(next.map((d) => d.deviceId));
    for (const id of [...lastAttempt.keys()]) {
      if (!live.has(id)) lastAttempt.delete(id);
    }
    for (const id of [...lastCounterAttempt.keys()]) {
      if (!live.has(id)) lastCounterAttempt.delete(id);
    }
    return targets.length;
  }

  function due(device, t) {
    const interval = Math.max(Number(device.intervalSec) || 300, MIN_INTERVAL_SEC) * 1000;
    const last = lastAttempt.get(device.deviceId);
    return last == null || (t - last) >= interval;
  }

  // Polls every device whose interval has elapsed and submits one batch.
  // Never throws: this runs on a timer nobody is watching.
  // `onResult` is called per successful device, before the batch is submitted.
  // The runtime uses it to remember interface names, so a trap saying
  // "ifIndex 1" can be shown as "GigabitEthernet0/1" — the poll already read
  // that table, and re-reading it for the trap path would be a second walk of
  // the same data.
  async function runCycle({ force = false, onResult = null } = {}) {
    if (running) return { polled: 0, failed: 0, skipped: true };
    running = true;
    try {
      const t = now();
      const batch = targets.filter((d) => force || due(d, t));
      if (!batch.length) return { polled: 0, failed: 0 };

      const devices = [];
      const errors = [];

      // Sequential, not parallel. Ten simultaneous bridge-table walks out of one
      // host is a burst that looks like a scan to anything watching the network,
      // and the whole point of the per-device interval is that this work is not
      // urgent.
      for (const device of batch) {
        lastAttempt.set(device.deviceId, now());
        try {
          const missing = credentialError(device);
          if (missing) throw missing;
          const result = await withTimeout(poll({ device }), timeoutMs, device.host);
          devices.push(result);
          // Best-effort: a consumer that throws must not cost the poll that
          // already succeeded.
          if (onResult) {
            try { onResult(result); } catch { /* not this cycle's problem */ }
          }
        } catch (err) {
          errors.push({
            deviceId: device.deviceId,
            error: String((err && err.message) || 'poll failed').slice(0, 255),
            code: (err && err.code) || null,
          });
          logger.warn(`SNMP poll of ${device.host} failed: ${err && err.message}`);
        }
      }

      if (devices.length || errors.length) {
        try {
          await submit({ devices, errors });
        } catch (err) {
          // A submit failure is the caller's to classify (a 401 is fatal
          // upstream). The poll results are NOT held for a retry: they are a
          // snapshot of a forwarding table, and a stale snapshot re-sent later
          // would claim a device was somewhere it has since left.
          logger.warn(`Could not submit SNMP topology (${err && err.message}).`);
          throw err;
        }
      }
      return { polled: devices.length, failed: errors.length };
    } finally {
      running = false;
    }
  }

  // Is this device due for a COUNTER read? Its own interval, floored, and
  // defaulting faster than the topology one because a counter's interval IS the
  // measurement's resolution.
  function counterDue(device, t) {
    const wanted = Number(device.counterIntervalSec) || COUNTER_DEFAULT_INTERVAL_SEC;
    const interval = Math.max(wanted, COUNTER_MIN_INTERVAL_SEC) * 1000;
    const last = lastCounterAttempt.get(device.deviceId);
    return last == null || (t - last) >= interval;
  }

  // Which devices want counters at all. `collect` is the same list the topology
  // poller reads; a device that does not ask for 'ifcounters' is simply not in
  // this cycle, so the volume is opt-in per device.
  function wantsCounters(device) {
    const collect = Array.isArray(device.collect) ? device.collect : [];
    return collect.includes('ifcounters');
  }

  // Runs `limit` at a time over a list, in order. Not Promise.all (a burst that
  // looks like a scan) and not a strict sequence (twenty devices at a 30-second
  // worst case does not fit in a minute). Never throws: each task's own failure
  // is its own.
  async function inBatches(items, limit, task) {
    const queue = [...items];
    const workers = [];
    for (let i = 0; i < Math.max(1, limit); i += 1) {
      workers.push((async () => {
        for (;;) {
          const item = queue.shift();
          if (item === undefined) return;
          await task(item);
        }
      })());
    }
    await Promise.all(workers);
  }

  // One counter cycle. Reads every due device's interface counters and submits
  // them as ONE batch.
  //
  // Never throws, and never holds results for a retry: a counter snapshot is
  // only meaningful next to the reading before it, and re-sending a stale one
  // later would have the server compute a rate over a gap that never happened.
  async function runCounterCycle({ force = false } = {}) {
    if (!submitCounters) return { polled: 0, failed: 0, skipped: true };
    if (counterRunning) return { polled: 0, failed: 0, skipped: true };
    counterRunning = true;
    try {
      const t = now();
      const batch = targets.filter((d) => wantsCounters(d) && (force || counterDue(d, t)));
      if (!batch.length) return { polled: 0, failed: 0 };

      const devices = [];
      const errors = [];
      await inBatches(batch, counterConcurrency, async (device) => {
        lastCounterAttempt.set(device.deviceId, now());
        try {
          const missing = credentialError(device);
          if (missing) throw missing;
          const result = await withTimeout(pollCounters({ device }), timeoutMs, device.host);
          devices.push(result);
        } catch (err) {
          errors.push({
            deviceId: device.deviceId,
            error: String((err && err.message) || 'counter poll failed').slice(0, 255),
            code: (err && err.code) || null,
          });
          logger.warn(`SNMP counter poll of ${device.host} failed: ${err && err.message}`);
        }
      });

      if (devices.length || errors.length) {
        try {
          await submitCounters({ devices, errors });
        } catch (err) {
          logger.warn(`Could not submit SNMP counters (${err && err.message}).`);
          throw err;
        }
      }
      return { polled: devices.length, failed: errors.length };
    } finally {
      counterRunning = false;
    }
  }

  // The tick is deliberately short and cheap: it only asks which devices are
  // due. The per-device interval decides what actually gets polled.
  //
  // `cycle` is what a tick runs. The runtime passes its own wrapper, so a
  // SCHEDULED cycle gets the same treatment as a forced poll-snmp: the
  // per-device onResult hook (interface names for the trap resolver), the
  // last-submit time on the diagnose snapshot, and — the one that mattered — a
  // 401 on the submit reaching the runtime's fatal handling instead of being
  // swallowed here on every tick for ever. Without one, a tick runs a bare
  // cycle, as it always did.
  function start({ tickMs = 30000, cycle = null } = {}) {
    stop();
    if (!tickMs || tickMs <= 0) return;
    const run = typeof cycle === 'function' ? cycle : () => runCycle();
    timer = setInterval(() => {
      Promise.resolve().then(run).catch(() => { /* the cycle already logged; never unhandled */ });
    }, tickMs);
    if (timer.unref) timer.unref();
  }

  // The counter tick, on its own timer. Separate from the topology one because
  // the two cadences are different by design and a slow bridge-table walk must
  // not delay a counter read. `cycle` as for start().
  function startCounters({ tickMs = 15000, cycle = null } = {}) {
    stopCounters();
    if (!submitCounters || !tickMs || tickMs <= 0) return;
    const run = typeof cycle === 'function' ? cycle : () => runCounterCycle();
    counterTimer = setInterval(() => {
      Promise.resolve().then(run).catch(() => { /* the cycle already logged */ });
    }, tickMs);
    if (counterTimer.unref) counterTimer.unref();
  }

  function stopCounters() {
    if (counterTimer) {
      clearInterval(counterTimer);
      counterTimer = null;
    }
  }

  function stop() {
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
    stopCounters();
  }

  function stats() {
    return {
      targets: targets.length,
      devices: targets.map((d) => ({
        deviceId: d.deviceId,
        host: d.host,
        intervalSec: Math.max(Number(d.intervalSec) || 300, MIN_INTERVAL_SEC),
        lastAttemptAt: lastAttempt.has(d.deviceId) ? new Date(lastAttempt.get(d.deviceId)).toISOString() : null,
      })),
    };
  }

  return { setTargets, runCycle, runCounterCycle, start, startCounters, stop, stopCounters, stats };
}

module.exports = {
  createSnmpPoller,
  credentialError,
  MIN_INTERVAL_SEC,
  DEFAULT_TIMEOUT_MS,
  COUNTER_MIN_INTERVAL_SEC,
  COUNTER_DEFAULT_INTERVAL_SEC,
  COUNTER_CONCURRENCY,
};
