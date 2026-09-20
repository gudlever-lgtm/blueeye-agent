'use strict';

const { pollSnmpTopology } = require('./snmpTopology');

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

function createSnmpPoller({
  submit,
  logger = silentLogger,
  poll = pollSnmpTopology,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  now = () => Date.now(),
} = {}) {
  let targets = [];
  // deviceId -> ms epoch of the last attempt (success or failure). A device
  // that keeps failing waits out its own interval like any other, rather than
  // being retried every tick.
  const lastAttempt = new Map();
  let timer = null;
  let running = false;

  // Replaces the target list. Devices that disappeared from the config lose
  // their schedule state with them.
  function setTargets(list) {
    const next = Array.isArray(list) ? list.filter((d) => d && typeof d.host === 'string' && d.host) : [];
    targets = next;
    const live = new Set(next.map((d) => d.deviceId));
    for (const id of [...lastAttempt.keys()]) {
      if (!live.has(id)) lastAttempt.delete(id);
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
  async function runCycle({ force = false } = {}) {
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
          const result = await withTimeout(poll({ device }), timeoutMs, device.host);
          devices.push(result);
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

  // The tick is deliberately short and cheap: it only asks which devices are
  // due. The per-device interval decides what actually gets polled.
  function start({ tickMs = 30000 } = {}) {
    stop();
    if (!tickMs || tickMs <= 0) return;
    timer = setInterval(() => {
      runCycle().catch(() => { /* runCycle already logged; never unhandled */ });
    }, tickMs);
    if (timer.unref) timer.unref();
  }

  function stop() {
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
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

  return { setTargets, runCycle, start, stop, stats };
}

module.exports = { createSnmpPoller, MIN_INTERVAL_SEC, DEFAULT_TIMEOUT_MS };
