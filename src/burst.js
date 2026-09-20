'use strict';

const { runProbe } = require('./probes');

const silentLogger = { info() {}, warn() {}, error() {}, debug() {} };

// Burst mode: measure one target once a second for up to two minutes, and
// stream every sample as it happens.
//
// WHY. The agent reports on a 60-second interval and the analysis baselines are
// hourly, so a five-second loss event is invisible — the fault a technician is
// standing in front of, on the phone, right now, does not exist in the data.
// This is the tool for that moment: not a new metric, a temporary resolution.
//
// THE CAPS ARE ENFORCED HERE, NOT ONLY IN THE SERVER'S VALIDATION.
//
// A burst is a PACKET GENERATOR. The server validates what it sends, but the
// agent is the thing that actually emits the packets, and it must not be able
// to be talked into a flood by a wrong number, a replayed frame or a future
// version of the server with a bug in it. A caller that asks for an hour at
// 50 Hz gets two minutes at 2 Hz, and the reply says what was clamped — the one
// place in this stage where clamping beats refusing, because the technician is
// mid-fault and a rejection helps nobody.
const MAX_SECONDS = 120;
const MAX_HZ = 2;
const MIN_HZ = 0.2; // one sample every five seconds; below that use a probe

// Bounds one number into a range, reporting whether it had to move.
function clampNum(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return { value: fallback, clamped: false };
  if (n < min) return { value: min, clamped: true };
  if (n > max) return { value: max, clamped: true };
  return { value: n, clamped: false };
}

// Normalises a burst request into what will actually be run.
function planBurst(spec = {}) {
  const seconds = clampNum(spec.seconds, 60, 1, MAX_SECONDS);
  const hz = clampNum(spec.hz, 1, MIN_HZ, MAX_HZ);
  const clamped = [];
  if (seconds.clamped) clamped.push('seconds');
  if (hz.clamped) clamped.push('hz');
  return {
    target: String((spec.target || spec.host || '')).trim(),
    // Only the probe types that make sense once a second. A traceroute or a
    // page load takes longer than the interval, so offering them would mean
    // every tick overlapping the last.
    probe: ['ping', 'tcp', 'dns'].includes(spec.probe) ? spec.probe : 'ping',
    port: Number.isInteger(spec.port) && spec.port > 0 && spec.port < 65536 ? spec.port : null,
    // Payload size, for the MTU-shaped faults a burst is good at catching.
    size: Number.isInteger(spec.size) && spec.size > 0 && spec.size <= 9000 ? spec.size : null,
    df: spec.df === true,
    seconds: Math.round(seconds.value),
    hz: hz.value,
    clamped,
  };
}

function createBurstRunner({
  probeRunner = runProbe,
  logger = silentLogger,
  now = () => Date.now(),
  // Injected so tests advance a fake clock instead of waiting two minutes.
  sleep = (ms) => new Promise((resolve) => { const t = setTimeout(resolve, ms); if (t.unref) t.unref(); }),
} = {}) {
  // ONE AT A TIME. Two concurrent bursts double the packet rate and the second
  // one's samples interleave with the first's in the stream, which would make
  // both unreadable.
  let running = false;
  let cancelled = false;

  function isRunning() { return running; }

  // Asks a running burst to stop at its next tick. The technician watching the
  // chart saw what they needed; finishing the remaining 90 seconds serves
  // nobody.
  function cancel() {
    if (running) cancelled = true;
    return running;
  }

  // Runs one burst. `onSample` is called per tick so the dashboard can draw the
  // chart live; it is best-effort and a throw there never stops the run.
  //
  // Never throws: this is driven by a server command and a failure must come
  // back as a reply, not as an unhandled rejection.
  async function run(spec, { onSample = null } = {}) {
    const plan = planBurst(spec);
    if (!plan.target) {
      return { ok: false, error: 'a burst needs a target', plan };
    }
    if (running) {
      // Refused, not queued: by the time a queued burst ran, the fault it was
      // meant to catch would be minutes old.
      return { ok: false, error: 'a burst is already running on this agent', plan };
    }

    running = true;
    cancelled = false;
    const startedAt = now();
    const samples = [];
    const intervalMs = Math.round(1000 / plan.hz);
    const total = Math.max(1, Math.round(plan.seconds * plan.hz));

    try {
      for (let i = 0; i < total; i += 1) {
        if (cancelled) break;
        const tickAt = now();

        let result;
        try {
          result = await probeRunner({
            type: plan.probe,
            host: plan.target,
            // One measurement per tick. A count above 1 would make each tick
            // take longer than the interval it is supposed to fit in.
            count: 1,
            port: plan.port || undefined,
            sizes: plan.size ? [plan.size] : undefined,
            df: plan.df || undefined,
            timeoutMs: Math.min(intervalMs, 2000),
          });
        } catch (err) {
          // runProbe does not throw, but an injected one might. A bad tick is a
          // LOST sample, which is a real measurement, not a failed run.
          result = { ok: false, error: err && err.message };
        }

        const sample = {
          t: Math.round((tickAt - startedAt) / 100) / 10, // seconds from start, 0.1 s
          ok: !!(result && result.ok),
          rttMs: result && Number.isFinite(result.rttMs) ? result.rttMs : null,
        };
        samples.push(sample);

        if (onSample) {
          try { onSample(sample, { index: i, total }); } catch { /* drawing is not the measurement */ }
        }

        if (i < total - 1 && !cancelled) {
          // Subtract the time the probe itself took, so the CADENCE stays at
          // 1 Hz rather than drifting to "1 Hz plus however long a ping takes".
          // A chart whose x-axis is a lie is worse than no chart.
          const spent = now() - tickAt;
          await sleep(Math.max(0, intervalMs - spent));
        }
      }

      return {
        ok: true,
        plan,
        startedAt: new Date(startedAt).toISOString(),
        endedAt: new Date(now()).toISOString(),
        cancelled,
        samples,
      };
    } finally {
      running = false;
      cancelled = false;
    }
  }

  return { run, cancel, isRunning, planBurst };
}

module.exports = {
  createBurstRunner,
  planBurst,
  MAX_SECONDS,
  MAX_HZ,
  MIN_HZ,
};
