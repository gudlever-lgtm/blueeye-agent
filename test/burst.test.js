'use strict';

// Tests for burst mode (src/burst.js) and its wiring into the runtime.
//
// A burst is a PACKET GENERATOR. The server validates what it sends, but the
// agent is the thing that actually emits the packets, so the caps are asserted
// HERE — a wrong number, a replayed frame or a future server with a bug in it
// must not be able to turn this into a flood.
//
// The clock and the sleep are injected, so a two-minute burst runs instantly
// and the cadence can be measured rather than waited out.

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { createBurstRunner, planBurst, MAX_SECONDS, MAX_HZ } = require('../src/burst');
const { startFakeServer } = require('../test-support/fakeServer');
const { createAgentRuntime } = require('../src/runtime');
const { silentLogger } = require('../src/logger');

// A clock the test drives, and a sleep that advances it instead of waiting.
function fakeClock(start = 1_000_000) {
  let t = start;
  return {
    now: () => t,
    sleep: async (ms) => { t += ms; },
    advance: (ms) => { t += ms; },
    at: () => t,
  };
}

const okProbe = (rttMs = 1.4) => async () => ({ ok: true, rttMs });

// ------------------------------------------------------------------ the plan
test('a request beyond the caps is CLAMPED, and the reply says what moved', () => {
  // The one place in this feature where clamping beats refusing: the
  // technician is mid-fault, and a rejection helps nobody.
  const plan = planBurst({ target: '10.14.0.11', seconds: 3600, hz: 50 });
  assert.equal(plan.seconds, MAX_SECONDS);
  assert.equal(plan.hz, MAX_HZ);
  assert.deepEqual(plan.clamped.sort(), ['hz', 'seconds']);
});

test('a sensible request passes through untouched', () => {
  const plan = planBurst({ target: '10.14.0.11', seconds: 60, hz: 1 });
  assert.equal(plan.seconds, 60);
  assert.equal(plan.hz, 1);
  assert.deepEqual(plan.clamped, []);
});

test('only probes that FIT in one tick are offered', () => {
  // A traceroute or a page load takes longer than the interval, so every tick
  // would overlap the last.
  assert.equal(planBurst({ target: 'x', probe: 'traceroute' }).probe, 'ping');
  assert.equal(planBurst({ target: 'x', probe: 'pageload' }).probe, 'ping');
  assert.equal(planBurst({ target: 'x', probe: 'tcp' }).probe, 'tcp');
  assert.equal(planBurst({ target: 'x', probe: 'dns' }).probe, 'dns');
});

test('junk in the plan never produces junk out', () => {
  for (const bad of [undefined, null, {}, { seconds: 'lots', hz: NaN }, { seconds: -5, hz: -1 }]) {
    const plan = planBurst(bad || {});
    assert.ok(plan.seconds >= 1 && plan.seconds <= MAX_SECONDS, JSON.stringify(bad));
    assert.ok(plan.hz > 0 && plan.hz <= MAX_HZ);
  }
});

// ------------------------------------------------------------------ the caps
test('the caps are enforced by the AGENT, not only by server validation', async () => {
  // A server with a bug, a replayed frame, or a hand-crafted command must not
  // be able to make this emit an hour of packets at 50 Hz.
  const clock = fakeClock();
  let probes = 0;
  const runner = createBurstRunner({
    probeRunner: async () => { probes += 1; return { ok: true, rttMs: 1 }; },
    now: clock.now,
    sleep: clock.sleep,
  });
  const r = await runner.run({ target: '10.14.0.11', seconds: 100000, hz: 1000 });
  assert.equal(r.ok, true);
  assert.equal(probes, MAX_SECONDS * MAX_HZ, 'two minutes at 2 Hz, and not one packet more');
  assert.equal(r.samples.length, probes);
});

test('two bursts at once are refused, not queued', async () => {
  // Two concurrent bursts double the packet rate and interleave their samples
  // in the stream, making both unreadable. By the time a queued one ran, the
  // fault it was meant to catch would be minutes old.
  const clock = fakeClock();
  const runner = createBurstRunner({ probeRunner: okProbe(), now: clock.now, sleep: clock.sleep });

  let secondResult = null;
  const first = runner.run({ target: '10.14.0.11', seconds: 5, hz: 1 }, {
    onSample: async (_s, p) => {
      if (p.index === 0 && !secondResult) {
        secondResult = await runner.run({ target: '10.14.0.12', seconds: 5, hz: 1 });
      }
    },
  });
  await first;
  assert.equal(secondResult.ok, false);
  assert.match(secondResult.error, /already running/);
});

test('a burst with no target is refused before a single packet', async () => {
  const runner = createBurstRunner({ probeRunner: async () => { throw new Error('should not probe'); } });
  const r = await runner.run({ seconds: 10 });
  assert.equal(r.ok, false);
  assert.match(r.error, /needs a target/);
});

// -------------------------------------------------------------- the cadence
test('the probe time is subtracted so the cadence stays at 1 Hz', async () => {
  // A chart whose x-axis is a lie is worse than no chart: without this the
  // interval becomes "1 second PLUS however long a ping takes", and every
  // timestamp drifts.
  const clock = fakeClock();
  const slept = [];
  const runner = createBurstRunner({
    probeRunner: async () => { clock.advance(300); return { ok: true, rttMs: 300 }; },
    now: clock.now,
    sleep: async (ms) => { slept.push(ms); clock.advance(ms); },
  });
  await runner.run({ target: '10.14.0.11', seconds: 4, hz: 1 });
  assert.deepEqual(slept, [700, 700, 700], 'each wait is 1000 minus the 300 the probe took');
});

test('a probe slower than the interval does not produce a negative wait', async () => {
  const clock = fakeClock();
  const slept = [];
  const runner = createBurstRunner({
    probeRunner: async () => { clock.advance(2500); return { ok: false }; },
    now: clock.now,
    sleep: async (ms) => { slept.push(ms); clock.advance(ms); },
  });
  await runner.run({ target: '10.14.0.11', seconds: 3, hz: 1 });
  assert.ok(slept.every((ms) => ms >= 0), 'never a negative sleep');
});

test('sample timestamps are seconds from the start, not wall clock', async () => {
  const clock = fakeClock();
  const runner = createBurstRunner({ probeRunner: okProbe(), now: clock.now, sleep: clock.sleep });
  const r = await runner.run({ target: '10.14.0.11', seconds: 4, hz: 1 });
  assert.deepEqual(r.samples.map((s) => s.t), [0, 1, 2, 3]);
});

// ---------------------------------------------------------------- the samples
test('a failed probe is a LOST sample, which is a real measurement', async () => {
  // Loss is the thing this tool exists to catch; a tick that failed is the
  // signal, not an error.
  const clock = fakeClock();
  let n = 0;
  const runner = createBurstRunner({
    probeRunner: async () => { n += 1; return n === 2 ? { ok: false } : { ok: true, rttMs: 1.4 }; },
    now: clock.now,
    sleep: clock.sleep,
  });
  const r = await runner.run({ target: '10.14.0.11', seconds: 3, hz: 1 });
  assert.deepEqual(r.samples.map((s) => s.ok), [true, false, true]);
  assert.equal(r.samples[1].rttMs, null);
});

test('a probe runner that THROWS is also a lost sample, not a failed run', async () => {
  const clock = fakeClock();
  const runner = createBurstRunner({
    probeRunner: async () => { throw new Error('socket exploded'); },
    now: clock.now,
    sleep: clock.sleep,
  });
  const r = await runner.run({ target: '10.14.0.11', seconds: 3, hz: 1 });
  assert.equal(r.ok, true);
  assert.equal(r.samples.length, 3);
  assert.ok(r.samples.every((s) => s.ok === false));
});

test('every sample is streamed as it happens', async () => {
  const clock = fakeClock();
  const seen = [];
  const runner = createBurstRunner({ probeRunner: okProbe(), now: clock.now, sleep: clock.sleep });
  await runner.run({ target: '10.14.0.11', seconds: 5, hz: 1 }, {
    onSample: (s, p) => seen.push([s.t, p.index, p.total]),
  });
  assert.equal(seen.length, 5);
  assert.deepEqual(seen[0], [0, 0, 5]);
  assert.deepEqual(seen[4], [4, 4, 5]);
});

test('a streaming callback that throws never stops the measurement', async () => {
  // Drawing is a courtesy; the measurement is the point.
  const clock = fakeClock();
  const runner = createBurstRunner({ probeRunner: okProbe(), now: clock.now, sleep: clock.sleep });
  const r = await runner.run({ target: '10.14.0.11', seconds: 4, hz: 1 }, {
    onSample: () => { throw new Error('chart is on fire'); },
  });
  assert.equal(r.ok, true);
  assert.equal(r.samples.length, 4);
});

// ------------------------------------------------------------------- stopping
test('a burst stops at the next tick when asked', async () => {
  const clock = fakeClock();
  const runner = createBurstRunner({ probeRunner: okProbe(), now: clock.now, sleep: clock.sleep });
  const r = await runner.run({ target: '10.14.0.11', seconds: 120, hz: 1 }, {
    onSample: (_s, p) => { if (p.index === 2) runner.cancel(); },
  });
  assert.equal(r.cancelled, true);
  assert.equal(r.samples.length, 3, 'the tick in flight finishes; the next does not start');
});

test('cancelling when nothing runs is a no-op that says so', () => {
  const runner = createBurstRunner({ probeRunner: okProbe() });
  assert.equal(runner.cancel(), false);
  assert.equal(runner.isRunning(), false);
});

test('a burst that ends releases the slot', async () => {
  const clock = fakeClock();
  const runner = createBurstRunner({ probeRunner: okProbe(), now: clock.now, sleep: clock.sleep });
  await runner.run({ target: '10.14.0.11', seconds: 2, hz: 1 });
  assert.equal(runner.isRunning(), false);
  assert.equal((await runner.run({ target: '10.14.0.11', seconds: 2, hz: 1 })).ok, true);
});

// ------------------------------------------------------------------ the wire
function withTimeout(promise, ms, message) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(message || `timeout after ${ms}ms`)), ms);
    timer.unref();
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}
const onceEvent = (emitter, name) => new Promise((resolve) => emitter.once(name, resolve));
const noopHsflowd = {
  enable: async () => ({ state: 'active', detail: null }),
  disable: async () => ({ state: 'inactive', detail: null }),
  status: async () => ({ state: 'unknown', detail: null }),
};
const makeConfig = (server) => ({
  serverUrl: server.url, heartbeatMs: 10000, backoff: { baseMs: 30, maxMs: 120, factor: 2 },
  reportIntervalMs: 0, probeIntervalMs: 0, syslogEnabled: false,
});

test('a burst command streams samples and replies with the whole series', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const clock = fakeClock();
  const runtime = createAgentRuntime({
    config: makeConfig(server),
    token: 'valid', agentId: 1, logger: silentLogger, hsflowdManager: noopHsflowd,
    burstRunner: createBurstRunner({ probeRunner: okProbe(1.4), now: clock.now, sleep: clock.sleep }),
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config loaded');

    const reply = server.waitForWsMessage((m) => m.type === 'command-result' && m.id === 'b1');
    server.sendCommandToAll({ name: 'burst', id: 'b1', target: '10.14.0.11', seconds: 5, hz: 1 });
    const msg = await withTimeout(reply, 4000, 'no burst reply');

    assert.equal(msg.ok, true);
    assert.equal(msg.burst.samples.length, 5);
    assert.equal(msg.burst.plan.target, '10.14.0.11');

    // The live stream: one frame per sample, before the reply.
    const streamed = server.receivedWsMessages.filter((m) => m.type === 'burst_sample' && m.id === 'b1');
    assert.equal(streamed.length, 5);
    assert.equal(streamed[0].total, 5);
    assert.equal(streamed[0].sample.t, 0);
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('a burst command with no target is refused over the wire too', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const runtime = createAgentRuntime({
    config: makeConfig(server),
    token: 'valid', agentId: 1, logger: silentLogger, hsflowdManager: noopHsflowd,
    burstRunner: createBurstRunner({ probeRunner: async () => { throw new Error('should not probe'); } }),
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config loaded');

    // Not recognised as a burst at all — a burst with no target is a packet
    // generator with no destination — so it falls through to "unrecognised".
    const ignored = onceEvent(runtime, 'command-ignored');
    server.sendCommandToAll({ name: 'burst', id: 'b2' });
    const cmd = await withTimeout(ignored, 4000, 'not ignored');
    assert.equal(cmd.name, 'burst');
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('stop-burst stops a running one and answers either way', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const clock = fakeClock();
  const runtime = createAgentRuntime({
    config: makeConfig(server),
    token: 'valid', agentId: 1, logger: silentLogger, hsflowdManager: noopHsflowd,
    burstRunner: createBurstRunner({ probeRunner: okProbe(), now: clock.now, sleep: clock.sleep }),
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config loaded');

    const reply = server.waitForWsMessage((m) => m.type === 'command-result' && m.id === 's9');
    server.sendCommandToAll({ name: 'stop-burst', id: 's9' });
    const msg = await withTimeout(reply, 4000, 'no stop reply');
    assert.equal(msg.ok, true);
    assert.equal(msg.stopped, false, 'nothing was running, and it says so');
  } finally {
    runtime.stop();
    await server.close();
  }
});
