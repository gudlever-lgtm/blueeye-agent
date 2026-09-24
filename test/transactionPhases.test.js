'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { EventEmitter } = require('events');

const { createPhaseTimer, watchSocket } = require('../src/transactions/phases');
const { httpExecutor } = require('../src/transactions/executors/http');
const { tcpExecutor } = require('../src/transactions/executors/tcp');
const { runTransaction } = require('../src/transactions/executors');
const { createResultBuffer } = require('../src/transactions/buffer');
const { createTransactionManager } = require('../src/transactions/manager');
const { shouldCapture, shouldKeep, captureSeconds, modeOf } = require('../src/transactions/capturePolicy');

// ---------------------------------------------------------------- phase timer

test('phases: deltas between marks, and they sum to the step time', () => {
  let t = 1000;
  const timer = createPhaseTimer({ now: () => t });
  t = 1012; timer.mark('dns');
  t = 1043; timer.mark('tcp');
  t = 1121; timer.mark('tls');
  t = 5171; timer.mark('ttfb');
  t = 5200;
  const p = timer.phases();
  assert.deepEqual([p.dns, p.tcp, p.tls, p.ttfb, p.transfer], [12, 31, 78, 4050, 29]);
  assert.equal(p.dns + p.tcp + p.tls + p.ttfb + p.transfer, 4200, 'the split accounts for the whole step');
});

test('phases: a missing middle mark widens its neighbour rather than losing the time', () => {
  let t = 0;
  const timer = createPhaseTimer({ now: () => t });
  t = 10; timer.mark('dns');
  t = 40; timer.mark('tcp');
  // no TLS — a plain http step
  t = 140; timer.mark('ttfb');
  t = 150;
  const p = timer.phases();
  assert.equal(p.tls, null, 'a phase that never happened is null, not zero');
  assert.equal(p.ttfb, 100, 'and its time lands in the next phase, not nowhere');
});

test('phases: a step that never got a first byte reports no transfer', () => {
  let t = 0;
  const timer = createPhaseTimer({ now: () => t });
  t = 30; timer.mark('tcp');
  t = 15030; // timed out waiting for a response
  const p = timer.phases();
  assert.equal(p.ttfb, null);
  assert.equal(p.transfer, null, 'a body that never arrived must not read as a download');
});

test('phases: the first mark wins, so a retry inside a step keeps the real handshake', () => {
  let t = 0;
  const timer = createPhaseTimer({ now: () => t });
  t = 30; timer.mark('tcp');
  t = 900; timer.mark('tcp');
  assert.equal(timer.phases().tcp, 30);
});

test('phases: a reused keep-alive socket is recorded as reused, not as an instant handshake', () => {
  const timer = createPhaseTimer({ now: () => 0 });
  const socket = new EventEmitter();
  socket.connecting = false;
  socket.remoteAddress = '10.0.0.2';
  socket.localPort = 51234;
  socket.remotePort = 443;
  watchSocket(timer, socket);
  const p = timer.phases();
  assert.equal(p.reused, true);
  assert.equal(p.tcp, null, 'no handshake happened — reporting 0 ms would invent one');
  assert.equal(p.localPort, 51234);
});

test('phases: the resolved address and the local port are recorded from the socket', () => {
  let t = 0;
  const timer = createPhaseTimer({ now: () => t });
  const socket = new EventEmitter();
  socket.connecting = true;
  watchSocket(timer, socket);
  t = 12; socket.emit('lookup', null, '10.20.1.40');
  socket.remoteAddress = '10.20.1.40'; socket.localPort = 51234; socket.remotePort = 443;
  t = 43; socket.emit('connect');
  const p = timer.phases();
  assert.equal(p.address, '10.20.1.40');
  assert.equal(p.localPort, 51234);
  assert.equal(p.remotePort, 443);
  assert.equal(p.dns, 12);
  assert.equal(p.tcp, 31);
});

// ---------------------------------------------------------------- executors

// A fake http impl that emits a socket, so the phase marks are exercised.
function fakeHttpWithSocket({ status = 200, body = 'ok', socketEvents = true, clock }) {
  return {
    request(u, opts, cb) {
      const req = new EventEmitter();
      req.write = () => {}; req.destroy = () => {};
      const socket = new EventEmitter();
      socket.connecting = true;
      req.end = () => {
        setImmediate(() => {
          req.emit('socket', socket);
          if (socketEvents) {
            clock.t += 12; socket.emit('lookup', null, '10.20.1.40');
            socket.remoteAddress = '10.20.1.40'; socket.localPort = 51234; socket.remotePort = 443;
            clock.t += 31; socket.emit('connect');
            clock.t += 78; socket.emit('secureConnect');
          }
          clock.t += 4050;
          const res = new EventEmitter();
          res.setEncoding = () => {};
          res.statusCode = status;
          res.headers = {};
          cb(res);
          setImmediate(() => { clock.t += 29; res.emit('data', body); res.emit('end'); });
        });
      };
      return req;
    },
  };
}

test('http executor: reports the phase split alongside the step time', async () => {
  const clock = { t: 0 };
  const out = await httpExecutor(
    { type: 'http', config: { steps: [{ url: 'https://app.kunde.dk/login' }] } },
    { httpsImpl: fakeHttpWithSocket({ clock }), httpImpl: fakeHttpWithSocket({ clock }), now: () => clock.t },
  );
  assert.equal(out.status, 'ok');
  assert.equal(out.step_phases.length, 1);
  const p = out.step_phases[0];
  assert.equal(p.dns, 12);
  assert.equal(p.tcp, 31, 'the TCP handshake IS the network round-trip time');
  assert.equal(p.tls, 78);
  assert.equal(p.ttfb, 4050, 'and this is the server thinking, which the old single number hid');
  assert.equal(p.address, '10.20.1.40');
  assert.equal(p.localPort, 51234);
});

test('http executor: a failed step still reports where the time went', async () => {
  const clock = { t: 0 };
  const impl = {
    request(u, opts, cb) {
      const req = new EventEmitter();
      req.write = () => {}; req.destroy = () => {};
      const socket = new EventEmitter();
      socket.connecting = true;
      req.end = () => setImmediate(() => {
        req.emit('socket', socket);
        clock.t += 30;
        socket.remoteAddress = '10.0.0.2'; socket.localPort = 40001;
        socket.emit('connect');
        clock.t += 15000;
        req.emit('timeout');
      });
      return req;
    },
  };
  const out = await httpExecutor(
    { type: 'http', config: { steps: [{ url: 'http://x/y' }], timeout_ms: 15000 } },
    { httpImpl: impl, httpsImpl: impl, now: () => clock.t },
  );
  assert.equal(out.status, 'timeout');
  const p = out.step_phases[0];
  assert.equal(p.tcp, 30, 'the handshake completed in 30 ms…');
  assert.equal(p.ttfb, null, '…and then the server said nothing at all');
});

test('http executor: an injected impl that never emits a socket still returns a result', async () => {
  const clock = { t: 0 };
  const out = await httpExecutor(
    { type: 'http', config: { steps: [{ url: 'http://x/y' }] } },
    { httpImpl: fakeHttpWithSocket({ clock, socketEvents: false }), httpsImpl: fakeHttpWithSocket({ clock, socketEvents: false }), now: () => clock.t },
  );
  assert.equal(out.status, 'ok');
  assert.equal(out.step_phases[0].tcp, null);
});

test('tcp executor: splits resolution from the handshake', async () => {
  const clock = { t: 0 };
  const socket = new EventEmitter();
  socket.connecting = true;
  socket.setTimeout = () => {};
  socket.destroy = () => {};
  const p = tcpExecutor(
    { type: 'tcp', target: 'db01', config: { port: 5432 } },
    { connect: () => socket, now: () => clock.t },
  );
  setImmediate(() => {
    clock.t += 850; socket.emit('lookup', null, '10.0.0.9');
    socket.remoteAddress = '10.0.0.9'; socket.localPort = 40002; socket.remotePort = 5432;
    clock.t += 31; socket.emit('connect');
  });
  const out = await p;
  assert.equal(out.status, 'ok');
  assert.equal(out.phases.dns, 850, 'a 900 ms connect that was mostly DNS is a different fault');
  assert.equal(out.phases.tcp, 31);
});

test('runTransaction: single-step executors get the same array shape as http', async () => {
  const clock = { t: 0 };
  const socket = new EventEmitter();
  socket.connecting = true;
  socket.setTimeout = () => {};
  socket.destroy = () => {};
  const p = runTransaction(
    { id: 3, type: 'tcp', target: 'db01', config: { port: 5432 } },
    { connect: () => socket, now: () => clock.t },
  );
  setImmediate(() => { clock.t += 20; socket.emit('connect'); });
  const out = await p;
  assert.ok(Array.isArray(out.step_phases), 'one wire shape for every type');
  assert.equal(out.step_phases.length, 1);
  assert.equal(out.phases, undefined, 'and the singular form does not also go out');
});

test('runTransaction: an executor with no phases to report sends none', async () => {
  const out = await runTransaction(
    { id: 4, type: 'icmp', target: '10.0.0.1', config: {} },
    { exec: (bin, args, opts, cb) => cb(null, '1 packets transmitted, 1 received, 0% packet loss\nrtt min/avg/max/mdev = 1.0/1.1/1.2/0.1 ms'), platform: 'linux' },
  );
  assert.equal(out.status, 'ok');
  assert.equal(out.step_phases, undefined, 'an absent breakdown must not become an array of nulls');
});

// ---------------------------------------------------------------- policy

test('capturePolicy: off never starts a capture; the other modes do', () => {
  assert.equal(shouldCapture({ capture: 'off' }), false);
  assert.equal(shouldCapture({}), false, 'and off is the default');
  assert.equal(shouldCapture({ capture: 'on_fault' }), true);
  assert.equal(shouldCapture({ capture: 'always' }), true);
  assert.equal(modeOf({ capture: 'nonsense' }), 'off', 'an unknown mode falls back to off, never to on');
});

test('capturePolicy: on_fault keeps a failure and discards a pass', () => {
  assert.equal(shouldKeep({ capture: 'on_fault' }, { status: 'ok' }).keep, false);
  for (const status of ['fail', 'timeout', 'error']) {
    const d = shouldKeep({ capture: 'on_fault' }, { status });
    assert.equal(d.keep, true, status);
    assert.equal(d.reason, `status:${status}`, 'and the row says why it exists');
  }
});

test('capturePolicy: on_fault also keeps a pass that broke the latency threshold', () => {
  const test4s = { capture: 'on_fault', config: { thresholds: { latency_ms: 1000 } } };
  assert.equal(shouldKeep(test4s, { status: 'ok', latency_ms: 4200 }).keep, true);
  assert.equal(shouldKeep(test4s, { status: 'ok', latency_ms: 200 }).keep, false);
  assert.match(shouldKeep(test4s, { status: 'ok', latency_ms: 4200 }).reason, /^latency:4200ms>1000ms$/);
});

test('capturePolicy: capture length follows the test timeout, and is bounded', () => {
  assert.equal(captureSeconds({ config: { timeout_ms: 5000 } }), 7);
  assert.equal(captureSeconds({ config: { timeout_ms: 15000, steps: [1, 2, 3] } }), 30, 'clamped');
  assert.equal(captureSeconds({ config: {} }), 15, 'a test with no timeout gets the default');
});

// ---------------------------------------------------------------- manager

function fakeCapture({ packets = [], ok = true, reason = 'nope' } = {}) {
  const calls = { started: 0, stopped: [], cancelled: 0 };
  return {
    calls,
    async start() {
      calls.started += 1;
      if (!ok) return { ok: false, reason };
      return {
        ok: true,
        session: {
          async stop(opts) {
            calls.stopped.push(opts);
            if (!opts.keep) return { kept: false, packets: [], durationMs: 10 };
            return {
              kept: true, packets, durationMs: 10, iface: 'eth0', filter: '(host 10.0.0.2 and tcp port 443)',
              snaplen: 96, observed: packets.length, dropped: 0, foreign: 0, truncated: false,
            };
          },
        },
      };
    },
    async cancel() { calls.cancelled += 1; return true; },
  };
}

function managerWith({ capture, run, sent }) {
  const scheduled = [];
  const m = createTransactionManager({
    send: (o) => { sent.push(o); return true; },
    configStore: { save() {}, load: () => [] },
    buffer: createResultBuffer(),
    run,
    capture,
    setTimeoutFn: (fn) => { scheduled.push(fn); return { unref() {} }; },
    clearTimeoutFn: () => {},
    random: () => 0.5,
  });
  return { m, scheduled };
}

test('manager: a test with capture off never starts one', async () => {
  const sent = [];
  const capture = fakeCapture();
  const { m, scheduled } = managerWith({ capture, sent, run: async (t) => ({ test_id: t.id, status: 'fail' }) });
  m.applyConfig([{ id: 1, type: 'tcp', target: 'db', interval_sec: 60, enabled: true, capture: 'off' }]);
  m.start();
  await scheduled[scheduled.length - 1]();
  assert.equal(capture.calls.started, 0);
});

test('manager: on_fault starts a capture every run and keeps only the failures', async () => {
  const sent = [];
  const capture = fakeCapture({ packets: [{ t: 0, flags: 'S' }] });
  let status = 'ok';
  const { m, scheduled } = managerWith({ capture, sent, run: async (t) => ({ test_id: t.id, time: 'T', status, latency_ms: 5 }) });
  m.applyConfig([{ id: 1, type: 'http', interval_sec: 60, enabled: true, capture: 'on_fault', config: { steps: [{ url: 'https://a/b' }] } }]);
  m.start();

  await scheduled[scheduled.length - 1]();
  assert.equal(capture.calls.started, 1, 'a capture runs even on a passing run…');
  assert.equal(capture.calls.stopped[0].keep, false, '…and is thrown away');
  assert.ok(!sent.some((f) => f.type === 'transaction_capture'), 'nothing is sent for a run that passed');

  status = 'timeout';
  await scheduled[scheduled.length - 1]();
  const frame = sent.find((f) => f.type === 'transaction_capture');
  assert.ok(frame, 'the failing run ships its packets');
  assert.equal(frame.test_id, 1);
  assert.equal(frame.capture.reason, 'status:timeout');
  assert.equal(frame.capture.packets.length, 1);
});

test('manager: the capture frame is matched to its result by test_id + time', async () => {
  const sent = [];
  const capture = fakeCapture({ packets: [{ t: 0 }] });
  const { m, scheduled } = managerWith({ capture, sent, run: async (t) => ({ test_id: t.id, time: '2026-01-01T00:00:00.000Z', status: 'fail' }) });
  m.applyConfig([{ id: 9, type: 'http', interval_sec: 60, enabled: true, capture: 'on_fault', config: { steps: [{ url: 'https://a/b' }] } }]);
  m.start();
  await scheduled[scheduled.length - 1]();
  const result = sent.find((f) => f.type === 'transaction_result').results[0];
  const cap = sent.find((f) => f.type === 'transaction_capture');
  assert.equal(cap.test_id, result.test_id);
  assert.equal(cap.time, result.time, 'the two frames carry the same key, so neither has to arrive first');
});

test('manager: a capture that cannot start never stops the test running', async () => {
  const sent = [];
  const capture = fakeCapture({ ok: false, reason: 'tcpdump is not installed' });
  const { m, scheduled } = managerWith({ capture, sent, run: async (t) => ({ test_id: t.id, time: 'T', status: 'fail' }) });
  m.applyConfig([{ id: 1, type: 'http', interval_sec: 60, enabled: true, capture: 'on_fault', config: { steps: [{ url: 'https://a/b' }] } }]);
  m.start();
  await scheduled[scheduled.length - 1]();
  assert.equal(sent.filter((f) => f.type === 'transaction_result').length, 1, 'the measurement still happened');
  assert.ok(!sent.some((f) => f.type === 'transaction_capture'));
});

test('manager: the local ports the run used are what narrows the capture', async () => {
  const sent = [];
  const capture = fakeCapture({ packets: [{ t: 0 }] });
  const { m, scheduled } = managerWith({
    capture,
    sent,
    run: async (t) => ({ test_id: t.id, time: 'T', status: 'fail', step_phases: [{ localPort: 51234 }, { localPort: 51235 }] }),
  });
  m.applyConfig([{ id: 1, type: 'http', interval_sec: 60, enabled: true, capture: 'on_fault', config: { steps: [{ url: 'https://a/b' }] } }]);
  m.start();
  await scheduled[scheduled.length - 1]();
  assert.deepEqual(capture.calls.stopped[0].observedPorts, [51234, 51235]);
});

test('manager: runNow runs an assigned test out of band and keeps its capture', async () => {
  const sent = [];
  const capture = fakeCapture({ packets: [{ t: 0 }] });
  const { m } = managerWith({ capture, sent, run: async (t) => ({ test_id: t.id, time: 'T', status: 'ok', latency_ms: 3 }) });
  m.applyConfig([{ id: 5, type: 'http', interval_sec: 60, enabled: true, config: { steps: [{ url: 'https://a/b' }] } }]);
  const out = await m.runNow(5, { capture: true });
  assert.equal(out.ok, true);
  assert.equal(out.result.test_id, 5);
  const cap = sent.find((f) => f.type === 'transaction_capture');
  assert.ok(cap, 'a run somebody asked for keeps its packets even though it passed');
  assert.equal(cap.capture.reason, 'requested');
  assert.ok(sent.some((f) => f.type === 'transaction_result'), 'and it lands in the same history as a scheduled run');
});

test('manager: runNow refuses a test this agent is not assigned', async () => {
  const sent = [];
  const { m } = managerWith({ capture: fakeCapture(), sent, run: async () => ({ status: 'ok' }) });
  m.applyConfig([{ id: 5, type: 'tcp', target: 'x', interval_sec: 60, enabled: true }]);
  const out = await m.runNow(99, {});
  assert.equal(out.ok, false);
  assert.match(out.error, /not assigned/);
});

test('manager: runNow refuses to run the same test twice at once', async () => {
  const sent = [];
  let release;
  const gate = new Promise((r) => { release = r; });
  const { m } = managerWith({ capture: null, sent, run: async (t) => { await gate; return { test_id: t.id, time: 'T', status: 'ok' }; } });
  m.applyConfig([{ id: 5, type: 'tcp', target: 'x', interval_sec: 60, enabled: true }]);
  const first = m.runNow(5, {});
  const second = await m.runNow(5, {});
  assert.equal(second.ok, false);
  assert.match(second.error, /already running/);
  release();
  assert.equal((await first).ok, true);
});

test('manager: stopping cancels any capture still running', async () => {
  const capture = fakeCapture();
  const { m } = managerWith({ capture, sent: [], run: async () => ({ status: 'ok' }) });
  m.start();
  m.stop();
  await new Promise((r) => setImmediate(r));
  assert.equal(capture.calls.cancelled, 1);
});
