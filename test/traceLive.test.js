'use strict';

// A traceroute run on demand streams each hop over the WebSocket as the binary
// prints it, so the dashboard can draw the path while the trace is running.
// The submitted result stays the record; the stream is a courtesy.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');

const { traceroute, streamHops } = require('../src/probes/traceroute');
const { tcptraceroute } = require('../src/probes/tcptraceroute');
const { startFakeServer } = require('../test-support/fakeServer');
const { createAgentRuntime } = require('../src/runtime');
const { silentLogger } = require('../src/logger');

const LINUX_OUT = [
  'traceroute to us.cnn.com (151.101.1.67), 20 hops max, 60 byte packets',
  ' 1  192.168.1.1  0.512 ms  0.480 ms  0.470 ms',
  ' 2  * * *',
  ' 3  151.101.1.67  98.1 ms  98.4 ms  98.9 ms',
  '',
].join('\n');

// An exec that behaves like execFile: returns a child whose stdout emits the
// output in awkward chunks (split mid-line), then calls back with all of it.
function chunkedExec(out, chunks = 7) {
  return (_bin, _args, _opts, cb) => {
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    const size = Math.ceil(out.length / chunks);
    setImmediate(() => {
      for (let i = 0; i < out.length; i += size) child.stdout.emit('data', Buffer.from(out.slice(i, i + size)));
      cb(null, out, '');
    });
    return child;
  };
}

test('traceroute calls onHop once per hop, in order, even when lines arrive split', async () => {
  const seen = [];
  const res = await traceroute({ host: 'us.cnn.com' }, { exec: chunkedExec(LINUX_OUT), platform: 'linux', onHop: (h) => seen.push(h) });
  assert.deepEqual(seen.map((h) => h.hop), [1, 2, 3]);
  assert.equal(seen[1].ip, null);
  assert.equal(seen[1].lossPct, 100);
  assert.equal(seen[2].ip, '151.101.1.67');
  // The streamed hops are the same records the result carries.
  assert.deepEqual(seen, res.hops);
});

test('Windows CRLF output streams the same hops', async () => {
  const out = [
    'Tracing route to 151.101.1.67 over a maximum of 20 hops', '',
    '  1    <1 ms    <1 ms    <1 ms  192.168.1.1',
    '  2    12 ms    11 ms    13 ms  62.61.1.1', '', 'Trace complete.', '',
  ].join('\r\n');
  const seen = [];
  await traceroute({ host: '151.101.1.67' }, { exec: chunkedExec(out, 5), platform: 'win32', onHop: (h) => seen.push(h) });
  assert.deepEqual(seen.map((h) => [h.hop, h.ip]), [[1, '192.168.1.1'], [2, '62.61.1.1']]);
});

test('a listener that throws does not break the trace', async () => {
  const res = await traceroute({ host: 'us.cnn.com' }, { exec: chunkedExec(LINUX_OUT), platform: 'linux', onHop: () => { throw new Error('socket gone'); } });
  assert.equal(res.ok, true);
  assert.equal(res.hops.length, 3);
});

test('an exec without a stdout stream (the old fakes) still works, just without streaming', async () => {
  const exec = (_b, _a, _o, cb) => { setImmediate(() => cb(null, LINUX_OUT, '')); return undefined; };
  const seen = [];
  const res = await traceroute({ host: 'us.cnn.com' }, { exec, platform: 'linux', onHop: (h) => seen.push(h) });
  assert.equal(res.hops.length, 3);
  assert.equal(seen.length, 0);
  assert.doesNotThrow(() => streamHops(null, 3, () => {}));
});

test('tcptraceroute streams hops too', async () => {
  const seen = [];
  const res = await tcptraceroute({ host: 'us.cnn.com', port: 443 }, { exec: chunkedExec(LINUX_OUT), onHop: (h) => seen.push(h) });
  assert.equal(res.target, 'us.cnn.com:443');
  assert.deepEqual(seen.map((h) => h.hop), [1, 2, 3]);
});

// ---- over the wire --------------------------------------------------------

function withTimeout(p, ms, msg) {
  let timer;
  return Promise.race([p, new Promise((_, rej) => { timer = setTimeout(() => rej(new Error(msg)), ms); })]).finally(() => clearTimeout(timer));
}
const onceEvent = (em, ev) => new Promise((resolve) => em.once(ev, resolve));
const noopHsflowd = {
  enable: async () => ({ state: 'active', detail: null }),
  disable: async () => ({ state: 'inactive', detail: null }),
  status: async () => ({ state: 'unknown', detail: null }),
};
const makeConfig = (server) => ({
  serverUrl: server.url, heartbeatMs: 10000, backoff: { baseMs: 30, maxMs: 120, factor: 2 },
  reportIntervalMs: 0, probeIntervalMs: 0, syslogEnabled: false,
});

test('an on-demand traceroute sends a trace_hop frame per hop, then submits the result', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  // A probe runner that behaves like runProbe: it hands the per-type deps to
  // the traceroute runner, which streams through onHop.
  const probeRunner = async (spec, deps = {}) => ({
    ts: new Date().toISOString(),
    ...(await traceroute(spec, { exec: chunkedExec(LINUX_OUT), platform: 'linux', ...(deps.traceroute || {}) })),
  });
  const runtime = createAgentRuntime({
    config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger, hsflowdManager: noopHsflowd, probeRunner,
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config loaded');
    const submitted = onceEvent(runtime, 'probe-submitted');
    server.sendCommandToAll({ name: 'run-probe', probe: { type: 'traceroute', host: 'us.cnn.com' } });
    const { result } = await withTimeout(submitted, 4000, 'probe not submitted');
    assert.equal(result.hops.length, 3);

    await withTimeout(server.waitForWsMessage((m) => m.type === 'trace_hop' && m.hop && m.hop.hop === 3), 4000, 'hop 3 not streamed');
    const frames = server.receivedWsMessages.filter((m) => m.type === 'trace_hop');
    assert.deepEqual(frames.map((m) => m.hop.hop), [1, 2, 3]);
    assert.ok(frames.every((m) => m.target === 'us.cnn.com' && m.probeType === 'traceroute'));
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('a non-trace probe gets no live deps and sends no trace_hop frames', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  let gotDeps = 'unset';
  const probeRunner = async (spec, deps) => { gotDeps = deps; return { ts: new Date().toISOString(), type: 'ping', target: spec.host, ok: true, rttMs: 3 }; };
  const runtime = createAgentRuntime({
    config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger, hsflowdManager: noopHsflowd, probeRunner,
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config loaded');
    const submitted = onceEvent(runtime, 'probe-submitted');
    server.sendCommandToAll({ name: 'run-probe', probe: { type: 'ping', host: '1.1.1.1' } });
    await withTimeout(submitted, 4000, 'probe not submitted');
    assert.equal(gotDeps, undefined);
    assert.equal(server.receivedWsMessages.filter((m) => m.type === 'trace_hop').length, 0);
  } finally {
    runtime.stop();
    await server.close();
  }
});
