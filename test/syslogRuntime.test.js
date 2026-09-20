'use strict';

// Integration tests for the syslog receiver's wiring into the agent runtime:
// the flush loop, the failure paths, and the diagnose snapshot.
//
// The receiver is INJECTED (a stub exposing the same start/drain/stats/stop
// contract) so these tests never bind a port — what is under test here is the
// runtime's handling of it, not the socket code, which syslogReceiver.test.js
// covers against injected sockets.

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { startFakeServer } = require('../test-support/fakeServer');
const { createAgentRuntime } = require('../src/runtime');
const { silentLogger } = require('../src/logger');

function withTimeout(promise, ms, message) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(message || `timeout after ${ms}ms`)), ms);
    timer.unref();
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}
const onceEvent = (emitter, name) => new Promise((resolve) => emitter.once(name, resolve));

const makeConfig = (server, extra = {}) => ({
  serverUrl: server.url,
  heartbeatMs: 10000,
  backoff: { baseMs: 30, maxMs: 120, factor: 2 },
  reportIntervalMs: 0, // no traffic reporting noise in these tests
  probeIntervalMs: 0,
  syslogEnabled: true,
  syslogFlushIntervalMs: 0, // flush only when the test asks
  ...extra,
});

const noopHsflowd = {
  enable: async () => ({ state: 'active', detail: null }),
  disable: async () => ({ state: 'inactive', detail: null }),
  status: async () => ({ state: 'unknown', detail: null }),
};

const EVENT = {
  sourceIp: '10.14.0.11',
  receivedAt: '2026-09-20T09:41:12.418Z',
  deviceTime: '2026-09-20T09:41:09.000Z',
  clockSkewMs: 3418,
  transport: 'syslog',
  facility: 23,
  severity: 2,
  eventType: 'link.down',
  host: 'sw-core-1',
  tag: '%LINK-3-UPDOWN',
  ifname: 'GigabitEthernet0/1',
  summary: 'Interface GigabitEthernet0/1, changed state to down',
  raw: '<186>Sep 20 09:41:09 sw-core-1 %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down',
  occurrences: 1,
};

// A receiver stub with the same contract as the real one.
function stubReceiver({ events = [], failStart = null, stats = {} } = {}) {
  let queued = [...events];
  let stopped = false;
  let started = false;
  return {
    start: async () => {
      if (failStart) throw failStart;
      started = true;
      return { udp: true, tcp: true, port: 1514 };
    },
    drain: () => { const out = queued; queued = []; return out; },
    stats: () => ({ port: 1514, udp: true, tcp: true, buffered: queued.length, received: events.length, dropped: 0, unparsed: 0, overflowed: 0, senders: 1, lastAt: null, ...stats }),
    stop: () => { stopped = true; },
    push: (e) => queued.push(e),
    wasStarted: () => started,
    wasStopped: () => stopped,
  };
}

test('buffered device events are flushed to the server', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const rx = stubReceiver({ events: [EVENT] });
  const runtime = createAgentRuntime({
    config: makeConfig(server),
    token: 'valid',
    agentId: 1,
    logger: silentLogger,
    hsflowdManager: noopHsflowd,
    syslogReceiver: rx,
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config loaded');

    const sent = await runtime.flushDeviceEventsNow();
    assert.equal(sent, 1);
    assert.equal(server.receivedDeviceEvents.length, 1);
    const [batch] = server.receivedDeviceEvents;
    assert.equal(batch.token, 'valid');
    assert.equal(batch.events[0].eventType, 'link.down');
    assert.equal(batch.events[0].ifname, 'GigabitEthernet0/1');
    assert.equal(batch.events[0].clockSkewMs, 3418);
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('an empty buffer sends nothing at all', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const runtime = createAgentRuntime({
    config: makeConfig(server),
    token: 'valid',
    agentId: 1,
    logger: silentLogger,
    hsflowdManager: noopHsflowd,
    syslogReceiver: stubReceiver({ events: [] }),
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config loaded');
    assert.equal(await runtime.flushDeviceEventsNow(), 0);
    assert.equal(server.receivedDeviceEvents.length, 0, 'no empty batches on the wire');
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('a receiver that cannot bind does not stop the agent', async () => {
  // A host where something already holds 1514 must still report traffic and run
  // probes. The failure is reported, not fatal.
  const server = await startFakeServer({ validTokens: ['valid'] });
  const bindErr = new Error('EADDRINUSE');
  bindErr.code = 'SYSLOG_BIND_FAILED';
  const runtime = createAgentRuntime({
    config: makeConfig(server),
    token: 'valid',
    agentId: 1,
    logger: silentLogger,
    hsflowdManager: noopHsflowd,
    syslogReceiver: stubReceiver({ failStart: bindErr }),
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config loaded');
    // The runtime is alive and still answers a ping.
    const ack = server.waitForWsMessage((m) => m.type === 'ack' && m.id === 'p1');
    server.sendCommandToAll({ name: 'ping', id: 'p1' });
    assert.equal((await withTimeout(ack, 4000, 'no ping ack')).ok, true);
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('a rejected token during flush is fatal, as everywhere else', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const runtime = createAgentRuntime({
    config: makeConfig(server),
    token: 'valid',
    agentId: 1,
    logger: silentLogger,
    hsflowdManager: noopHsflowd,
    syslogReceiver: stubReceiver({ events: [EVENT] }),
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config loaded');
    const fatal = onceEvent(runtime, 'fatal');
    server.revokeAllTokens();
    await runtime.flushDeviceEventsNow();
    assert.equal(await withTimeout(fatal, 4000, 'no fatal emitted'), 'rest-token-rejected');
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('drained events are not re-queued when the server is unreachable', async () => {
  // Holding them would mean the agent accumulates an outage's worth of log
  // lines in memory on a host it does not own. The receiver's bounded buffer
  // exists so this process never becomes the outage; the counters record the
  // gap so it is visible rather than silent.
  const server = await startFakeServer({ validTokens: ['valid'] });
  const rx = stubReceiver({ events: [EVENT] });
  const runtime = createAgentRuntime({
    config: makeConfig(server, { serverUrl: 'http://127.0.0.1:1' }),
    token: 'valid',
    agentId: 1,
    logger: silentLogger,
    hsflowdManager: noopHsflowd,
    syslogReceiver: rx,
  });
  try {
    assert.equal(await runtime.flushDeviceEventsNow(), 0, 'the POST failed');
    assert.deepEqual(rx.drain(), [], 'and the events were not put back');
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('the diagnose snapshot carries the receiver counters', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const runtime = createAgentRuntime({
    config: makeConfig(server),
    token: 'valid',
    agentId: 1,
    logger: silentLogger,
    hsflowdManager: noopHsflowd,
    syslogReceiver: stubReceiver({ events: [EVENT], stats: { dropped: 7, overflowed: 2 } }),
  });
  try {
    runtime.start();
    // Wait for the BIND, not just the config: startSyslog() runs after
    // loadServerConfig() in the bootstrap, so 'config' alone would race it.
    await withTimeout(onceEvent(runtime, 'syslog'), 4000, 'receiver never bound');

    const reply = server.waitForWsMessage((m) => m.type === 'command-result' && m.id === 'd1');
    server.sendCommandToAll({ name: 'diagnose', id: 'd1' });
    const msg = await withTimeout(reply, 4000, 'no diagnose reply');

    assert.equal(msg.ok, true);
    assert.equal(msg.diagnostic.syslog.port, 1514);
    assert.equal(msg.diagnostic.syslog.dropped, 7);
    assert.equal(msg.diagnostic.syslog.overflowed, 2);
    assert.deepEqual(msg.diagnostic.syslog.bound, { udp: true, tcp: true, port: 1514 });
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('with syslog disabled nothing binds and the snapshot says so', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const runtime = createAgentRuntime({
    config: makeConfig(server, { syslogEnabled: false }),
    token: 'valid',
    agentId: 1,
    logger: silentLogger,
    hsflowdManager: noopHsflowd,
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config loaded');

    const reply = server.waitForWsMessage((m) => m.type === 'command-result' && m.id === 'd2');
    server.sendCommandToAll({ name: 'diagnose', id: 'd2' });
    const msg = await withTimeout(reply, 4000, 'no diagnose reply');
    assert.equal(msg.diagnostic.syslog, null);
    assert.equal(await runtime.flushDeviceEventsNow(), 0);
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('stopping the runtime stops the receiver', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const rx = stubReceiver({ events: [] });
  const runtime = createAgentRuntime({
    config: makeConfig(server),
    token: 'valid',
    agentId: 1,
    logger: silentLogger,
    hsflowdManager: noopHsflowd,
    syslogReceiver: rx,
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config loaded');
    runtime.stop();
    assert.equal(rx.wasStopped(), true);
  } finally {
    await server.close();
  }
});
