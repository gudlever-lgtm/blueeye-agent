'use strict';

// Tests for the SNMP trap receiver (src/traps/) and its wiring into the agent
// runtime.
//
// A trap and a syslog line are the same thing arriving over a different socket,
// so these rows must come out in exactly the shape src/syslog/receiver.js
// produces — that is asserted here, because the server has one ingest route and
// a divergence would only show up in production.
//
// The decoder is injected, so every trap shape is exercised without net-snmp
// and without a switch.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('events');

const {
  translateTrap, trapOidOf, KNOWN_TRAP_OIDS, TRAP_EVENT_TYPES, UNKNOWN_TYPE,
} = require('../src/traps/translate');
const { createTrapReceiver } = require('../src/traps/receiver');
const { startFakeServer } = require('../test-support/fakeServer');
const { createAgentRuntime } = require('../src/runtime');
const { silentLogger } = require('../src/logger');

const OID_TRAP_OID = '1.3.6.1.6.3.1.1.4.1.0';
const OID_SYSUPTIME = '1.3.6.1.2.1.1.3.0';
const RECV = Date.UTC(2026, 8, 20, 9, 41, 11);

// The varbinds a real linkDown carries: sysUpTime, the trap identity, then the
// interface the trap is about.
const linkDown = (over = {}) => ([
  { oid: OID_SYSUPTIME, value: 123456 },
  { oid: OID_TRAP_OID, value: '1.3.6.1.6.3.1.1.5.3' },
  { oid: '1.3.6.1.2.1.2.2.1.1.1', value: 1 },                 // ifIndex
  { oid: '1.3.6.1.2.1.2.2.1.7.1', value: over.admin ?? 1 },   // ifAdminStatus
  { oid: '1.3.6.1.2.1.2.2.1.8.1', value: over.oper ?? 2 },    // ifOperStatus
]);

// ------------------------------------------------------------- translation
test('a linkDown becomes the same row shape a syslog line produces', () => {
  const r = translateTrap({ varbinds: linkDown(), sourceIp: '10.14.0.11', receivedAt: RECV });

  // The shape the server's ingest expects, field for field.
  assert.deepEqual(Object.keys(r).sort(), [
    'clockSkewMs', 'detail', 'deviceTime', 'eventType', 'facility', 'host',
    'ifname', 'occurrences', 'raw', 'receivedAt', 'severity', 'sourceIp',
    'summary', 'tag', 'transport',
  ]);
  assert.equal(r.transport, 'trap');
  assert.equal(r.eventType, 'link.down');
  assert.equal(r.severity, 2);
  assert.equal(r.sourceIp, '10.14.0.11');
  assert.equal(r.tag, '1.3.6.1.6.3.1.1.5.3');
  assert.equal(r.receivedAt, new Date(RECV).toISOString());
});

test('a trap carries no wall-clock time, so deviceTime and skew are null', () => {
  // sysUpTime is an uptime, not a date. Fabricating a timestamp from it would
  // put a made-up number in the column the clock-skew check reads.
  const r = translateTrap({ varbinds: linkDown(), sourceIp: '10.14.0.11', receivedAt: RECV });
  assert.equal(r.deviceTime, null);
  assert.equal(r.clockSkewMs, null);
  assert.equal(r.detail.upTimeTicks, 123456, 'but the uptime itself is kept');
});

test('the interface is named from what the topology poll already read', () => {
  // The poll walked ifName off this device; re-walking it for the trap path
  // would be a second read of the same table.
  const r = translateTrap({
    varbinds: linkDown(),
    sourceIp: '10.14.0.11',
    receivedAt: RECV,
    resolveIfName: (ifIndex) => (ifIndex === 1 ? 'GigabitEthernet0/1' : null),
  });
  assert.equal(r.ifname, 'GigabitEthernet0/1');
  assert.match(r.summary, /on GigabitEthernet0\/1/);
});

test('an unresolvable ifIndex is shown as an index, never a guessed name', () => {
  const r = translateTrap({ varbinds: linkDown(), sourceIp: '10.14.0.11', receivedAt: RECV });
  assert.equal(r.ifname, null);
  assert.match(r.summary, /on ifIndex 1/);
});

test('a resolver that throws costs the name, not the trap', () => {
  const r = translateTrap({
    varbinds: linkDown(), sourceIp: '10.14.0.11', receivedAt: RECV,
    resolveIfName: () => { throw new Error('nope'); },
  });
  assert.equal(r.ifname, null);
  assert.equal(r.eventType, 'link.down');
});

test('ifDescr in the trap wins over a resolver lookup', () => {
  const r = translateTrap({
    varbinds: [
      { oid: OID_TRAP_OID, value: '1.3.6.1.6.3.1.1.5.3' },
      { oid: '1.3.6.1.2.1.2.2.1.1.1', value: 1 },
      { oid: '1.3.6.1.2.1.2.2.1.2.1', value: Buffer.from('Gi0/1', 'utf8') },
    ],
    sourceIp: '10.14.0.11', receivedAt: RECV,
    resolveIfName: () => 'SomethingElse0/9',
  });
  assert.equal(r.ifname, 'Gi0/1', "the device's own description is the better answer");
});

test('an administratively-down port is not the same fault as one that fell over', () => {
  // Somebody turned this port off. That sends a technician somewhere entirely
  // different from a port that dropped on its own.
  const r = translateTrap({ varbinds: linkDown({ admin: 2, oper: 2 }), sourceIp: '10.14.0.11', receivedAt: RECV });
  assert.equal(r.eventType, 'link.admin_down');
  assert.equal(r.severity, 5, 'and it is not critical');
  assert.match(r.summary, /administratively down/);
});

test('an UNKNOWN trap is kept as its OID and never guessed', () => {
  // A trap labelled link.down that was actually something else has actively
  // misled somebody. Same rule the syslog classifier follows.
  const r = translateTrap({
    varbinds: [
      { oid: OID_TRAP_OID, value: '1.3.6.1.4.1.99999.1.2.3' },
      { oid: '1.3.6.1.4.1.99999.2.1', value: Buffer.from('vendor detail', 'utf8') },
    ],
    sourceIp: '10.14.0.11', receivedAt: RECV,
  });
  assert.equal(r.eventType, UNKNOWN_TYPE);
  assert.match(r.summary, /Unrecognised trap 1\.3\.6\.1\.4\.1\.99999\.1\.2\.3/);
  assert.equal(r.detail.trapOid, '1.3.6.1.4.1.99999.1.2.3');
  assert.ok(r.detail.varbinds.some((v) => v.value === 'vendor detail'), 'the varbinds survive for a human to read');
});

test('a trap with no trap OID at all is still recorded', () => {
  const r = translateTrap({ varbinds: [{ oid: OID_SYSUPTIME, value: 1 }], sourceIp: '10.14.0.11', receivedAt: RECV });
  assert.equal(r.eventType, UNKNOWN_TYPE);
  assert.match(r.summary, /no trap OID/);
});

test('the traps a technician actually chases are in the table', () => {
  const cases = [
    ['1.3.6.1.6.3.1.1.5.1', 'device.rebooted'],
    ['1.3.6.1.6.3.1.1.5.4', 'link.up'],
    ['1.3.6.1.6.3.1.1.5.5', 'auth.failure'],
    ['1.3.6.1.2.1.17.0.2', 'stp.topology_change'],
    ['1.3.6.1.2.1.17.0.1', 'stp.root_changed'],
    ['1.3.6.1.2.1.14.16.2.2', 'ospf.adjacency_lost'],
    ['1.3.6.1.2.1.15.7.2', 'bgp.session_down'],
    ['1.3.6.1.2.1.33.2.1', 'ups.on_battery'],
    ['1.3.6.1.4.1.9.9.13.3.0.4', 'fan.failed'],
    ['1.3.6.1.4.1.9.9.215.2.0.1', 'mac.flapping'],
  ];
  for (const [oid, expected] of cases) {
    const r = translateTrap({ varbinds: [{ oid: OID_TRAP_OID, value: oid }], sourceIp: '10.0.0.1', receivedAt: RECV });
    assert.equal(r.eventType, expected, oid);
  }
  assert.ok(KNOWN_TRAP_OIDS.length >= 35, `only ${KNOWN_TRAP_OIDS.length} trap OIDs`);
});

test('every trap event_type matches the shape the server validates', () => {
  // The server accepts a dotted lowercase identifier and falls back to
  // syslog.raw otherwise. A type this table produces must never be one the
  // boundary silently rewrites.
  const SHAPE = /^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)*$/;
  for (const type of TRAP_EVENT_TYPES) assert.match(type, SHAPE, type);
});

test('the varbind record is bounded', () => {
  const many = [{ oid: OID_TRAP_OID, value: '1.3.6.1.6.3.1.1.5.3' }];
  for (let i = 0; i < 200; i += 1) many.push({ oid: `1.3.6.1.4.1.1.${i}`, value: i });
  const r = translateTrap({ varbinds: many, sourceIp: '10.0.0.1', receivedAt: RECV });
  assert.ok(r.detail.varbinds.length <= 32, 'a bounded record, not a transcript');
});

test('translation survives junk without throwing', () => {
  for (const bad of [undefined, null, {}, { varbinds: null }, { varbinds: 'x' }, { varbinds: [null, 42] }]) {
    const r = translateTrap({ ...(bad || {}), sourceIp: '10.0.0.1', receivedAt: RECV });
    assert.equal(typeof r.summary, 'string');
  }
  assert.equal(trapOidOf([]), null);
});

// --------------------------------------------------------------- the receiver
function fakeSocket() {
  const sock = new EventEmitter();
  sock.bind = (port, addr, cb) => setImmediate(cb);
  sock.close = () => {};
  sock.deliver = (address = '10.14.0.11') => sock.emit('message', Buffer.from('x'), { address });
  return sock;
}

function build(opts = {}) {
  const socket = fakeSocket();
  const rx = createTrapReceiver({
    createSocket: () => socket,
    decode: opts.decode || (() => ({ varbinds: linkDown() })),
    isKnownSender: opts.isKnownSender || (() => true),
    ...opts.receiverOpts,
  });
  return { rx, socket };
}

test('a trap from a polled switch becomes a buffered row', async () => {
  const { rx, socket } = build();
  await rx.start();
  socket.deliver();
  const events = rx.drain();
  assert.equal(events.length, 1);
  assert.equal(events[0].transport, 'trap');
  assert.equal(events[0].eventType, 'link.down');
  rx.stop();
});

test('a trap from a device this agent does NOT poll is refused', async () => {
  // An SNMPv2c trap is unauthenticated: anyone who can route UDP here can claim
  // to be any switch. The source address is all we have, and it is the
  // strongest check v2c permits.
  const { rx, socket } = build({ isKnownSender: (ip) => ip === '10.14.0.11' });
  await rx.start();
  socket.deliver('10.14.0.11');
  socket.deliver('192.0.2.66');
  assert.equal(rx.drain().length, 1);
  assert.equal(rx.stats().refused, 1);
  rx.stop();
});

test('an unknown sender is refused BEFORE any decoding', async () => {
  // A hostile sender must not be able to make this process do work by sending
  // malformed packets.
  let decoded = 0;
  const { rx, socket } = build({
    isKnownSender: () => false,
    decode: () => { decoded += 1; return { varbinds: linkDown() }; },
  });
  await rx.start();
  socket.deliver('192.0.2.66');
  assert.equal(decoded, 0);
  assert.equal(rx.stats().refused, 1);
  rx.stop();
});

test('refused and rate-limited are counted separately', async () => {
  // "A switch nobody added is shouting at us" and "a device we poll is shouting
  // too fast" are different problems with different fixes.
  let clock = 1_000_000;
  const { rx, socket } = build({
    isKnownSender: (ip) => ip === '10.14.0.11',
    receiverOpts: { ratePerSec: 1, burst: 2, now: () => clock },
  });
  await rx.start();
  for (let i = 0; i < 5; i += 1) socket.deliver('10.14.0.11');
  for (let i = 0; i < 3; i += 1) socket.deliver('192.0.2.66');
  const s = rx.stats();
  assert.equal(s.dropped, 3);
  assert.equal(s.refused, 3);
  rx.stop();
});

test('an undecodable datagram is counted, not fatal', async () => {
  const { rx, socket } = build({ decode: () => { throw new Error('not SNMP'); } });
  await rx.start();
  socket.deliver();
  assert.deepEqual(rx.drain(), []);
  assert.equal(rx.stats().undecodable, 1);
  rx.stop();
});

test('repeats fold inside one window, like syslog', async () => {
  const { rx, socket } = build();
  await rx.start();
  socket.deliver();
  socket.deliver();
  socket.deliver();
  const events = rx.drain();
  assert.equal(events.length, 1);
  assert.equal(events[0].occurrences, 3);
  rx.stop();
});

test('the buffer is bounded', async () => {
  let n = 0;
  const { rx, socket } = build({
    decode: () => {
      n += 1;
      return { varbinds: [{ oid: OID_TRAP_OID, value: `1.3.6.1.4.1.9999.${n}` }] };
    },
    receiverOpts: { maxEvents: 3, ratePerSec: 1e6, burst: 1e6 },
  });
  await rx.start();
  for (let i = 0; i < 20; i += 1) socket.deliver();
  assert.equal(rx.drain().length, 3);
  assert.ok(rx.stats().overflowed >= 15);
  rx.stop();
});

test('the default port is 1162, not 162', () => {
  const rx = createTrapReceiver({ decode: () => ({ varbinds: [] }) });
  assert.equal(rx.stats().port, 1162);
});

test('an IPv4-mapped IPv6 sender is recorded as plain IPv4', async () => {
  const { rx, socket } = build();
  await rx.start();
  socket.deliver('::ffff:10.14.0.11');
  assert.equal(rx.drain()[0].sourceIp, '10.14.0.11');
  rx.stop();
});

// ---------------------------------------------------------------- the runtime
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

function stubTraps(events = []) {
  let queued = [...events];
  return {
    start: async () => ({ udp: true, port: 1162 }),
    drain: () => { const out = queued; queued = []; return out; },
    stats: () => ({ port: 1162, udp: true, buffered: queued.length, received: events.length, dropped: 0, refused: 2, undecodable: 0, overflowed: 0, senders: 1, lastAt: null }),
    stop: () => {},
  };
}

const TRAP_ROW = translateTrap({ varbinds: linkDown(), sourceIp: '10.14.0.11', receivedAt: RECV });

test('traps and syslog flush in ONE batch', async () => {
  // They are the same kind of row; sending them separately would double the
  // requests for no benefit.
  const server = await startFakeServer({ validTokens: ['valid'] });
  const syslogRow = { ...TRAP_ROW, transport: 'syslog', eventType: 'link.down', summary: 'Interface Gi0/1 changed state to down' };
  const runtime = createAgentRuntime({
    config: {
      serverUrl: server.url, heartbeatMs: 10000, backoff: { baseMs: 30, maxMs: 120, factor: 2 },
      reportIntervalMs: 0, probeIntervalMs: 0, syslogEnabled: true, syslogFlushIntervalMs: 0,
    },
    token: 'valid', agentId: 1, logger: silentLogger, hsflowdManager: noopHsflowd,
    syslogReceiver: {
      start: async () => ({ udp: true, tcp: true, port: 1514 }),
      drain: () => [syslogRow],
      stats: () => ({ port: 1514, buffered: 0, received: 1, dropped: 0, unparsed: 0, overflowed: 0, senders: 1, lastAt: null }),
      stop: () => {},
    },
    trapReceiver: stubTraps([TRAP_ROW]),
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config loaded');

    assert.equal(await runtime.flushDeviceEventsNow(), 2);
    assert.equal(server.receivedDeviceEvents.length, 1, 'one request, not two');
    const kinds = server.receivedDeviceEvents[0].events.map((e) => e.transport).sort();
    assert.deepEqual(kinds, ['syslog', 'trap']);
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('one receiver throwing costs its own rows, not the other\'s', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const runtime = createAgentRuntime({
    config: {
      serverUrl: server.url, heartbeatMs: 10000, backoff: { baseMs: 30, maxMs: 120, factor: 2 },
      reportIntervalMs: 0, probeIntervalMs: 0, syslogEnabled: true, syslogFlushIntervalMs: 0,
    },
    token: 'valid', agentId: 1, logger: silentLogger, hsflowdManager: noopHsflowd,
    syslogReceiver: {
      start: async () => ({ udp: true, tcp: true, port: 1514 }),
      drain: () => { throw new Error('syslog buffer corrupt'); },
      stats: () => ({ port: 1514 }),
      stop: () => {},
    },
    trapReceiver: stubTraps([TRAP_ROW]),
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config loaded');
    assert.equal(await runtime.flushDeviceEventsNow(), 1, 'the trap still went');
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('the diagnose snapshot carries the trap counters', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const runtime = createAgentRuntime({
    config: {
      serverUrl: server.url, heartbeatMs: 10000, backoff: { baseMs: 30, maxMs: 120, factor: 2 },
      reportIntervalMs: 0, probeIntervalMs: 0, syslogEnabled: false,
    },
    token: 'valid', agentId: 1, logger: silentLogger, hsflowdManager: noopHsflowd,
    trapReceiver: stubTraps([]),
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'traps'), 4000, 'trap receiver never bound');

    const reply = server.waitForWsMessage((m) => m.type === 'command-result' && m.id === 't1');
    server.sendCommandToAll({ name: 'diagnose', id: 't1' });
    const msg = await withTimeout(reply, 4000, 'no diagnose reply');

    assert.equal(msg.diagnostic.traps.port, 1162);
    assert.equal(msg.diagnostic.traps.refused, 2, 'so "a switch nobody added is shouting" is visible');
    assert.deepEqual(msg.diagnostic.traps.bound, { udp: true, port: 1162 });
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('with traps disabled nothing binds and the snapshot says so', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const runtime = createAgentRuntime({
    config: {
      serverUrl: server.url, heartbeatMs: 10000, backoff: { baseMs: 30, maxMs: 120, factor: 2 },
      reportIntervalMs: 0, probeIntervalMs: 0, syslogEnabled: false, trapsEnabled: false,
    },
    token: 'valid', agentId: 1, logger: silentLogger, hsflowdManager: noopHsflowd,
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config loaded');

    const reply = server.waitForWsMessage((m) => m.type === 'command-result' && m.id === 't2');
    server.sendCommandToAll({ name: 'diagnose', id: 't2' });
    assert.equal((await withTimeout(reply, 4000, 'no reply')).diagnostic.traps, null);
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('an integer varbind delivered as bytes is read in full, not only its first six bytes', () => {
  // Seven bytes, value 70000. Reading only the first six (the old code) gave
  // 0x000000000111 = 273 — the same 256x-low bug the SNMP reader had on a real
  // seven-byte Counter64.
  const seven = Buffer.from([0, 0, 0, 0, 0x01, 0x11, 0x70]);
  const varbinds = linkDown().map((v) => (v.oid.startsWith('1.3.6.1.2.1.2.2.1.1.') ? { ...v, value: seven } : v));
  const r = translateTrap({ varbinds, sourceIp: '10.14.0.11', receivedAt: RECV });
  assert.match(r.summary, /ifIndex 70000/);
});
