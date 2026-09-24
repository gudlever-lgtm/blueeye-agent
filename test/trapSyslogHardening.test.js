'use strict';

// The trap and syslog receivers' sender checks:
//
//   * the trap decoder is our own (net-snmp does not export the `Message` the
//     old default decoder called, so every real trap was "undecodable"); the
//     fixtures are datagrams net-snmp's own encoder produced;
//   * a v1/v2c trap whose community differs from the one the agent polls that
//     device with is refused and counted as `badCommunity`;
//   * syslog has an optional sender allowlist (CIDRs and/or "only the switches
//     this agent polls"), fails closed on a bad entry, and counts `refused`.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('events');

const { decodeTrap } = require('../src/traps/decode');
const { createTrapReceiver } = require('../src/traps/receiver');
const { createSyslogReceiver, parseSenderAllowlist } = require('../src/syslog/receiver');
const { loadConfig } = require('../src/config');
const { startFakeServer } = require('../test-support/fakeServer');
const { createAgentRuntime } = require('../src/runtime');
const { silentLogger } = require('../src/logger');

// Captured from net-snmp 3.x `session.trap(TrapType.LinkDown, …)` sent to a
// local UDP socket, community "s3cret-ro".
const V2C_LINKDOWN = Buffer.from(
  '30818e02010104097333637265742d726fa77e020405cf49780201000201003070300d06082b060102010103004301073017060a2b06010603010104010006092b0601060301010503300f060a2b060102010202010101020101300f060a2b060102010202010701020101300f060a2b0601020102020108010201023013060a2b06010201020201020104054769302f31',
  'hex',
);
const V1_LINKDOWN = Buffer.from(
  '303a02010004097333637265742d726fa42a06052b0601040140040a0e000b020102020100430210923011300f060a2b060102010202010103020103',
  'hex',
);

// ----------------------------------------------------------------- decoder
test('decodeTrap reads a v2c trap: community, trap OID, varbinds', () => {
  const d = decodeTrap(V2C_LINKDOWN);
  assert.equal(d.version, '2c');
  assert.equal(d.community, 's3cret-ro');
  assert.deepEqual(d.varbinds.slice(1, 5).map((v) => [v.oid, v.value]), [
    ['1.3.6.1.6.3.1.1.4.1.0', '1.3.6.1.6.3.1.1.5.3'],
    ['1.3.6.1.2.1.2.2.1.1.1', 1],
    ['1.3.6.1.2.1.2.2.1.7.1', 1],
    ['1.3.6.1.2.1.2.2.1.8.1', 2],
  ]);
  assert.equal(d.varbinds[5].value.toString(), 'Gi0/1', 'OCTET STRING stays a Buffer, like net-snmp');
});

test('decodeTrap converts a v1 trap to the v2 varbind shape (RFC 3584)', () => {
  const d = decodeTrap(V1_LINKDOWN);
  assert.equal(d.version, '1');
  assert.equal(d.community, 's3cret-ro');
  const byOid = Object.fromEntries(d.varbinds.map((v) => [v.oid, v.value]));
  assert.equal(byOid['1.3.6.1.2.1.1.3.0'], 4242, 'time-stamp -> sysUpTime.0');
  assert.equal(byOid['1.3.6.1.6.3.1.1.4.1.0'], '1.3.6.1.6.3.1.1.5.3', 'generic 2 (linkDown) -> snmpTraps.3');
  assert.equal(byOid['1.3.6.1.2.1.2.2.1.1.3'], 3);
  assert.equal(byOid['1.3.6.1.6.3.1.1.4.3.0'], '1.3.6.1.4.1', 'enterprise kept');
});

test('decodeTrap: a v3 datagram is its own code, garbage and truncation are malformed', () => {
  // SEQUENCE { INTEGER 3, ... } — enough to be recognised as v3.
  const v3 = Buffer.from('300c020103300702010102020100', 'hex');
  assert.throws(() => decodeTrap(v3), (e) => e.code === 'TRAP_V3_UNSUPPORTED');
  assert.throws(() => decodeTrap(Buffer.from('hello world, not BER')), (e) => e.code === 'TRAP_MALFORMED');
  for (let cut = 1; cut < V2C_LINKDOWN.length; cut += 7) {
    assert.throws(() => decodeTrap(V2C_LINKDOWN.subarray(0, cut)), (e) => e.code === 'TRAP_MALFORMED');
  }
  // A get-request (0xa0) is not a trap.
  const get = Buffer.from(V2C_LINKDOWN);
  get[get.indexOf(0xa7)] = 0xa0;
  assert.throws(() => decodeTrap(get), /not a trap/);
});

// ------------------------------------------------------- receiver: community
function fakeSocket() {
  const sock = new EventEmitter();
  sock.bind = (port, addr, cb) => setImmediate(cb);
  sock.close = () => {};
  sock.deliver = (msg, address = '10.14.0.11') => sock.emit('message', msg, { address });
  return sock;
}

async function trapRx(opts = {}) {
  const socket = fakeSocket();
  const rx = createTrapReceiver({ createSocket: () => socket, isKnownSender: () => true, ...opts });
  await rx.start();
  return { rx, socket };
}

test('the DEFAULT decoder turns a real datagram into a link.down row (no net-snmp needed)', async () => {
  const { rx, socket } = await trapRx();
  socket.deliver(V2C_LINKDOWN);
  const events = rx.drain();
  assert.equal(rx.stats().undecodable, 0);
  assert.equal(events.length, 1);
  assert.equal(events[0].eventType, 'link.down');
  rx.stop();
});

test('with checkCommunity on, a trap whose community differs from the polled one is refused as badCommunity', async () => {
  const { rx, socket } = await trapRx({ checkCommunity: true, expectedCommunity: (ip) => (ip === '10.14.0.11' ? 'other-ro' : null) });
  socket.deliver(V2C_LINKDOWN, '10.14.0.11'); // wrong community
  socket.deliver(V1_LINKDOWN, '10.14.0.11'); // wrong community, v1 too
  socket.deliver(V2C_LINKDOWN, '10.14.0.12'); // community unknown -> address only
  assert.equal(rx.drain().length, 1);
  const s = rx.stats();
  assert.equal(s.badCommunity, 2);
  assert.equal(s.communityMismatch, 2);
  assert.equal(s.refused, 0, 'not the same counter as an unknown address');
  assert.equal(s.checkCommunity, true);
  rx.stop();
});

test('the matching community is accepted; with the check off (the default) a mismatch is kept and counted', async () => {
  const ok = await trapRx({ expectedCommunity: () => 's3cret-ro' });
  ok.socket.deliver(V2C_LINKDOWN);
  assert.equal(ok.rx.drain().length, 1);
  ok.rx.stop();

  // A trap community that differs from the read community is a normal setup:
  // dropping it by default would lose that switch's traps without a trace.
  const off = await trapRx({ expectedCommunity: () => 'other-ro' });
  off.socket.deliver(V2C_LINKDOWN);
  assert.equal(off.rx.drain().length, 1);
  assert.equal(off.rx.stats().badCommunity, 0);
  assert.equal(off.rx.stats().communityMismatch, 1, 'visible in the stats even when accepted');
  off.rx.stop();
});

test('a v3 trap is counted as v3, not as undecodable garbage', async () => {
  const { rx, socket } = await trapRx();
  socket.deliver(Buffer.from('300c020103300702010102020100', 'hex'));
  assert.equal(rx.stats().v3, 1);
  assert.equal(rx.stats().undecodable, 0);
  rx.stop();
});

// ------------------------------------------------------ syslog allowlist
const LINE = '<186>Sep 20 09:41:09 sw-core-1 %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down';

test('parseSenderAllowlist: CIDRs and bare addresses, v4 and v6, string or array', () => {
  const a = parseSenderAllowlist('10.20.0.0/16, 192.0.2.7 2001:db8::/32');
  assert.equal(a.configured, true);
  assert.deepEqual(a.invalid, []);
  assert.equal(a.match('10.20.3.4'), true);
  assert.equal(a.match('10.21.0.1'), false);
  assert.equal(a.match('192.0.2.7'), true);
  assert.equal(a.match('192.0.2.8'), false);
  assert.equal(a.match('2001:db8::5'), true);
  assert.equal(a.match('::ffff:10.20.0.1'), true, 'IPv4-mapped is unwrapped');
  assert.equal(a.match('unknown'), false);
  assert.equal(parseSenderAllowlist(['10.0.0.0/8']).match('10.1.1.1'), true);
  assert.equal(parseSenderAllowlist([]).configured, false);
  assert.equal(parseSenderAllowlist(undefined).configured, false);
});

test('parseSenderAllowlist fails CLOSED: a typo in the only entry refuses everything', () => {
  const a = parseSenderAllowlist(['10.0.0.0/33', 'switch-1', '10.0.0.0/x']);
  assert.deepEqual(a.invalid, ['10.0.0.0/33', 'switch-1', '10.0.0.0/x']);
  assert.equal(a.configured, true);
  assert.equal(a.match('10.0.0.1'), false);
});

function syslogRx(isAllowedSender) {
  const socket = fakeSocket();
  const srv = new EventEmitter();
  let onConn = null;
  srv.listen = (p, a, cb) => setImmediate(cb);
  srv.close = () => {};
  srv.connect = (remoteAddress) => {
    const sock = new EventEmitter();
    sock.remoteAddress = remoteAddress;
    sock.setEncoding = () => {};
    sock.destroyed = false;
    sock.destroy = () => { sock.destroyed = true; };
    onConn(sock);
    return sock;
  };
  const rx = createSyslogReceiver({
    createSocket: () => socket,
    createServer: (h) => { onConn = h; return srv; },
    isAllowedSender,
  });
  return { rx, socket, srv };
}

test('syslog: a sender off the allowlist is refused and counted, UDP and TCP alike', async () => {
  const allow = parseSenderAllowlist(['10.14.0.0/24']);
  const { rx, socket, srv } = syslogRx((ip) => allow.match(ip));
  await rx.start();
  socket.deliver(Buffer.from(LINE), '10.14.0.11');
  socket.deliver(Buffer.from(`${LINE}\n${LINE}`), '198.51.100.9');
  const tcpBad = srv.connect('::ffff:198.51.100.9');
  assert.equal(tcpBad.destroyed, true, 'a refused TCP sender is cut off at connect');
  const tcpOk = srv.connect('::ffff:10.14.0.12');
  tcpOk.emit('data', `${LINE}\n`);
  const events = rx.drain();
  assert.deepEqual(events.map((e) => e.sourceIp).sort(), ['10.14.0.11', '10.14.0.12']);
  const s = rx.stats();
  assert.equal(s.refused, 3, 'two UDP lines + one TCP connection');
  assert.equal(s.dropped, 0, 'refused is not rate-limited');
  assert.equal(s.senders, 2, 'a refused sender never claims a rate-limit bucket');
  rx.stop();
});

test('syslog: no allowlist accepts every sender, as before', async () => {
  const { rx, socket } = syslogRx(undefined);
  await rx.start();
  socket.deliver(Buffer.from(LINE), '198.51.100.9');
  assert.equal(rx.drain().length, 1);
  assert.equal(rx.stats().refused, 0);
  rx.stop();
});

// ------------------------------------------------------------------ config
test('config: syslogAllowedSenders / syslogOnlyPolled / trapsCheckCommunity', () => {
  const env = { BLUEEYE_AGENT_CONFIG: '/nonexistent/blueeye-agent.config.json' };
  const d = loadConfig({ env });
  assert.deepEqual(d.syslogAllowedSenders, []);
  assert.equal(d.syslogOnlyPolled, false);
  assert.equal(d.trapsCheckCommunity, false, 'off by default — a differing trap community must not drop traps');
  const c = loadConfig({
    env: {
      ...env,
      BLUEEYE_SYSLOG_ALLOWED_SENDERS: '10.0.0.0/8, 192.0.2.7',
      BLUEEYE_SYSLOG_ONLY_POLLED: '1',
      BLUEEYE_TRAPS_CHECK_COMMUNITY: 'true',
    },
  });
  assert.deepEqual(c.syslogAllowedSenders, ['10.0.0.0/8', '192.0.2.7']);
  assert.equal(c.syslogOnlyPolled, true);
  assert.equal(c.trapsCheckCommunity, true);
});

// ----------------------------------------------------------------- runtime
const makeConfig = (server, extra = {}) => ({
  serverUrl: server.url,
  heartbeatMs: 10000,
  backoff: { baseMs: 30, maxMs: 120, factor: 2 },
  reportIntervalMs: 0,
  probeIntervalMs: 0,
  syslogEnabled: false,
  ...extra,
});
const noopHsflowd = {
  enable: async () => ({ state: 'active', detail: null }),
  disable: async () => ({ state: 'inactive', detail: null }),
  status: async () => ({ state: 'unknown', detail: null }),
};
const stub = () => ({ start: async () => ({ udp: true }), drain: () => [], stats: () => ({}), stop: () => {} });
const idleSnmp = {
  setTargets: (l) => (Array.isArray(l) ? l.length : 0),
  runCycle: async () => ({ polled: 0, failed: 0 }),
  runCounterCycle: async () => ({ polled: 0, failed: 0 }),
  start: () => {}, startCounters: () => {}, stop: () => {}, stopCounters: () => {}, stats: () => ({}),
};
async function waitFor(pred, ms) {
  const until = Date.now() + ms;
  while (!pred()) {
    if (Date.now() > until) throw new Error('timeout');
    // eslint-disable-next-line no-await-in-loop
    await new Promise((r) => setTimeout(r, 10));
  }
}

test('runtime: the trap receiver gets the polled community per address (none for v3)', async () => {
  const server = await startFakeServer({
    validTokens: ['valid'],
    snmpTargets: [
      { deviceId: 7, host: '10.14.0.11', community: 'plant-ro', version: '2c', collect: ['if'] },
      { deviceId: 8, host: '10.14.0.12', version: '3', v3: { user: 'mon' }, collect: ['if'] },
    ],
  });
  const seen = {};
  const runtime = createAgentRuntime({
    config: makeConfig(server, { trapsEnabled: true }),
    token: 'valid', agentId: 1, logger: silentLogger, hsflowdManager: noopHsflowd,
    collectLldp: async () => ({ unavailable: 'test' }), snmpPoller: idleSnmp,
    trapReceiverFactory: (opts) => { Object.assign(seen, opts); return stub(); },
  });
  try {
    runtime.start();
    await waitFor(() => seen.isKnownSender && seen.isKnownSender('10.14.0.11'), 4000);
    assert.equal(seen.checkCommunity, false, 'off by default');
    assert.equal(seen.expectedCommunity('10.14.0.11'), 'plant-ro');
    assert.equal(seen.expectedCommunity('10.14.0.12'), null, 'a v3 target has no community to compare');
    assert.equal(seen.expectedCommunity('192.0.2.66'), null);
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('runtime: trapsCheckCommunity:false reaches the receiver', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const seen = {};
  const runtime = createAgentRuntime({
    config: makeConfig(server, { trapsEnabled: true, trapsCheckCommunity: false }),
    token: 'valid', agentId: 1, logger: silentLogger, hsflowdManager: noopHsflowd,
    collectLldp: async () => ({ unavailable: 'test' }), snmpPoller: idleSnmp,
    trapReceiverFactory: (opts) => { Object.assign(seen, opts); return stub(); },
  });
  try {
    assert.equal(seen.checkCommunity, false);
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('runtime: syslogAllowedSenders UNION syslogOnlyPolled decides the syslog sender filter', async () => {
  const server = await startFakeServer({
    validTokens: ['valid'],
    snmpTargets: [{ deviceId: 7, host: '10.14.0.11', community: 'plant-ro', collect: ['if'] }],
  });
  const seen = {};
  const runtime = createAgentRuntime({
    config: makeConfig(server, { syslogEnabled: true, syslogAllowedSenders: ['192.0.2.0/24'], syslogOnlyPolled: true }),
    token: 'valid', agentId: 1, logger: silentLogger, hsflowdManager: noopHsflowd,
    collectLldp: async () => ({ unavailable: 'test' }), snmpPoller: idleSnmp,
    syslogReceiverFactory: (opts) => { Object.assign(seen, opts); return stub(); },
  });
  try {
    runtime.start();
    await waitFor(() => seen.isAllowedSender('10.14.0.11'), 4000);
    assert.equal(seen.isAllowedSender('192.0.2.200'), true, 'in the CIDR list');
    assert.equal(seen.isAllowedSender('10.14.0.11'), true, 'a polled switch');
    assert.equal(seen.isAllowedSender('198.51.100.1'), false, 'neither');
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('runtime: with neither syslog setting, every sender is accepted', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const seen = {};
  const runtime = createAgentRuntime({
    config: makeConfig(server, { syslogEnabled: true }),
    token: 'valid', agentId: 1, logger: silentLogger, hsflowdManager: noopHsflowd,
    collectLldp: async () => ({ unavailable: 'test' }), snmpPoller: idleSnmp,
    syslogReceiverFactory: (opts) => { Object.assign(seen, opts); return stub(); },
  });
  try {
    assert.equal(seen.isAllowedSender('198.51.100.1'), true);
  } finally {
    runtime.stop();
    await server.close();
  }
});
