'use strict';

// The runtime's background loops — the work nobody triggers and nobody watches,
// which is exactly where a gap stays invisible:
//
//   * the device-event flush runs when EITHER syslog or traps bound (a
//     trap-only agent used to buffer traps that were never sent), and there is
//     only ever one flush timer;
//   * a SCHEDULED SNMP cycle feeds the same hook a forced poll-snmp does (the
//     interface names the trap resolver shows) and a 401 on its submit is
//     fatal instead of swallowed on every tick;
//   * the trap sender allowlist matches a switch configured by HOSTNAME;
//   * capabilities (ARP, connection table, NIC, LLDP) are re-reported on a
//     cadence, not only at start and on reconnect;
//   * the local LLDP neighbours ride on that report, or the reason they can't.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('events');

const { startFakeServer } = require('../test-support/fakeServer');
const { createAgentRuntime } = require('../src/runtime');
const { createSnmpPoller } = require('../src/snmpPoller');
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
const delay = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(pred, ms, message) {
  const until = Date.now() + ms;
  while (!pred()) {
    if (Date.now() > until) throw new Error(message);
    // eslint-disable-next-line no-await-in-loop
    await delay(10);
  }
}

const noopHsflowd = {
  enable: async () => ({ state: 'active', detail: null }),
  disable: async () => ({ state: 'inactive', detail: null }),
  status: async () => ({ state: 'unknown', detail: null }),
};
const makeConfig = (server, extra = {}) => ({
  serverUrl: server.url,
  heartbeatMs: 10000,
  backoff: { baseMs: 30, maxMs: 120, factor: 2 },
  reportIntervalMs: 0,
  probeIntervalMs: 0,
  syslogEnabled: false,
  ...extra,
});
// Every test that is not about LLDP gets a quiet, deterministic reader.
const noLldp = async () => ({ unavailable: 'test' });

const TRAP_ROW = {
  sourceIp: '10.14.0.11', receivedAt: '2026-09-20T09:41:11.000Z', deviceTime: null, clockSkewMs: null,
  transport: 'trap', facility: null, severity: 2, eventType: 'link.down', host: null, tag: '1.3.6.1.6.3.1.1.5.3',
  ifname: 'ifIndex 1', summary: 'Link down on ifIndex 1', raw: null, occurrences: 1, detail: {},
};

function stubReceiver(events = [], port = 1162) {
  let queued = [...events];
  return {
    start: async () => ({ udp: true, port }),
    drain: () => { const out = queued; queued = []; return out; },
    stats: () => ({ port, buffered: queued.length }),
    stop: () => {},
    push: (e) => queued.push(e),
  };
}

// ------------------------------------------------------ device-event flush
test('traps on, syslog off: buffered traps are flushed on the timer', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const runtime = createAgentRuntime({
    config: makeConfig(server, { syslogEnabled: false, trapsEnabled: true, syslogFlushIntervalMs: 30 }),
    token: 'valid', agentId: 1, logger: silentLogger, hsflowdManager: noopHsflowd, collectLldp: noLldp,
    trapReceiver: stubReceiver([TRAP_ROW]),
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'device-events'), 4000, 'traps were never flushed');
    assert.equal(server.receivedDeviceEvents.length, 1);
    assert.equal(server.receivedDeviceEvents[0].events[0].transport, 'trap');
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('syslog AND traps bound: one flush timer, not two', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  // A flush interval no other timer in the runtime uses, so its setInterval
  // calls can be counted exactly.
  const FLUSH_MS = 43210;
  const realSetInterval = global.setInterval;
  let flushTimers = 0;
  global.setInterval = (fn, ms, ...rest) => {
    if (ms === FLUSH_MS) flushTimers += 1;
    return realSetInterval(fn, ms, ...rest);
  };
  const runtime = createAgentRuntime({
    config: makeConfig(server, { syslogEnabled: true, trapsEnabled: true, syslogFlushIntervalMs: FLUSH_MS }),
    token: 'valid', agentId: 1, logger: silentLogger, hsflowdManager: noopHsflowd, collectLldp: noLldp,
    syslogReceiver: stubReceiver([], 1514),
    trapReceiver: stubReceiver([]),
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'traps'), 4000, 'trap receiver never bound');
    assert.equal(flushTimers, 1);
  } finally {
    global.setInterval = realSetInterval;
    runtime.stop();
    await server.close();
  }
});

// ------------------------------------------------- scheduled SNMP topology
const TARGET = (over = {}) => ({ deviceId: 7, host: '10.14.0.11', community: 'public', collect: ['if'], intervalSec: 300, ...over });
const RESULT = (deviceId) => ({ deviceId, interfaces: [{ ifIndex: 1, ifName: 'GigabitEthernet0/1' }], fdb: [], neighbours: [], vlans: [], supported: ['if'] });

// A real poller whose start()/startCounters() only record what the runtime
// asked for, so a test can run "the next tick" deterministically.
function capturingPoller(opts) {
  const real = createSnmpPoller(opts);
  const captured = {};
  return {
    captured,
    poller: {
      ...real,
      start: (o) => { captured.topology = o; },
      startCounters: (o) => { captured.counters = o; },
    },
  };
}

// A trap receiver factory that hands the runtime's allowlist + resolver back to the test.
function capturingTrapFactory() {
  const seen = {};
  const factory = (opts) => { Object.assign(seen, opts); return stubReceiver([]); };
  return { seen, factory };
}

test('a scheduled topology cycle feeds the interface-name hook and the diagnose timestamp', async () => {
  const server = await startFakeServer({ validTokens: ['valid'], snmpTargets: [TARGET()] });
  const { captured, poller } = capturingPoller({
    submit: (p) => server.postSnmpTopology(p),
    poll: async ({ device }) => RESULT(device.deviceId),
  });
  const traps = capturingTrapFactory();
  const runtime = createAgentRuntime({
    config: makeConfig(server, { trapsEnabled: true }),
    token: 'valid', agentId: 1, logger: silentLogger, hsflowdManager: noopHsflowd, collectLldp: noLldp,
    snmpPoller: poller, trapReceiverFactory: traps.factory,
  });
  try {
    runtime.start();
    await waitFor(() => captured.topology, 4000, 'the poller was never started');
    assert.equal(typeof captured.topology.cycle, 'function', 'the tick runs the runtime\'s cycle');
    assert.equal(traps.seen.resolveIfName('10.14.0.11', 1), null, 'nothing learned yet');

    const done = onceEvent(runtime, 'snmp-topology');
    await captured.topology.cycle(); // one scheduled tick
    await withTimeout(done, 2000, 'scheduled cycle did not report');

    assert.equal(server.receivedSnmpTopology.length, 1);
    assert.equal(traps.seen.resolveIfName('10.14.0.11', 1), 'GigabitEthernet0/1', 'the trap resolver learned from a SCHEDULED poll');
    assert.ok(runtime.getDiagnostic().snmp.lastSubmitAt, 'the diagnose snapshot records the scheduled submit');
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('a 401 on a SCHEDULED topology or counter submit is fatal, not swallowed', async () => {
  for (const which of ['topology', 'counters']) {
    // eslint-disable-next-line no-await-in-loop
    const server = await startFakeServer({ validTokens: ['valid'], snmpTargets: [TARGET({ collect: ['if', 'ifcounters'] })] });
    const rejected = async () => { throw Object.assign(new Error('401'), { code: 'TOKEN_REJECTED' }); };
    const { captured, poller } = capturingPoller({
      submit: which === 'topology' ? rejected : async () => {},
      submitCounters: which === 'counters' ? rejected : async () => {},
      poll: async ({ device }) => RESULT(device.deviceId),
      pollCounters: async ({ device }) => ({ deviceId: device.deviceId, interfaces: [] }),
    });
    const runtime = createAgentRuntime({
      config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger,
      hsflowdManager: noopHsflowd, collectLldp: noLldp, snmpPoller: poller,
    });
    try {
      runtime.start();
      // eslint-disable-next-line no-await-in-loop
      await waitFor(() => captured[which], 4000, `${which} poller never started`);
      const fatal = onceEvent(runtime, 'fatal');
      // eslint-disable-next-line no-await-in-loop
      await captured[which].cycle();
      // eslint-disable-next-line no-await-in-loop
      assert.equal(await withTimeout(fatal, 2000, `${which}: no fatal`), 'rest-token-rejected');
    } finally {
      runtime.stop();
      // eslint-disable-next-line no-await-in-loop
      await server.close();
    }
  }
});

test('the scheduled tick of a bare poller still runs a plain cycle', async () => {
  let cycles = 0;
  const p = createSnmpPoller({ submit: async () => {}, poll: async ({ device }) => { cycles += 1; return RESULT(device.deviceId); } });
  p.setTargets([TARGET()]);
  p.start({ tickMs: 5 });
  try {
    await waitFor(() => cycles >= 1, 2000, 'no tick ran');
  } finally { p.stop(); }
  let hooked = 0;
  const q = createSnmpPoller({ submit: async () => {}, poll: async () => RESULT(7) });
  q.start({ tickMs: 5, cycle: async () => { hooked += 1; throw new Error('a failing cycle is never unhandled'); } });
  try {
    await waitFor(() => hooked >= 2, 2000, 'the injected cycle never ran');
  } finally { q.stop(); }
});

// ------------------------------------------- trap allowlist by hostname
test('a switch configured by hostname is matched on its resolved address', async () => {
  const server = await startFakeServer({
    validTokens: ['valid'],
    snmpTargets: [TARGET({ deviceId: 7, host: 'sw-core-1.plant.lan' }), TARGET({ deviceId: 8, host: '10.0.0.8' })],
  });
  const lookups = [];
  const lookupHost = async (host) => {
    lookups.push(host);
    if (host === 'sw-core-1.plant.lan') return [{ address: '10.14.0.11', family: 4 }, { address: '::ffff:10.14.0.12', family: 6 }];
    throw Object.assign(new Error('nx'), { code: 'ENOTFOUND' });
  };
  const traps = capturingTrapFactory();
  const { captured, poller } = capturingPoller({ submit: async () => {}, poll: async ({ device }) => RESULT(device.deviceId) });
  const runtime = createAgentRuntime({
    config: makeConfig(server, { trapsEnabled: true }),
    token: 'valid', agentId: 1, logger: silentLogger, hsflowdManager: noopHsflowd, collectLldp: noLldp,
    trapReceiverFactory: traps.factory, lookupHost, snmpPoller: poller,
  });
  try {
    const resolved = onceEvent(runtime, 'snmp-targets-resolved');
    runtime.start();
    await withTimeout(resolved, 4000, 'targets never resolved');

    assert.deepEqual(lookups, ['sw-core-1.plant.lan'], 'a literal IP is not looked up');
    assert.equal(traps.seen.isKnownSender('10.14.0.11'), true, 'hostname target, resolved');
    assert.equal(traps.seen.isKnownSender('10.14.0.12'), true, 'every address it resolves to, IPv4-mapped unwrapped');
    assert.equal(traps.seen.isKnownSender('10.0.0.8'), true, 'literal target');
    assert.equal(traps.seen.isKnownSender('sw-core-1.plant.lan'), false, 'the name itself is not an address');
    assert.equal(traps.seen.isKnownSender('192.0.2.66'), false, 'a stranger is still refused');

    // The interface names learned from polling the HOSTNAME target resolve
    // for a trap from its ADDRESS.
    await waitFor(() => captured.topology, 4000, 'poller never started');
    await captured.topology.cycle();
    assert.equal(traps.seen.resolveIfName('10.14.0.11', 1), 'GigabitEthernet0/1');
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('a re-applied config refreshes the resolution, and a failed lookup keeps the last address', async () => {
  const targets = [TARGET({ deviceId: 7, host: 'sw-core-1.plant.lan' })];
  const server = await startFakeServer({ validTokens: ['valid'], snmpTargets: targets });
  let answer = [{ address: '10.14.0.11', family: 4 }];
  const lookupHost = async () => {
    if (answer instanceof Error) throw answer;
    return answer;
  };
  const traps = capturingTrapFactory();
  const runtime = createAgentRuntime({
    config: makeConfig(server, { trapsEnabled: true }),
    token: 'valid', agentId: 1, logger: silentLogger, hsflowdManager: noopHsflowd, collectLldp: noLldp,
    trapReceiverFactory: traps.factory, lookupHost,
  });
  try {
    let resolved = onceEvent(runtime, 'snmp-targets-resolved');
    runtime.start();
    await withTimeout(resolved, 4000, 'first resolution');
    assert.equal(traps.seen.isKnownSender('10.14.0.11'), true);

    // The switch moved. A reconnect re-fetches the config, which re-resolves.
    answer = [{ address: '10.14.0.99', family: 4 }];
    resolved = onceEvent(runtime, 'snmp-targets-resolved');
    server.dropAllSockets();
    await withTimeout(resolved, 4000, 'no re-resolution after reconnect');
    assert.equal(traps.seen.isKnownSender('10.14.0.99'), true);
    assert.equal(traps.seen.isKnownSender('10.14.0.11'), false, 'the old address is no longer trusted');

    // DNS goes away: the last known address stays in force.
    answer = Object.assign(new Error('timeout'), { code: 'ETIMEOUT' });
    resolved = onceEvent(runtime, 'snmp-targets-resolved');
    server.dropAllSockets();
    await withTimeout(resolved, 4000, 'no re-resolution after second reconnect');
    assert.equal(traps.seen.isKnownSender('10.14.0.99'), true);
  } finally {
    runtime.stop();
    await server.close();
  }
});

// ------------------------------------------------ periodic capabilities
test('capabilities are re-reported on the configured cadence', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  let arpReads = 0;
  const runtime = createAgentRuntime({
    config: makeConfig(server, { capabilitiesIntervalMs: 40 }),
    token: 'valid', agentId: 1, logger: silentLogger, hsflowdManager: noopHsflowd, collectLldp: noLldp,
    collectArp: async () => { arpReads += 1; return [{ ip: '10.0.0.1', mac: '00:11:22:33:44:55', iface: 'eth0' }]; },
  });
  try {
    runtime.start();
    await waitFor(() => server.receivedCapabilities.length >= 5, 4000, 'capabilities were not re-reported');
    assert.ok(arpReads >= 5, 'the ARP table is re-read each time, not cached from the first report');
    assert.equal(server.receivedCapabilities.at(-1).arp[0].mac, '00:11:22:33:44:55');
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('0 disables the cadence: only the bootstrap and connect reports', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const runtime = createAgentRuntime({
    config: makeConfig(server, { capabilitiesIntervalMs: 0 }),
    token: 'valid', agentId: 1, logger: silentLogger, hsflowdManager: noopHsflowd, collectLldp: noLldp,
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config');
    await delay(250);
    assert.ok(server.receivedCapabilities.length <= 2, `got ${server.receivedCapabilities.length}`);
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('no periodic report while the WebSocket is down', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  // A socket that never opens: REST still works, the live channel does not.
  class NeverOpens extends EventEmitter {
    constructor() { super(); this.readyState = 0; this.OPEN = 1; }
    send() {}
    close() {}
    terminate() {}
  }
  const runtime = createAgentRuntime({
    config: makeConfig(server, { capabilitiesIntervalMs: 20 }),
    token: 'valid', agentId: 1, logger: silentLogger, hsflowdManager: noopHsflowd, collectLldp: noLldp,
    WebSocketImpl: NeverOpens,
  });
  try {
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config');
    await delay(200);
    assert.equal(server.receivedCapabilities.length, 1, 'only the bootstrap report');
  } finally {
    runtime.stop();
    await server.close();
  }
});

// ------------------------------------------------------------ local LLDP
test('LLDP neighbours + the local chassis id ride on the capabilities report', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const neighbours = [{ localPort: 'eth0', remoteChassisId: '00:1b:44:11:3a:b7', remotePort: 'Gi1/0/24', linkState: 'up' }];
  const runtime = createAgentRuntime({
    config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger, hsflowdManager: noopHsflowd,
    collectLldp: async () => ({ neighbours, chassisId: '52:54:00:ab:cd:ef' }),
  });
  try {
    runtime.start();
    await waitFor(() => server.receivedCapabilities.length >= 1, 4000, 'no capabilities');
    const caps = server.receivedCapabilities[0];
    assert.deepEqual(caps.lldp, neighbours);
    assert.equal(caps.lldpChassisId, '52:54:00:ab:cd:ef');
    assert.equal(caps.unavailable && caps.unavailable.lldp, undefined);
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('no lldpd: the field is OMITTED and unavailable.lldp says why, beside the other reasons', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const runtime = createAgentRuntime({
    config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger, hsflowdManager: noopHsflowd,
    capabilities: { sources: ['proc'], unavailable: { snmp: 'net-snmp is missing' }, agentVersion: '1.0.0', managed: 'systemd' },
    collectLldp: async () => ({ unavailable: 'lldpd is not installed (lldpctl not found)' }),
  });
  try {
    runtime.start();
    await waitFor(() => server.receivedCapabilities.length >= 1, 4000, 'no capabilities');
    const caps = server.receivedCapabilities[0];
    assert.equal('lldp' in caps, false, 'never [] — that would read as "every neighbour removed"');
    assert.equal('lldpChassisId' in caps, false);
    assert.match(caps.unavailable.lldp, /not installed/);
    assert.equal(caps.unavailable.snmp, 'net-snmp is missing', 'existing reasons are kept');
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('lldpd running with no neighbours sends [] — a real snapshot', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const runtime = createAgentRuntime({
    config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger, hsflowdManager: noopHsflowd,
    collectLldp: async () => ({ neighbours: [], chassisId: null }),
  });
  try {
    runtime.start();
    await waitFor(() => server.receivedCapabilities.length >= 1, 4000, 'no capabilities');
    assert.deepEqual(server.receivedCapabilities[0].lldp, []);
    assert.equal('lldpChassisId' in server.receivedCapabilities[0], false);
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('an LLDP reader that throws costs the field, never the report', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const runtime = createAgentRuntime({
    config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger, hsflowdManager: noopHsflowd,
    collectLldp: async () => { throw new Error('boom'); },
  });
  try {
    runtime.start();
    await waitFor(() => server.receivedCapabilities.length >= 1, 4000, 'no capabilities');
    assert.equal('lldp' in server.receivedCapabilities[0], false);
  } finally {
    runtime.stop();
    await server.close();
  }
});

// -------------------------------------------- probe batch refused by the server
// An older server answers 400 to a batch that holds one result type it does not
// know. The rest of the cycle must still land — one refused result is not a
// reason to lose every probe of the minute.
test('a 400 on the scheduled probe batch resubmits one by one and drops only the refused result', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const posted = [];
  const fetchImpl = async (url, init) => {
    if (String(url).endsWith('/agents/probe-results')) {
      const body = JSON.parse(init.body);
      posted.push(body.results.map((r) => r.type));
      if (body.results.some((r) => r.type === 'newtype')) {
        return new Response(JSON.stringify({ error: 'Validation failed' }), { status: 400, headers: { 'content-type': 'application/json' } });
      }
    }
    return fetch(url, init);
  };
  const probeRunner = async (spec) => ({ type: spec.type, target: spec.host || spec.target || 'x', ok: true, rttMs: 1 });
  const runtime = createAgentRuntime({
    config: makeConfig(server, {
      probeIntervalMs: 40, probeCount: 1, probeAutoGateway: false, probeAutoDns: false,
      probeTargets: [{ type: 'ping', host: '192.0.2.1' }, { type: 'newtype', host: '192.0.2.2' }, { type: 'tcp', host: '192.0.2.3', port: 443 }],
    }),
    token: 'valid', agentId: 1, logger: silentLogger, hsflowdManager: noopHsflowd, collectLldp: noLldp,
    fetchImpl, probeRunner,
  });
  try {
    runtime.start();
    const done = await withTimeout(onceEvent(runtime, 'scheduled-probes-submitted'), 4000, 'no probe submission');
    assert.deepEqual(done.results.map((r) => r.type).sort(), ['ping', 'tcp']);
    assert.deepEqual(done.refused.map((r) => r.type), ['newtype']);
    assert.equal(posted[0].length, 3, 'the whole batch was tried first');
    const landed = server.receivedProbeResults.flatMap((p) => p.body.results.map((r) => r.type)).sort();
    assert.deepEqual(landed, ['ping', 'tcp']);
  } finally {
    runtime.stop();
    await server.close();
  }
});
