'use strict';

// A failed probe says WHICH failure it was.
//
// Loss alone cannot tell a closed port from a dead host, or a name that does
// not exist from a resolver that did not answer — and those have different
// owners. The dns probe reports the resolver's `errorCode`; the tcp probe
// reports `failure` (refused / timeout / unreachable / error) and `errorCode`.
// Both must survive stats.summarize() and reach POST /agents/probe-results.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('events');

const { tcpProbe, classifyConnectError } = require('../src/probes/tcp');
const { dnsProbe, firstServer } = require('../src/probes/dns');
const { runProbe } = require('../src/probes');
const { startFakeServer } = require('../test-support/fakeServer');
const { createAgentRuntime } = require('../src/runtime');
const { silentLogger } = require('../src/logger');

const coded = (code, message = code) => Object.assign(new Error(message), { code });
const clock = () => { let t = 1000; return () => { const v = t; t += 5; return v; }; };

// A fake net.connect whose Nth socket emits the Nth scripted outcome:
// 'connect', 'timeout', or an Error for 'error'.
function scriptedConnect(outcomes) {
  let i = 0;
  return () => {
    const outcome = outcomes[Math.min(i, outcomes.length - 1)];
    i += 1;
    const sock = new EventEmitter();
    sock.setTimeout = () => {};
    sock.destroy = () => {};
    setImmediate(() => {
      if (outcome instanceof Error) sock.emit('error', outcome);
      else sock.emit(outcome);
    });
    return sock;
  };
}

// ---------------------------------------------------------------- tcp
test('tcp: a refused connect is "refused", not a timeout', async () => {
  const r = await tcpProbe({ host: '10.0.0.5', port: 502, count: 2 }, { connect: scriptedConnect([coded('ECONNREFUSED')]), now: clock() });
  assert.equal(r.ok, false);
  assert.equal(r.lossPct, 100);
  assert.equal(r.failure, 'refused');
  assert.equal(r.errorCode, 'ECONNREFUSED');
});

test('tcp: our own deadline is "timeout"', async () => {
  const r = await tcpProbe({ host: '10.0.0.5', port: 502, count: 1 }, { connect: scriptedConnect(['timeout']), now: clock() });
  assert.equal(r.failure, 'timeout');
  assert.equal(r.errorCode, 'ETIMEDOUT');
});

test('tcp: no route is "unreachable"', async () => {
  for (const code of ['EHOSTUNREACH', 'ENETUNREACH']) {
    // eslint-disable-next-line no-await-in-loop
    const r = await tcpProbe({ host: '10.0.0.5', port: 22, count: 1 }, { connect: scriptedConnect([coded(code)]), now: clock() });
    assert.equal(r.failure, 'unreachable', code);
    assert.equal(r.errorCode, code);
  }
});

test('tcp: anything else is "error", and a code-less error still says so', async () => {
  const r = await tcpProbe({ host: 'nope.invalid', port: 22, count: 1 }, { connect: scriptedConnect([coded('ENOTFOUND')]), now: clock() });
  assert.equal(r.failure, 'error');
  assert.equal(r.errorCode, 'ENOTFOUND');
  const bare = await tcpProbe({ host: '10.0.0.5', port: 22, count: 1 }, { connect: scriptedConnect([new Error('boom')]), now: clock() });
  assert.equal(bare.failure, 'error');
  assert.equal(bare.errorCode, 'EUNKNOWN');
  const threw = await tcpProbe({ host: '10.0.0.5', port: 22, count: 1 }, { connect: () => { throw coded('EMFILE'); }, now: clock() });
  assert.equal(threw.failure, 'error');
  assert.equal(threw.errorCode, 'EMFILE');
});

test('tcp: a clean run has failure and errorCode null', async () => {
  const r = await tcpProbe({ host: '10.0.0.5', port: 443, count: 2 }, { connect: scriptedConnect(['connect']), now: clock() });
  assert.equal(r.ok, true);
  assert.equal(r.failure, null);
  assert.equal(r.errorCode, null);
});

test('tcp: partial loss reports the LAST failing attempt', async () => {
  const r = await tcpProbe({ host: '10.0.0.5', port: 443, count: 3 }, {
    connect: scriptedConnect([coded('ECONNREFUSED'), 'connect', 'timeout']), now: clock(),
  });
  assert.equal(r.ok, true);
  assert.equal(r.success, 1);
  assert.equal(r.failure, 'timeout');
});

test('tcp: classifier table', () => {
  assert.equal(classifyConnectError('ECONNREFUSED'), 'refused');
  assert.equal(classifyConnectError('ETIMEDOUT'), 'timeout');
  assert.equal(classifyConnectError('EHOSTDOWN'), 'unreachable');
  assert.equal(classifyConnectError('ECONNRESET'), 'error');
});

// ---------------------------------------------------------------- dns
test('dns: the resolver code is reported', async () => {
  const cases = ['ENOTFOUND', 'ETIMEOUT', 'ESERVFAIL', 'ECONNREFUSED'];
  for (const code of cases) {
    // eslint-disable-next-line no-await-in-loop
    const r = await dnsProbe({ host: 'x.example', count: 2 }, { resolver: async () => { throw coded(code); }, now: clock() });
    assert.equal(r.ok, false, code);
    assert.equal(r.errorCode, code);
  }
});

test('dns: null when every lookup answered; the last failing code on partial loss', async () => {
  const ok = await dnsProbe({ host: 'x.example', count: 2 }, { resolver: async () => ({ address: '192.0.2.1' }), now: clock() });
  assert.equal(ok.errorCode, null);
  assert.equal(ok.detail, '192.0.2.1', 'the address detail is unchanged');

  let n = 0;
  const flaky = async () => {
    n += 1;
    if (n === 1) throw coded('ESERVFAIL');
    if (n === 3) throw coded('ETIMEOUT');
    return { address: '192.0.2.1' };
  };
  const partial = await dnsProbe({ host: 'x.example', count: 3 }, { resolver: flaky, now: clock() });
  assert.equal(partial.ok, true);
  assert.equal(partial.errorCode, 'ETIMEOUT');
});

test('dns: a thrown value without a code still reports a failure code', async () => {
  const r = await dnsProbe({ host: 'x.example', count: 1 }, { resolver: async () => { throw new Error('weird'); }, now: clock() });
  assert.equal(r.errorCode, 'EUNKNOWN');
});

// ---------------------------------------------------------------- on the wire
test('dns: the first configured nameserver is reported as the resolver', async () => {
  const r = await dnsProbe({ host: 'plc.example', count: 1 }, {
    resolver: async () => { throw coded('ETIMEOUT'); },
    servers: () => ['10.0.0.53', '10.0.0.54'],
    now: clock(),
  });
  assert.equal(r.errorCode, 'ETIMEOUT');
  assert.equal(r.resolver, '10.0.0.53');
});

test('dns: an injected lookup with no server list names no resolver', async () => {
  const r = await dnsProbe({ host: 'plc.example', count: 1 }, { resolver: async () => ({ address: '10.0.0.9' }), now: clock() });
  assert.equal(r.resolver, null);
});

test('firstServer strips a non-default port and IPv6 brackets, and survives a throwing list', () => {
  assert.equal(firstServer(() => ['192.0.2.1:5353']), '192.0.2.1');
  assert.equal(firstServer(() => ['[2001:db8::1]:5353']), '2001:db8::1');
  assert.equal(firstServer(() => ['2001:db8::53']), '2001:db8::53');
  assert.equal(firstServer(() => []), null);
  assert.equal(firstServer(() => { throw new Error('no resolv.conf'); }), null);
});

test('failure + errorCode survive runProbe and reach POST /agents/probe-results', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const probeRunner = (spec) => runProbe(spec, {
    tcp: { connect: scriptedConnect([coded('ECONNREFUSED')]), now: clock() },
    dns: { resolver: async () => { throw coded('ENOTFOUND'); }, now: clock() },
  });
  const runtime = createAgentRuntime({
    config: {
      serverUrl: server.url, heartbeatMs: 10000, backoff: { baseMs: 30, maxMs: 120, factor: 2 },
      reportIntervalMs: 0, probeIntervalMs: 0, syslogEnabled: false,
    },
    token: 'valid', agentId: 1, logger: silentLogger, probeRunner,
    hsflowdManager: { enable: async () => ({ state: 'active' }), disable: async () => ({ state: 'inactive' }), status: async () => ({ state: 'unknown' }) },
  });
  const once = (name) => new Promise((resolve) => runtime.once(name, resolve));
  try {
    runtime.start();
    await once('config');
    let submitted = once('probe-submitted');
    server.sendCommandToAll({ name: 'run-probe', probe: { type: 'tcp', host: '10.0.0.5', port: 502, count: 1 } });
    await submitted;
    submitted = once('probe-submitted');
    server.sendCommandToAll({ name: 'run-probe', probe: { type: 'dns', host: 'plc.invalid', count: 1 } });
    await submitted;

    const posted = server.receivedProbeResults.map((r) => r.body.results[0]);
    const tcp = posted.find((r) => r.type === 'tcp');
    const dns = posted.find((r) => r.type === 'dns');
    assert.equal(tcp.failure, 'refused');
    assert.equal(tcp.errorCode, 'ECONNREFUSED');
    assert.equal(dns.errorCode, 'ENOTFOUND');
  } finally {
    runtime.stop();
    await server.close();
  }
});
