'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('events');

const { tcpProbe } = require('../src/probes/tcp');
const { dnsProbe } = require('../src/probes/dns');
const { parsePing } = require('../src/probes/ping');
const { parseTraceroute } = require('../src/probes/traceroute');
const { runProbe } = require('../src/probes');
const { isRunProbeCommand, isRunTestCommand } = require('../src/command');

// A fake socket that emits `event` ('connect' | 'error' | 'timeout') on next tick.
function fakeConnect(event) {
  return () => {
    const sock = new EventEmitter();
    sock.setTimeout = () => {};
    sock.destroy = () => {};
    setImmediate(() => sock.emit(event));
    return sock;
  };
}
// Monotonic clock: each call advances 5ms, so a connect "takes" 5ms.
function clock() {
  let t = 1000;
  return () => { const v = t; t += 5; return v; };
}

test('tcpProbe reports success, RTT and zero loss on connect', async () => {
  const res = await tcpProbe({ host: '1.2.3.4', port: 443, count: 2, timeoutMs: 100 }, { connect: fakeConnect('connect'), now: clock() });
  assert.equal(res.type, 'tcp');
  assert.equal(res.target, '1.2.3.4:443');
  assert.equal(res.ok, true);
  assert.equal(res.success, 2);
  assert.equal(res.lossPct, 0);
  assert.equal(res.rttMs, 5);
});

test('tcpProbe reports 100% loss when every connect errors/times out', async () => {
  const err = await tcpProbe({ host: '1.2.3.4', port: 443, count: 3 }, { connect: fakeConnect('error'), now: clock() });
  assert.equal(err.ok, false);
  assert.equal(err.lossPct, 100);
  assert.equal(err.success, 0);
});

test('tcpProbe rejects an invalid port', async () => {
  const res = await tcpProbe({ host: 'x', port: 0 });
  assert.equal(res.ok, false);
  assert.equal(res.lossPct, 100);
});

test('dnsProbe times successful lookups and records the address', async () => {
  const res = await dnsProbe({ host: 'example.com', count: 2 }, { resolver: async () => ({ address: '93.184.216.34' }), now: clock() });
  assert.equal(res.type, 'dns');
  assert.equal(res.ok, true);
  assert.equal(res.success, 2);
  assert.equal(res.detail, '93.184.216.34');
});

test('dnsProbe counts failures as loss', async () => {
  const res = await dnsProbe({ host: 'nope.invalid', count: 2 }, { resolver: async () => { throw new Error('NXDOMAIN'); }, now: clock() });
  assert.equal(res.ok, false);
  assert.equal(res.lossPct, 100);
});

test('parsePing reads loss% and rtt summary (Linux format)', () => {
  const out = [
    'PING host (1.2.3.4) 56(84) bytes of data.',
    '--- host ping statistics ---',
    '4 packets transmitted, 4 received, 0% packet loss, time 3004ms',
    'rtt min/avg/max/mdev = 10.1/12.2/15.3/1.4 ms',
  ].join('\n');
  const p = parsePing(out);
  assert.equal(p.lossPct, 0);
  assert.equal(p.min, 10.1);
  assert.equal(p.avg, 12.2);
  assert.equal(p.max, 15.3);
  assert.equal(p.mdev, 1.4);
});

test('parsePing reads partial loss', () => {
  const out = '4 packets transmitted, 3 received, 25% packet loss\nrtt min/avg/max/mdev = 10/12/15/1 ms';
  assert.equal(parsePing(out).lossPct, 25);
});

test('parseTraceroute extracts hops, ips and rtt (timeouts -> null ip)', () => {
  const out = ' 1  10.0.0.1  1.2 ms\n 2  * * *\n 3  93.184.216.34  12.5 ms';
  const hops = parseTraceroute(out);
  assert.equal(hops.length, 3);
  assert.deepEqual(hops[0], { hop: 1, ip: '10.0.0.1', rttMs: 1.2 });
  assert.equal(hops[1].ip, null);
  assert.equal(hops[2].ip, '93.184.216.34');
});

test('runProbe dispatches by type and stamps a ts', async () => {
  const res = await runProbe({ type: 'tcp', host: '1.2.3.4', port: 80, count: 1 }, { tcp: { connect: fakeConnect('connect'), now: clock() } });
  assert.equal(res.type, 'tcp');
  assert.ok(res.ts);
  assert.equal(res.ok, true);
});

test('runProbe returns an error result for an unknown type (never throws)', async () => {
  const res = await runProbe({ type: 'wat', host: 'x' });
  assert.equal(res.ok, false);
  assert.match(res.error, /unknown probe type/);
});

test('isRunProbeCommand needs the run-probe verb AND a probe object', () => {
  assert.equal(isRunProbeCommand({ name: 'run-probe', probe: { type: 'ping', host: 'x' } }), true);
  assert.equal(isRunProbeCommand({ name: 'run-probe' }), false);
  assert.equal(isRunProbeCommand({ name: 'run-test' }), false);
  assert.equal(isRunTestCommand({ name: 'run-test' }), true);
});
