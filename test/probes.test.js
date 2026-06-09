'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('events');

const { tcpProbe } = require('../src/probes/tcp');
const { dnsProbe } = require('../src/probes/dns');
const { parsePing } = require('../src/probes/ping');
const { parseTraceroute } = require('../src/probes/traceroute');
const { httpProbe, normalizeUrl } = require('../src/probes/http');
const { runProbe } = require('../src/probes');
const { isRunProbeCommand, isRunTestCommand } = require('../src/command');

// A fake tls.connect: returns an EventEmitter socket exposing the given cert and
// invokes the secureConnect callback on the next tick.
function fakeTls(cert) {
  return (_opts, onSecure) => {
    const sock = new EventEmitter();
    sock.getPeerCertificate = () => cert;
    sock.destroy = () => {};
    setImmediate(() => onSecure && onSecure());
    return sock;
  };
}

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

test('parsePing reads the Windows format (loss + Minimum/Maximum/Average)', () => {
  const out = [
    'Pinging 1.2.3.4 with 32 bytes of data:',
    'Reply from 1.2.3.4: bytes=32 time=11ms TTL=117',
    'Ping statistics for 1.2.3.4:',
    '    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),',
    'Approximate round trip times in milli-seconds:',
    '    Minimum = 10ms, Maximum = 12ms, Average = 11ms',
  ].join('\n');
  const p = parsePing(out);
  assert.equal(p.lossPct, 0);
  assert.equal(p.min, 10);
  assert.equal(p.max, 12);
  assert.equal(p.avg, 11);
});

test('parseTraceroute aggregates multi-sample hops into loss + jitter (MTR-style)', () => {
  // Linux `traceroute -q 3` layout: IP then up to 3 RTTs; "*" = a lost probe.
  const out = [
    ' 1  10.0.0.1  1.0 ms  2.0 ms  3.0 ms',
    ' 2  * * *',
    ' 3  93.184.216.34  12.5 ms  *  13.5 ms',
  ].join('\n');
  const hops = parseTraceroute(out, 3);
  assert.equal(hops.length, 3);
  // hop 1: 3/3 answered, avg 2, jitter = mean|Δ| of (1,1) = 1, no loss.
  assert.deepEqual(hops[0], { hop: 1, ip: '10.0.0.1', sent: 3, recv: 3, lossPct: 0, rttMs: 2, minMs: 1, maxMs: 3, jitterMs: 1 });
  // hop 2: silent router — 0/3, 100% loss, null IP, null timings.
  assert.equal(hops[1].ip, null);
  assert.equal(hops[1].recv, 0);
  assert.equal(hops[1].lossPct, 100);
  assert.equal(hops[1].rttMs, null);
  // hop 3: 2/3 answered -> ~33% loss, RTTs averaged.
  assert.equal(hops[2].ip, '93.184.216.34');
  assert.equal(hops[2].recv, 2);
  assert.equal(hops[2].lossPct, 33.33);
  assert.equal(hops[2].rttMs, 13);
});

test('parseTraceroute reads the Windows tracert layout (IP last, "<1 ms")', () => {
  const out = [
    '  1     1 ms     1 ms     1 ms  192.168.1.1',
    '  2     *        *        *     Request timed out.',
    '  3    <1 ms    <1 ms    <1 ms  10.0.0.1',
  ].join('\n');
  const hops = parseTraceroute(out, 3);
  assert.equal(hops[0].ip, '192.168.1.1');
  assert.equal(hops[0].recv, 3);
  assert.equal(hops[0].lossPct, 0);
  assert.equal(hops[1].lossPct, 100);
  assert.equal(hops[2].ip, '10.0.0.1');
  assert.equal(hops[2].rttMs, 0.5); // "<1 ms" -> ~0.5 ms
});

test('normalizeUrl accepts full URLs and defaults a bare host to https', () => {
  assert.equal(normalizeUrl('https://example.com/health').href, 'https://example.com/health');
  assert.equal(normalizeUrl('example.com').href, 'https://example.com/');
  assert.equal(normalizeUrl('ftp://example.com'), null);
  assert.equal(normalizeUrl(''), null);
});

test('httpProbe reports ok + status for a 200 and reads TLS cert expiry', async () => {
  const NOW = Date.UTC(2026, 0, 1);
  const validTo = new Date(NOW + 30 * 86400000).toUTCString();
  const res = await httpProbe(
    { url: 'https://example.com', count: 2 },
    { fetchImpl: async () => ({ status: 200 }), tlsConnect: fakeTls({ valid_to: validTo, issuer: { O: 'Test CA' } }), now: () => NOW }
  );
  assert.equal(res.type, 'http');
  assert.equal(res.target, 'https://example.com/');
  assert.equal(res.ok, true);
  assert.equal(res.status, 200);
  assert.equal(res.lossPct, 0);
  assert.equal(res.certExpiryDays, 30);
});

test('httpProbe treats a 500 as a failed check (loss, not ok)', async () => {
  const res = await httpProbe({ url: 'http://x.test', count: 1 }, { fetchImpl: async () => ({ status: 500 }), now: () => 0 });
  assert.equal(res.ok, false);
  assert.equal(res.status, 500);
  assert.equal(res.lossPct, 100);
});

test('httpProbe counts a network error as loss and leaves status null', async () => {
  const res = await httpProbe(
    { url: 'http://x.test', count: 2 },
    { fetchImpl: async () => { throw new Error('ECONNREFUSED'); }, now: () => 0 }
  );
  assert.equal(res.ok, false);
  assert.equal(res.lossPct, 100);
  assert.equal(res.status, null);
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
