'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { parseCidr, totalAddresses, inScope } = require('../src/discovery/cidr');
const { createScanner, validateScope, DiscoveryScopeError } = require('../src/discovery/scanner');
const { createRateLimiter } = require('../src/discovery/rateLimiter');
const { collectLocalCidrs } = require('../src/localIps');

// ---- cidr helpers ----------------------------------------------------------

test('parseCidr computes network + count; totalAddresses sums without expanding', () => {
  const p = parseCidr('192.168.1.128/25');
  assert.equal(p.count, 128);
  assert.equal(inScope('192.168.1.200', [p]), true);
  assert.equal(inScope('192.168.1.10', [p]), false);
  const t = totalAddresses(['10.0.0.0/30', '10.0.1.0/30', 'nope']);
  assert.equal(t.count, 8);
  assert.deepEqual(t.invalid, ['nope']);
});

// ---- scope refusal ---------------------------------------------------------

test('validateScope refuses empty and over-cap scopes', () => {
  assert.throws(() => validateScope({ cidrs: [], addressCap: 100 }), (e) => e instanceof DiscoveryScopeError && e.code === 'scope_unconfigured');
  assert.throws(() => validateScope({ cidrs: ['10.0.0.0/8'], addressCap: 65536 }), (e) => e.code === 'scope_too_large');
  assert.throws(() => validateScope({ cidrs: ['bogus'], addressCap: 100 }), (e) => e.code === 'scope_invalid');
});

// ---- scanner (injected probes + rate limiter) ------------------------------

test('scanner probes only in-scope addresses and returns live candidates', async () => {
  const seen = [];
  const scanner = createScanner({
    tcpProbe: async (ip, port) => { seen.push(`${ip}:${port}`); return ip === '10.0.0.2' && port === 22; },
    icmpProbe: async () => null,
    dnsReverse: async (ip) => (ip === '10.0.0.2' ? 'host2.lan' : null),
    ports: [22, 80],
  });
  const limiter = createRateLimiter({ ratePerSec: 1000, sleep: async () => {} });
  const res = await scanner.scan({ cidrs: ['10.0.0.0/30'], addressCap: 100, rateLimiter: limiter });
  // /30 = 4 addresses; only 10.0.0.2 had an open port → one candidate.
  assert.equal(res.addresses, 4);
  assert.equal(res.candidates.length, 1);
  assert.deepEqual(res.candidates[0], { ip: '10.0.0.2', hostname: 'host2.lan', openPorts: [22], icmp: false });
  // Every probed target was inside 10.0.0.0/30.
  assert.ok(seen.every((s) => inScope(s.split(':')[0], [parseCidr('10.0.0.0/30')])));
});

// ---- own-subnet derivation (empty-scope default) ---------------------------

test('collectLocalCidrs derives the network CIDR from interface addresses', () => {
  const cidrs = collectLocalCidrs({
    networkInterfaces: () => ({
      lo: [{ address: '127.0.0.1', family: 'IPv4', internal: true, cidr: '127.0.0.1/8' }],
      eth0: [{ address: '192.168.1.34', family: 'IPv4', internal: false, cidr: '192.168.1.34/24' }],
      eth1: [{ address: '169.254.1.1', family: 'IPv4', internal: false, cidr: '169.254.1.1/16' }], // link-local skipped
      wg0: [{ address: '10.8.0.2', family: 'IPv4', internal: false, cidr: '10.8.0.2/32' }], // /32 skipped
      v6: [{ address: 'fe80::1', family: 'IPv6', internal: false, cidr: 'fe80::1/64' }], // IPv6 skipped
    }),
  });
  assert.deepEqual(cidrs, ['192.168.1.0/24']);
});

// ---- ICMP echo (system ping, injected exec) --------------------------------

const { createIcmpProbe } = require('../src/discovery/probes');
const { DEFAULT_PORTS } = require('../src/discovery/scanner');

const LINUX_REPLY = [
  'PING 10.0.0.9 (10.0.0.9) 56(84) bytes of data.',
  '64 bytes from 10.0.0.9: icmp_seq=1 ttl=64 time=0.412 ms',
  '',
  '--- 10.0.0.9 ping statistics ---',
  '1 packets transmitted, 1 received, 0% packet loss, time 0ms',
  'rtt min/avg/max/mdev = 0.412/0.412/0.412/0.000 ms',
].join('\n');
const LINUX_SILENT = '--- 10.0.0.8 ping statistics ---\n1 packets transmitted, 0 received, 100% packet loss, time 0ms\n';

function fakeExec(respond) {
  const calls = [];
  const exec = (bin, args, opts, cb) => { calls.push({ bin, args, opts }); setImmediate(() => respond(args, cb)); };
  return { exec, calls };
}

test('icmp: one echo, short deadline, host after --; a reply is alive', async () => {
  const { exec, calls } = fakeExec((_a, cb) => cb(null, LINUX_REPLY, ''));
  const icmp = createIcmpProbe({ exec, platform: 'linux', timeoutMs: 1000 });
  assert.equal(await icmp('10.0.0.9'), true);
  assert.equal(calls[0].bin, 'ping');
  assert.deepEqual(calls[0].args, ['-c', '1', '-w', '1', '--', '10.0.0.9']);
  assert.ok(calls[0].opts.timeout <= 5000, 'the child is bounded too');
});

test('icmp: ping ran and nothing answered is false (exit 1 is normal for that)', async () => {
  const { exec } = fakeExec((_a, cb) => cb(Object.assign(new Error('exit 1'), { code: 1 }), LINUX_SILENT, ''));
  assert.equal(await createIcmpProbe({ exec, platform: 'linux' })('10.0.0.8'), false);
});

test('icmp: no ping binary is "unknown", and is not retried for every address', async () => {
  const { exec, calls } = fakeExec((_a, cb) => cb(Object.assign(new Error('spawn ping ENOENT'), { code: 'ENOENT' }), '', ''));
  const icmp = createIcmpProbe({ exec, platform: 'linux' });
  assert.equal(await icmp('10.0.0.1'), null);
  assert.equal(await icmp('10.0.0.2'), null);
  assert.equal(calls.length, 1, 'the missing binary is latched');
});

test('icmp: unreadable output is "unknown", an unsafe host never spawns', async () => {
  const { exec, calls } = fakeExec((_a, cb) => cb(new Error('ping: socket: Operation not permitted'), '', 'ping: socket: Operation not permitted'));
  const icmp = createIcmpProbe({ exec, platform: 'linux' });
  assert.equal(await icmp('10.0.0.1'), null);
  assert.equal(await icmp('-f'), null);
  assert.equal(calls.length, 1);
});

test('icmp: on Windows a router\'s "Destination host unreachable" is not a reply from the host', async () => {
  const unreachable = [
    'Pinging 10.0.0.7 with 32 bytes of data:',
    'Reply from 10.0.0.1: Destination host unreachable.',
    '',
    'Ping statistics for 10.0.0.7:',
    '    Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),',
  ].join('\r\n');
  const reply = [
    'Pinging 10.0.0.9 with 32 bytes of data:',
    'Reply from 10.0.0.9: bytes=32 time<1ms TTL=64',
    '',
    'Ping statistics for 10.0.0.9:',
    '    Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),',
    'Approximate round trip times in milli-seconds:',
    '    Minimum = 0ms, Maximum = 0ms, Average = 0ms',
  ].join('\r\n');
  const { exec, calls } = fakeExec((args, cb) => cb(null, args.includes('10.0.0.9') ? reply : unreachable, ''));
  const icmp = createIcmpProbe({ exec, platform: 'win32' });
  assert.equal(await icmp('10.0.0.7'), false);
  assert.equal(await icmp('10.0.0.9'), true);
  assert.deepEqual(calls[0].args, ['-n', '1', '-w', '1000', '10.0.0.7']);
});

test('scanner finds a host that answers ICMP only (a typical PLC), TCP sweep unchanged', async () => {
  const seen = [];
  const scanner = createScanner({
    tcpProbe: async (ip, port) => { seen.push(`${ip}:${port}`); return false; },
    icmpProbe: async (ip) => ip === '10.0.0.1',
    dnsReverse: async () => null,
    ports: [502, 102],
  });
  const limiter = createRateLimiter({ ratePerSec: 1000, sleep: async () => {} });
  const res = await scanner.scan({ cidrs: ['10.0.0.0/30'], addressCap: 100, rateLimiter: limiter });
  assert.deepEqual(res.candidates, [{ ip: '10.0.0.1', hostname: null, openPorts: [], icmp: true }]);
  // Every port was still tried on every address, in order.
  assert.equal(seen.length, 4 * 2);
  assert.deepEqual(seen.slice(0, 2), ['10.0.0.0:502', '10.0.0.0:102']);
});

test('an ICMP probe that throws costs the echo, not the sweep', async () => {
  const scanner = createScanner({
    tcpProbe: async (ip, port) => ip === '10.0.0.2' && port === 22,
    icmpProbe: async () => { throw new Error('boom'); },
    dnsReverse: async () => null,
    ports: [22],
  });
  const limiter = createRateLimiter({ ratePerSec: 1000, sleep: async () => {} });
  const res = await scanner.scan({ cidrs: ['10.0.0.0/30'], addressCap: 100, rateLimiter: limiter });
  assert.deepEqual(res.candidates, [{ ip: '10.0.0.2', hostname: null, openPorts: [22], icmp: false }]);
});

test('the default port list covers the OT/ICS protocols, TCP only', () => {
  for (const p of [22, 80, 161, 443, 3389]) assert.ok(DEFAULT_PORTS.includes(p), `IT port ${p} kept`);
  for (const p of [102, 502, 2404, 20000, 44818, 4840]) assert.ok(DEFAULT_PORTS.includes(p), `OT port ${p}`);
  assert.equal(DEFAULT_PORTS.includes(47808), false, 'BACnet is UDP; a TCP connect cannot find it');
  assert.equal(new Set(DEFAULT_PORTS).size, DEFAULT_PORTS.length);
});

test('with no ports from the server the scanner sweeps the default list', async () => {
  const seenPorts = new Set();
  const scanner = createScanner({
    tcpProbe: async (_ip, port) => { seenPorts.add(port); return false; },
    icmpProbe: async () => null,
    dnsReverse: async () => null,
  });
  const limiter = createRateLimiter({ ratePerSec: 1e6, sleep: async () => {} });
  await scanner.scan({ cidrs: ['10.0.0.1/32'], addressCap: 10, rateLimiter: limiter, portList: [] });
  assert.deepEqual([...seenPorts], DEFAULT_PORTS);
});

// ---- per-address port concurrency -------------------------------------------

// A fake socket that never answers: resolves "closed" after the connect
// timeout, the way a silent address (firewall drops the SYN) behaves.
function silentProbe({ inFlight }) {
  return (ip, port, { timeoutMs }) => new Promise((resolve) => {
    inFlight.now += 1;
    inFlight.max = Math.max(inFlight.max, inFlight.now);
    setTimeout(() => { inFlight.now -= 1; resolve(false); }, timeoutMs);
  });
}

test('a silent address costs ~ceil(ports / concurrency) timeouts, not one per port', async () => {
  const inFlight = { now: 0, max: 0 };
  const scanner = createScanner({
    tcpProbe: silentProbe({ inFlight }),
    icmpProbe: async () => false,
    dnsReverse: async () => null,
    tcpTimeoutMs: 60,
    portConcurrency: 4,
  });
  const limiter = createRateLimiter({ ratePerSec: 1e6, sleep: async () => {} });
  const t0 = Date.now();
  const res = await scanner.scan({ cidrs: ['10.0.0.1/32'], addressCap: 10, rateLimiter: limiter });
  const took = Date.now() - t0;
  assert.equal(res.candidates.length, 0);
  // 11 default ports, 4 at a time = 3 waves of 60 ms. Sequential was 660 ms.
  assert.ok(took < 11 * 60 * 0.6, `took ${took} ms`);
  assert.ok(took >= 3 * 60 - 10, `took ${took} ms`);
  assert.equal(inFlight.max, 4, 'never more than portConcurrency connects in flight');
});

test('concurrent port probes still honour the rate limit (grants never bunch up)', async () => {
  // Real timers, short interval: 100/s = one grant per 10 ms. Six workers race
  // for those slots, which is the case that used to fail: each one waiting read
  // the same `nextAt`, computed the same wait, and they all woke together — so a
  // scan fired six probes in one millisecond and the rate limit meant nothing.
  const limiter = createRateLimiter({ ratePerSec: 100 });
  const grants = [];
  const wrapped = { acquire: async () => { await limiter.acquire(); grants.push(performance.now()); } };
  const scanner = createScanner({
    tcpProbe: async () => false,
    icmpProbe: async () => true,
    dnsReverse: async () => null,
    ports: [1, 2, 3, 4, 5, 6],
    portConcurrency: 6,
  });
  await scanner.scan({ cidrs: ['10.0.0.1/32'], addressCap: 10, rateLimiter: wrapped });
  // 1 address grant + 6 ports + 1 rDNS (icmp alive) = 8 grants.
  assert.equal(grants.length, 8);

  // What matters is the RATE, not each individual gap. Slots are absolute, so an
  // oversleeping timer is absorbed by the grant after it: a 15 ms gap is followed
  // by a 4 ms one and the schedule is still exactly on time. Asserting a floor on
  // every gap forbade that catch-up and failed intermittently on a loaded
  // machine — for the behaviour that keeps the average right.
  const elapsed = grants[grants.length - 1] - grants[0];
  const expected = (grants.length - 1) * limiter.intervalMs;
  // Tolerance for libuv's cached loop time (a 10 ms timer may fire a few ms early
  // by the wall clock).
  assert.ok(
    elapsed >= expected - 8,
    `8 grants took ${elapsed.toFixed(1)} ms; at 100/s they must take about ${expected} ms`
  );

  // And bunching, which is the actual regression this guards: two grants in the
  // same instant. Real spacing is milliseconds; a bunched pair is ~0 ms apart.
  for (let i = 1; i < grants.length; i += 1) {
    const gap = grants[i] - grants[i - 1];
    assert.ok(gap >= 1, `grant ${i} came ${gap.toFixed(3)} ms after the previous — they bunched`);
  }
});

test('open ports come back in list order whatever order the connects finish in', async () => {
  const delays = { 22: 40, 80: 5, 443: 20 };
  const scanner = createScanner({
    tcpProbe: (ip, port) => new Promise((r) => setTimeout(() => r(port !== 3389), delays[port] || 1)),
    icmpProbe: async () => null,
    dnsReverse: async () => null,
    ports: [22, 80, 443, 3389],
    portConcurrency: 4,
  });
  const limiter = createRateLimiter({ ratePerSec: 1e6, sleep: async () => {} });
  const res = await scanner.scan({ cidrs: ['10.0.0.1/32'], addressCap: 10, rateLimiter: limiter });
  assert.deepEqual(res.candidates[0].openPorts, [22, 80, 443]);
});

test('a port probe that throws is closed, the address sweep carries on', async () => {
  const scanner = createScanner({
    tcpProbe: async (ip, port) => { if (port === 80) throw new Error('EMFILE'); return port === 443; },
    icmpProbe: async () => null,
    dnsReverse: async () => null,
    ports: [80, 443],
  });
  const limiter = createRateLimiter({ ratePerSec: 1e6, sleep: async () => {} });
  const res = await scanner.scan({ cidrs: ['10.0.0.1/32'], addressCap: 10, rateLimiter: limiter });
  assert.deepEqual(res.candidates[0].openPorts, [443]);
});
