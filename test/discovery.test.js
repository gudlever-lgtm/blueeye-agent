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
