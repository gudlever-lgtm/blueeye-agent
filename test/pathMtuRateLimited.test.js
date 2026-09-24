'use strict';

// path_mtu numbered the path wrong wherever ICMP is rate-limited. It listed the
// path with a ONE-query traceroute and dropped every hop that did not answer,
// so on the end-to-end rig (agent -> router 198.51.100.2 -> target 203.0.113.2,
// Linux icmp_ratelimit=1000 ms on the target) a target TWO hops away was stored
// at hop 18: the target's reply to TTL 2 was rate-limited away, and traceroute
// kept going until a later TTL's reply got through.
//
// Fixtures in test/fixtures/traceroute/ are that rig's own output, captured
// 2026-09-24 with "Modern traceroute for Linux" 2.1.5 (`traceroute -n -m 32
// -q <1|2|3> -w 2 -- 203.0.113.2`) and iputils ping (`ping -c1 -t <1|2> -s 548
// -W 1 203.0.113.2`). Note that even -q 2 and -q 3 put the target at hop 10
// and hop 7: more queries per hop help, but only the TTL-limited ping can say
// where the target really is.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { pathMtuProbe, HOP_STATUS } = require('../src/probes/pathmtu');
const { parseTraceroute } = require('../src/probes/traceroute');

const FIX = path.join(__dirname, 'fixtures', 'traceroute');
const fixture = (name) => fs.readFileSync(path.join(FIX, name), 'utf8');
const TIMEOUT = fs.readFileSync(path.join(__dirname, 'fixtures', 'pathmtu', 'linux-timeout.txt'), 'utf8');

// A fake exec for the real rig: every link carries 1500, the router answers
// TTL 1 with time-exceeded, and anything with TTL >= 2 reaches the target.
// `traceText(q)` picks the captured trace for the -q the probe asked for.
// `silentTtls` never answer a ping (a router that drops TTL-expired ICMP).
function rig({ traceText, silentTtls = [], targetAt = 2, routerTtls = { 1: 'linux-ping-ttl1-ttl-exceeded.txt' } }) {
  const calls = { trace: [], ping: [] };
  function exec(bin, args, opts, cb) {
    if (bin === 'ss') return cb(new Error('no ss'), '', '');
    if (bin === 'traceroute') {
      const q = Number(args[args.indexOf('-q') + 1]);
      calls.trace.push(args);
      return cb(null, traceText(q), '');
    }
    const ttlAt = args.indexOf('-t');
    const ttl = ttlAt >= 0 ? Number(args[ttlAt + 1]) : null;
    const size = Number(args[args.indexOf('-s') + 1]) + 28;
    calls.ping.push({ ttl, size });
    if (size > 1500) return cb(new Error('frag'), TIMEOUT, '');
    if (ttl != null && silentTtls.includes(ttl)) return cb(new Error('timeout'), TIMEOUT, '');
    if (ttl == null || ttl >= targetAt) return cb(null, fixture('linux-ping-ttl2-reply.txt'), '');
    const text = routerTtls[ttl] ? fixture(routerTtls[ttl])
      : fixture('linux-ping-ttl1-ttl-exceeded.txt').replace('198.51.100.2', `198.51.100.${10 + ttl}`);
    return cb(new Error('ttl'), text, '');
  }
  return { exec, calls };
}

const probe = (sim) => pathMtuProbe({ host: '203.0.113.2', max_size: 1500 }, {
  exec: sim.exec, platform: 'linux', connectImpl: null, now: () => Date.now(),
});

test('the captured traces really are rate-limited (target at hop 18, 10 and 7)', () => {
  const last = (f, q) => { const h = parseTraceroute(fixture(f), q).filter((x) => x.ip); return h[h.length - 1]; };
  assert.deepEqual([1, 2, 3].map((q) => last(`linux-ratelimited-q${q}.txt`, q).hop), [18, 10, 7]);
  assert.equal(last('linux-ratelimited-q1.txt', 1).ip, '203.0.113.2');
});

for (const q of [1, 2, 3]) {
  test(`a 2-hop target behind a rate-limited trace (-q ${q} output) is stored at hop 2, not later`, async () => {
    const sim = rig({ traceText: () => fixture(`linux-ratelimited-q${q}.txt`) });
    const r = await probe(sim);
    assert.equal(r.ok, true);
    assert.deepEqual(r.hops.map((h) => [h.hop, h.ip, h.status]), [
      [1, '198.51.100.2', HOP_STATUS.OK],
      // Silent in the trace; the TTL-2 ping was answered by the target itself.
      [2, '203.0.113.2', HOP_STATUS.OK],
    ]);
    assert.equal(r.path_mtu, 1500);
    assert.equal(r.mtu_drop_at_hop, null);
    // Nothing past the target was probed.
    assert.ok(sim.calls.ping.every((p) => p.ttl == null || p.ttl <= 2), JSON.stringify(sim.calls.ping.map((p) => p.ttl)));
  });
}

test('the path is listed with at least two queries per hop', async () => {
  const sim = rig({ traceText: () => fixture('linux-ratelimited-q2.txt') });
  await probe(sim);
  assert.equal(sim.calls.trace.length, 1);
  const args = sim.calls.trace[0];
  assert.ok(Number(args[args.indexOf('-q') + 1]) >= 2, args.join(' '));
});

test('a silent hop keeps its number and later hops keep theirs', async () => {
  // Four hops; hop 2 answers neither the trace nor a ping (drops TTL-expired
  // ICMP). It used to be dropped from the list, which is harmless only while
  // everybody reads `hop` rather than the position.
  const trace = [
    'traceroute to 203.0.113.2 (203.0.113.2), 32 hops max, 60 byte packets',
    ' 1  198.51.100.2  0.227 ms  0.031 ms',
    ' 2  * *',
    ' 3  198.51.100.13  0.410 ms  0.388 ms',
    ' 4  203.0.113.2  0.512 ms  0.498 ms',
  ].join('\n');
  const sim = rig({ traceText: () => trace, silentTtls: [2], targetAt: 4 });
  const r = await probe(sim);
  assert.deepEqual(r.hops.map((h) => [h.hop, h.ip, h.status]), [
    [1, '198.51.100.2', HOP_STATUS.OK],
    [2, null, HOP_STATUS.NO_RESPONSE],
    [3, '198.51.100.13', HOP_STATUS.OK],
    [4, '203.0.113.2', HOP_STATUS.OK],
  ]);
});

test('a hop silent to the trace but answering the ping gets the ping\'s address', async () => {
  const trace = [
    ' 1  198.51.100.2  0.227 ms  0.031 ms',
    ' 2  * *',
    ' 3  203.0.113.2  0.512 ms  0.498 ms',
  ].join('\n');
  const sim = rig({ traceText: () => trace, targetAt: 3 });
  const r = await probe(sim);
  assert.deepEqual(r.hops.map((h) => [h.hop, h.ip]), [[1, '198.51.100.2'], [2, '198.51.100.12'], [3, '203.0.113.2']]);
});

test('silent lines after the last answering hop are left out, not listed as no_response', async () => {
  const trace = [' 1  198.51.100.2  0.2 ms  0.1 ms', ...Array.from({ length: 30 }, (_, i) => `${String(i + 2).padStart(2)}  * *`)].join('\n');
  const sim = rig({ traceText: () => trace, targetAt: 99 });
  const r = await probe(sim);
  assert.deepEqual(r.hops.map((h) => h.hop), [1]);
  assert.ok(sim.calls.ping.every((p) => p.ttl == null || p.ttl === 1));
});
