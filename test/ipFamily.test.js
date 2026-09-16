'use strict';

// The IPv4/IPv6 module. Everything the probes know about the difference between
// the two families lives here, so this is where that knowledge is pinned.
//
// The address parser gets the most attention, because the bug it replaced was
// silent: an IPv4-only regex on a traceroute line does not fail loudly on IPv6
// output, it returns null, and a null hop address is indistinguishable from a
// router that declined to answer. The whole path came back as anonymous hops and
// looked like a plausible measurement.

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  FAMILIES, HEADER_OVERHEAD, MSS_OVERHEAD, MIN_PACKET_SIZE,
  familyOf, resolveFamily, findAddress, pingCommand, tracerouteCommands,
} = require('../src/probes/ipFamily');
const { parseTraceroute, traceroute } = require('../src/probes/traceroute');

// ------------------------------------------------------------------ constants
test('the per-family constants are the RFC numbers, not approximations', () => {
  assert.deepEqual(FAMILIES, [4, 6]);
  assert.equal(HEADER_OVERHEAD[4], 28, '20 IP + 8 ICMP');
  assert.equal(HEADER_OVERHEAD[6], 48, '40 IPv6 + 8 ICMPv6');
  assert.equal(MSS_OVERHEAD[4], 40);
  assert.equal(MSS_OVERHEAD[6], 60);
  assert.equal(MIN_PACKET_SIZE[4], 576, 'RFC 791');
  assert.equal(MIN_PACKET_SIZE[6], 1280, 'RFC 8200');
});

// -------------------------------------------------------------------- family
test('familyOf reads a literal and refuses to guess at a hostname', () => {
  assert.equal(familyOf('10.20.30.40'), 4);
  assert.equal(familyOf('2001:db8::1'), 6);
  assert.equal(familyOf('::1'), 6);
  assert.equal(familyOf('::ffff:192.0.2.1'), 6);
  // A name can resolve to either; claiming one would be a guess dressed as a fact.
  assert.equal(familyOf('example.com'), null);
  for (const g of ['', '   ', null, undefined, 42, {}, [], '999.1.1.1', '2001:db8::zz']) {
    assert.equal(familyOf(g), null, JSON.stringify(g));
  }
});

test('resolveFamily: an explicit request wins, a literal names itself, a name means IPv4', () => {
  assert.equal(resolveFamily(6, 'example.com'), 6);
  assert.equal(resolveFamily('6', 'example.com'), 6);
  assert.equal(resolveFamily(4, '2001:db8::1'), 4, 'an explicit 4 is honoured even against a v6 literal');
  // This is what lets an operator type an address and simply get the right family.
  assert.equal(resolveFamily(undefined, '2001:db8::1'), 6);
  assert.equal(resolveFamily(null, '10.20.30.40'), 4);
  assert.equal(resolveFamily('nonsense', 'example.com'), 4);
  assert.equal(resolveFamily(5, 'example.com'), 4, 'an out-of-range request falls back, never throws');
});

// ------------------------------------------------------------------- address
test('findAddress reads IPv4 and IPv6 out of every traceroute layout', () => {
  // Linux/macOS, -n: address first.
  assert.equal(findAddress(' 1  10.0.0.1  1.0 ms  2.0 ms'), '10.0.0.1');
  assert.equal(findAddress(' 1  2001:db8::1  1.0 ms  2.0 ms'), '2001:db8::1');
  // Windows tracert, -d: address last, after the times.
  assert.equal(findAddress('  1     1 ms     1 ms     1 ms  192.168.1.1'), '192.168.1.1');
  assert.equal(findAddress('  1     1 ms     1 ms     1 ms  2001:db8::1'), '2001:db8::1');
  // Without -n the address is parenthesised after the name.
  assert.equal(findAddress(' 2  rtr.example.com (203.0.113.9)  4 ms'), '203.0.113.9');
  assert.equal(findAddress(' 2  rtr.example.com (2001:db8::9)  4 ms'), '2001:db8::9');
  // Bracketed, as Windows writes it with names resolved.
  assert.equal(findAddress('  3  4 ms  rtr [2001:db8::9]'), '2001:db8::9');
  // A responder line, where the address is followed by a separator colon.
  assert.equal(findAddress('1400 bytes from 2001:db8:beef::7: Packet too big'), '2001:db8:beef::7');
  assert.equal(findAddress('64 bytes from 10.20.30.40: icmp_seq=1 ttl=57'), '10.20.30.40');
});

test('findAddress does not mistake timings, hop numbers or prose for an address', () => {
  assert.equal(findAddress(' 2  * * *'), null);
  assert.equal(findAddress('  2     *        *        *     Request timed out.'), null);
  assert.equal(findAddress(' 3  1.0 ms  2.0 ms  3.0 ms'), null, 'RTTs are not addresses');
  assert.equal(findAddress('--- 10 packets transmitted, 9 received ---'), null);
  assert.equal(findAddress(''), null);
  assert.equal(findAddress(null), null);
  assert.equal(findAddress(undefined), null);
});

test('findAddress keeps a trailing colon that belongs to the address', () => {
  // `2001:db8::` is a legal address; blindly stripping a trailing colon would
  // silently report a DIFFERENT host as the hop.
  assert.equal(findAddress(' 1  2001:db8::  1.0 ms'), '2001:db8::');
  // …while the colon after an address in "from <addr>: reason" is a separator.
  assert.equal(findAddress('From 2001:db8::: something'), '2001:db8::');
});

test('findAddress drops a link-local zone, which means nothing off this host', () => {
  assert.equal(findAddress(' 1  fe80::1%eth0  1.0 ms'), 'fe80::1');
});

test('findAddress takes the FIRST address, so a line naming two is unambiguous', () => {
  assert.equal(findAddress(' 1  2001:db8::1  2001:db8::2'), '2001:db8::1');
});

// ---------------------------------------------------- the parser it feeds
test('parseTraceroute now reads an IPv6 path — the bug this module was written for', () => {
  const out = [
    ' 1  2001:db8::1  1.0 ms  1.1 ms  1.2 ms',
    ' 2  * * *',
    ' 3  2001:db8:beef::7  9.0 ms  9.5 ms  10.0 ms',
  ].join('\n');
  const hops = parseTraceroute(out, 3);
  assert.equal(hops.length, 3);
  assert.equal(hops[0].ip, '2001:db8::1');
  assert.equal(hops[0].lossPct, 0);
  // A hop that genuinely did not answer still reads as null — the distinction
  // that was lost when every IPv6 hop came back this way.
  assert.equal(hops[1].ip, null);
  assert.equal(hops[1].lossPct, 100);
  assert.equal(hops[2].ip, '2001:db8:beef::7');
  assert.equal(hops[2].rttMs, 9.5);
});

test('the IPv4 path parses exactly as it did before', () => {
  const out = [
    ' 1  10.0.0.1  1.0 ms  2.0 ms  3.0 ms',
    ' 2  93.184.216.34  10 ms  10 ms  10 ms',
  ].join('\n');
  const hops = parseTraceroute(out, 3);
  assert.equal(hops[0].ip, '10.0.0.1');
  assert.equal(hops[0].rttMs, 2);
  assert.equal(hops[1].ip, '93.184.216.34');
});

// ------------------------------------------------------------ ping commands
test('pingCommand: IPv6 never sets a don\'t-fragment flag, because there is none', () => {
  // RFC 8200 forbids routers from fragmenting IPv6 in transit, so DF is the
  // permanent behaviour and every OS's DF flag is IPv4-only.
  const linux6 = pingCommand({ platform: 'linux', family: 6, payload: 1352, timeoutMs: 1000, host: 'h' });
  assert.ok(linux6.args.includes('-6'));
  assert.ok(linux6.args.includes('-M'), 'Linux still refuses LOCAL fragmentation with -M do');

  const win6 = pingCommand({ platform: 'win32', family: 6, payload: 1352, timeoutMs: 1000, host: 'h' });
  assert.ok(!win6.args.includes('-f'), 'Windows -f is IPv4-only');

  const mac6 = pingCommand({ platform: 'darwin', family: 6, payload: 1352, timeoutMs: 1000, host: 'h' });
  assert.equal(mac6.bin, 'ping6');
  assert.ok(!mac6.args.includes('-D'), 'macOS -D is IPv4-only');
});

test('pingCommand: the hop-limit flag differs on every platform and family', () => {
  const at = (p, f) => pingCommand({ platform: p, family: f, payload: 100, timeoutMs: 1000, ttl: 7, host: 'h' }).args;
  assert.equal(at('linux', 4)[at('linux', 4).indexOf('-t') + 1], '7');
  assert.equal(at('linux', 6)[at('linux', 6).indexOf('-t') + 1], '7');
  assert.equal(at('darwin', 4)[at('darwin', 4).indexOf('-m') + 1], '7');
  assert.equal(at('darwin', 6)[at('darwin', 6).indexOf('-h') + 1], '7');
  assert.equal(at('win32', 4)[at('win32', 4).indexOf('-i') + 1], '7');
  assert.equal(at('win32', 6)[at('win32', 6).indexOf('-i') + 1], '7');
});

test('pingCommand: the timeout unit is right on each platform', () => {
  const ms = 2500;
  const linux = pingCommand({ platform: 'linux', family: 4, payload: 1, timeoutMs: ms, host: 'h' }).args;
  assert.equal(linux[linux.indexOf('-W') + 1], '3', 'Linux -W is SECONDS');
  const mac = pingCommand({ platform: 'darwin', family: 4, payload: 1, timeoutMs: ms, host: 'h' }).args;
  assert.equal(mac[mac.indexOf('-t') + 1], '3', 'macOS -t is a whole-run timeout in SECONDS');
  const mac6 = pingCommand({ platform: 'darwin', family: 6, payload: 1, timeoutMs: ms, host: 'h' }).args;
  assert.equal(mac6[mac6.indexOf('-W') + 1], '2500', 'ping6 -W is MILLISECONDS');
  const win = pingCommand({ platform: 'win32', family: 4, payload: 1, timeoutMs: ms, host: 'h' }).args;
  assert.equal(win[win.indexOf('-w') + 1], '2500', 'Windows -w is MILLISECONDS');
});

test('pingCommand: the target is last, after the end-of-options marker on Unix', () => {
  for (const [platform, family] of [['linux', 4], ['linux', 6], ['darwin', 4], ['darwin', 6]]) {
    const { args } = pingCommand({ platform, family, payload: 1, timeoutMs: 1000, host: 'h' });
    assert.equal(args[args.length - 2], '--', `${platform}/${family}`);
    assert.equal(args[args.length - 1], 'h', `${platform}/${family}`);
  }
  // Windows has no `--`; safeHost() is what closes option injection there.
  const win = pingCommand({ platform: 'win32', family: 4, payload: 1, timeoutMs: 1000, host: 'h' }).args;
  assert.equal(win[win.length - 1], 'h');
});

// ------------------------------------------------------ traceroute commands
test('tracerouteCommands offers both IPv6 binaries, because distributions disagree', () => {
  const linux6 = tracerouteCommands({ platform: 'linux', family: 6, host: 'h', maxHops: 20, queries: 3 });
  assert.deepEqual(linux6.map((c) => c.bin), ['traceroute', 'traceroute6']);
  assert.ok(linux6[0].args.includes('-6'));
  assert.ok(!linux6[1].args.includes('-6'), 'traceroute6 is already IPv6; the flag would be an error');

  // macOS ships traceroute6 and not every version takes -6, so it goes first.
  const mac6 = tracerouteCommands({ platform: 'darwin', family: 6, host: 'h', maxHops: 20, queries: 3 });
  assert.deepEqual(mac6.map((c) => c.bin), ['traceroute6', 'traceroute']);

  // IPv4 is a single candidate — nothing about the existing path changes.
  const v4 = tracerouteCommands({ platform: 'linux', family: 4, host: 'h', maxHops: 20, queries: 3 });
  assert.equal(v4.length, 1);
  assert.deepEqual(v4[0], { bin: 'traceroute', args: ['-n', '-m', '20', '-q', '3', '-w', '2', '--', 'h'] });

  const win6 = tracerouteCommands({ platform: 'win32', family: 6, host: 'h', maxHops: 20, queries: 3 });
  assert.deepEqual(win6, [{ bin: 'tracert', args: ['-6', '-d', '-h', '20', 'h'] }]);
});

// --------------------------------------------------- traceroute integration
test('traceroute traces IPv6 and falls back to the second binary when the first is absent', async () => {
  const tried = [];
  const exec = (bin, args, _opts, cb) => {
    tried.push(bin);
    if (bin === 'traceroute') { const e = new Error('ENOENT'); e.code = 'ENOENT'; return cb(e, ''); }
    cb(null, ' 1  2001:db8::1  1.0 ms  1.0 ms  1.0 ms\n 2  2001:db8::40  9.0 ms  9.0 ms  9.0 ms\n');
  };
  const res = await traceroute({ host: '2001:db8::40' }, { exec, platform: 'linux' });
  assert.deepEqual(tried, ['traceroute', 'traceroute6']);
  assert.equal(res.ok, true);
  assert.equal(res.ipVersion, 6, 'the literal selected IPv6 with no parameter');
  assert.equal(res.hops[0].ip, '2001:db8::1');
  assert.equal(res.hops[1].ip, '2001:db8::40');
});

test('traceroute names the first candidate when no IPv6 binary exists at all', async () => {
  const exec = (bin, _a, _o, cb) => { const e = new Error('ENOENT'); e.code = 'ENOENT'; cb(e, ''); };
  const res = await traceroute({ host: '2001:db8::40' }, { exec, platform: 'linux' });
  assert.equal(res.ok, false);
  assert.equal(res.error, 'traceroute not installed', 'the reason names the tool the server can install');
  assert.deepEqual(res.hops, []);
});

test('a non-ENOENT failure belongs to the binary that ran — no pointless second attempt', async () => {
  const tried = [];
  const exec = (bin, _a, _o, cb) => { tried.push(bin); cb(Object.assign(new Error('boom'), { killed: true }), ''); };
  const res = await traceroute({ host: '2001:db8::40' }, { exec, platform: 'linux' });
  assert.deepEqual(tried, ['traceroute'], 'a real failure must not be retried against another binary');
  assert.equal(res.error, 'traceroute timed out');
});

test('an explicit ip_version overrides what the literal says', async () => {
  let seen = null;
  const exec = (bin, args, _o, cb) => { seen = { bin, args }; cb(null, ' 1  10.0.0.1  1.0 ms\n'); };
  const res = await traceroute({ host: 'example.com', ip_version: 6 }, { exec, platform: 'linux' });
  assert.equal(res.ipVersion, 6);
  assert.ok(seen.args.includes('-6'));
});

test('the IPv4 traceroute is unchanged: one binary, no -6, same argv', async () => {
  const tried = [];
  let seen = null;
  const exec = (bin, args, _o, cb) => { tried.push(bin); seen = args; cb(null, ' 1  10.0.0.1  1.0 ms  1.0 ms  1.0 ms\n'); };
  const res = await traceroute({ host: 'example.com' }, { exec, platform: 'linux' });
  assert.deepEqual(tried, ['traceroute']);
  assert.deepEqual(seen, ['-n', '-m', '20', '-q', '3', '-w', '2', '--', 'example.com']);
  assert.equal(res.ipVersion, 4);
  assert.equal(res.hops[0].ip, '10.0.0.1');
});
