'use strict';

// `ping` with a don't-fragment size sweep — the probe that tells an MTU
// blackhole from a lossy link.
//
// The per-hop path_mtu probe is a separate module with its own suite
// (test/pathMtu.test.js); this one covers the sweep, the per-platform argv and
// the rule that keeps a blocked 1472-byte packet from reading as an outage.

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { pingProbe, buildPingArgs, parseMtuHint, normalizeSizes } = require('../src/probes/ping');

// --- canned `ping` output ----------------------------------------------------

const okOutput = (sent = 1) => [
  `PING h (1.2.3.4) 56(84) bytes of data.`,
  `--- h ping statistics ---`,
  `${sent} packets transmitted, ${sent} received, 0% packet loss, time 0ms`,
  `rtt min/avg/max/mdev = 1.0/2.0/3.0/0.5 ms`,
].join('\n');

const lossOutput = (sent = 1) => [
  `PING h (1.2.3.4) 56(84) bytes of data.`,
  `--- h ping statistics ---`,
  `${sent} packets transmitted, 0 received, 100% packet loss, time 0ms`,
].join('\n');

const fragNeededOutput = (mtu) => [
  `PING h (1.2.3.4) 1472(1500) bytes of data.`,
  `From 10.0.0.1 icmp_seq=1 Frag needed and DF set (mtu = ${mtu})`,
  `--- h ping statistics ---`,
  `1 packets transmitted, 0 received, 100% packet loss, time 0ms`,
].join('\n');

// A fake execFile driven by a decision function over the parsed argv. Records
// every call so a test can assert on what was actually asked of the system tool.
function fakePing(decide) {
  const calls = [];
  const exec = (cmd, args, _opts, cb) => {
    const sizeIdx = args.findIndex((a) => a === '-s' || a === '-l');
    const size = sizeIdx >= 0 ? Number(args[sizeIdx + 1]) : null;
    const host = args[args.length - 1];
    const df = args.includes('-M') || args.includes('-D') || args.includes('-f');
    calls.push({ cmd, args, size, host, df });
    const out = decide({ size, host, df, args });
    setImmediate(() => cb(out.err || null, out.stdout || '', out.stderr || ''));
  };
  return { exec, calls };
}

// A path that carries `limit` payload bytes and silently drops anything bigger.
const blackholeAt = (limit) => ({ size }) =>
  (size == null || size <= limit ? { stdout: okOutput() } : { stdout: lossOutput(), err: new Error('exit 1') });

// --- ping: size sweep --------------------------------------------------------

test('pingProbe without sizes keeps its historical argv and shape', async () => {
  const { exec, calls } = fakePing(() => ({ stdout: okOutput(4) }));
  const res = await pingProbe({ host: 'h', count: 4 }, { exec, platform: 'linux' });
  assert.deepEqual(calls[0].args, ['-c', '4', '-w', '10', '--', 'h']);
  assert.equal(res.type, 'ping');
  assert.equal(res.ok, true);
  assert.equal(res.lossPct, 0);
  assert.equal(res.rttMs, 2);
  assert.equal(res.sizes, undefined, 'no sweep means no sizes array');
  assert.equal(res.df, undefined);
});

test('pingProbe sweeps each size in one run and reports them separately', async () => {
  const { exec, calls } = fakePing(blackholeAt(64));
  const res = await pingProbe({ host: 'h', count: 1, sizes: [64, 1472], df: true }, { exec, platform: 'linux' });
  assert.equal(calls.length, 2);
  assert.deepEqual(calls.map((c) => c.size), [64, 1472]);
  assert.ok(calls.every((c) => c.df), 'every sweep packet carries DF');
  assert.equal(res.sizes.length, 2);
  assert.equal(res.sizes[0].bytes, 64);
  assert.equal(res.sizes[0].lossPct, 0);
  assert.equal(res.sizes[1].bytes, 1472);
  assert.equal(res.sizes[1].lossPct, 100);
});

test('a size sweep reports the SMALLEST size at the top level, so a blocked 1472 is not an outage', async () => {
  const { exec } = fakePing(blackholeAt(64));
  const res = await pingProbe({ host: 'h', count: 1, sizes: [64, 1472], df: true }, { exec, platform: 'linux' });
  // This is the whole point: reachability says the host is up. Only the
  // per-size detail carries the size dependence.
  assert.equal(res.ok, true);
  assert.equal(res.lossPct, 0);
  assert.equal(res.sizes[1].lossPct, 100);
});

test('sizes are deduped, sorted and capped; junk entries are dropped', () => {
  assert.deepEqual(normalizeSizes([1472, 64, 64, '512']), [64, 512, 1472]);
  assert.deepEqual(normalizeSizes([-1, 'x', null, 99999999]), null);
  assert.equal(normalizeSizes([]), null);
  assert.equal(normalizeSizes('1472'), null);
  assert.equal(normalizeSizes([1, 2, 3, 4, 5, 6, 7, 8]).length, 6);
});

test('a router that answers "frag needed" hands back its MTU', async () => {
  const { exec } = fakePing(({ size }) =>
    (size > 1400 ? { stdout: fragNeededOutput(1400), err: new Error('exit 1') } : { stdout: okOutput() }));
  const res = await pingProbe({ host: 'h', count: 1, sizes: [64, 1472], df: true }, { exec, platform: 'linux' });
  assert.equal(res.mtuHint, 1400);
  assert.equal(res.sizes[1].mtuHint, 1400);
});

test('parseMtuHint reads the MTU out of an ICMP frag-needed and refuses nonsense', () => {
  assert.equal(parseMtuHint('Frag needed and DF set (mtu = 1400)'), 1400);
  assert.equal(parseMtuHint('mtu=1280'), 1280);
  assert.equal(parseMtuHint('no hint here'), null);
  assert.equal(parseMtuHint('mtu = 0'), null);
  assert.equal(parseMtuHint('mtu = 999999'), null);
});

test('a payload the local interface refuses is reported as unmeasured, not as loss', async () => {
  const { exec } = fakePing(({ size }) =>
    (size > 1472 ? { stderr: 'ping: local error: Message too long, mtu=1500', err: new Error('exit 1') } : { stdout: okOutput() }));
  const res = await pingProbe({ host: 'h', count: 1, sizes: [64, 9000], df: true }, { exec, platform: 'linux' });
  assert.equal(res.sizes[1].measured, false);
  assert.match(res.sizes[1].error, /local interface MTU/);
});

test('DF and payload size are spelled per platform, and so is the deadline', () => {
  assert.deepEqual(
    buildPingArgs({ platform: 'linux', count: 1, host: 'h', size: 1472, df: true, deadlineSec: 2 }),
    ['-c', '1', '-w', '2', '-s', '1472', '-M', 'do', '--', 'h']
  );
  assert.deepEqual(
    buildPingArgs({ platform: 'darwin', count: 1, host: 'h', size: 1472, df: true, deadlineSec: 2 }),
    ['-c', '1', '-t', '2', '-s', '1472', '-D', '--', 'h']
  );
  assert.deepEqual(
    buildPingArgs({ platform: 'win32', count: 1, host: 'h', size: 1472, df: true, deadlineSec: 2 }),
    ['-n', '1', '-w', '2000', '-l', '1472', '-f', 'h']
  );
});

test('a hostile host is rejected before it reaches argv', async () => {
  const { exec, calls } = fakePing(() => ({ stdout: okOutput() }));
  const res = await pingProbe({ host: '-f', sizes: [64, 1472] }, { exec, platform: 'linux' });
  assert.equal(res.ok, false);
  assert.equal(calls.length, 0);
});
