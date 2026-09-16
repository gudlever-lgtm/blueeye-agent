'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { pingProbe, buildPingArgs, parseMtuHint, normalizeSizes } = require('../src/probes/ping');
const { pathMtuProbe, mssFor, IPV4_OVERHEAD } = require('../src/probes/pathMtu');
const { runProbe } = require('../src/probes');

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

// --- path_mtu ----------------------------------------------------------------

test('path_mtu reports the full MTU when the biggest packet gets through', async () => {
  const { exec, calls } = fakePing(() => ({ stdout: okOutput() }));
  const res = await pathMtuProbe({ host: 'h' }, { exec, platform: 'linux' });
  assert.equal(res.ok, true);
  assert.equal(res.pathMtu, 1472 + IPV4_OVERHEAD); // 1500
  assert.equal(res.blackholeDetected, false);
  assert.equal(res.recommendedMss, 1460);
  assert.equal(calls.length, 2, 'floor + ceiling only — no bisection needed');
});

test('path_mtu bisects to the real limit and flags a silent drop as a blackhole', async () => {
  const { exec } = fakePing(blackholeAt(1372)); // a 1400-byte path
  const res = await pathMtuProbe({ host: 'h' }, { exec, platform: 'linux' });
  assert.equal(res.ok, true);
  assert.equal(res.pathMtu, 1400);
  assert.equal(res.blackholeDetected, true);
  assert.equal(res.mtuHint, null);
  assert.equal(res.recommendedMss, 1360);
  assert.match(res.detail, /without any ICMP reply/);
});

test('a path that ANSWERS with frag-needed is not a blackhole', async () => {
  const { exec } = fakePing(({ size }) =>
    (size <= 1372 ? { stdout: okOutput() } : { stdout: fragNeededOutput(1400), err: new Error('exit 1') }));
  const res = await pathMtuProbe({ host: 'h' }, { exec, platform: 'linux' });
  assert.equal(res.blackholeDetected, false);
  assert.equal(res.mtuHint, 1400);
  assert.equal(res.pathMtu, 1400);
  assert.match(res.detail, /a router reported mtu = 1400/);
});

test('path_mtu refuses to invent an MTU when the target never answers', async () => {
  const { exec } = fakePing(() => ({ stdout: lossOutput(), err: new Error('exit 1') }));
  const res = await pathMtuProbe({ host: 'h' }, { exec, platform: 'linux' });
  assert.equal(res.ok, false);
  assert.equal(res.pathMtu, null);
  assert.match(res.error, /the path is down, or it filters ICMP echo/);
});

test('every path_mtu answer carries the packets that produced it', async () => {
  const { exec } = fakePing(blackholeAt(1372));
  const res = await pathMtuProbe({ host: 'h' }, { exec, platform: 'linux' });
  assert.ok(res.probes.length >= 3);
  for (const p of res.probes) {
    assert.equal(typeof p.bytes, 'number');
    assert.equal(p.packetBytes, p.bytes + IPV4_OVERHEAD);
    assert.equal(typeof p.ok, 'boolean');
  }
  // The largest passing probe is what pathMtu was derived from.
  const largestOk = Math.max(...res.probes.filter((p) => p.ok).map((p) => p.bytes));
  assert.equal(res.pathMtu, largestOk + IPV4_OVERHEAD);
});

test('perHop names the first hop that stops carrying the packet', async () => {
  // 10.0.0.1 carries everything; 10.0.0.2 is the tunnel head and drops big ones.
  const { exec } = fakePing(({ size, host }) => {
    if (host === '10.0.0.2' && size > 100) return { stdout: lossOutput(), err: new Error('exit 1') };
    if (host === 'h') return blackholeAt(1372)({ size });
    return { stdout: okOutput() };
  });
  const trace = async () => ({
    type: 'traceroute', target: 'h', ok: true,
    hops: [{ hop: 1, ip: '10.0.0.1' }, { hop: 2, ip: '10.0.0.2' }, { hop: 3, ip: '10.0.0.3' }],
  });
  const res = await pathMtuProbe({ host: 'h', perHop: true }, { exec, platform: 'linux', trace });
  assert.equal(res.mtuDropAtHop, 2);
  assert.equal(res.hops.length, 3);
  assert.equal(res.hops[1].respondsSmall, true);
  assert.equal(res.hops[1].okAtLarge, false);
});

test('a hop that ignores ICMP echo entirely is never blamed for the drop', async () => {
  const { exec } = fakePing(({ host, size }) => {
    if (host === '10.0.0.1') return { stdout: lossOutput(), err: new Error('exit 1') }; // silent router
    if (host === 'h') return blackholeAt(1372)({ size });
    return { stdout: okOutput() };
  });
  const trace = async () => ({ hops: [{ hop: 1, ip: '10.0.0.1' }, { hop: 2, ip: '10.0.0.2' }] });
  const res = await pathMtuProbe({ host: 'h', perHop: true }, { exec, platform: 'linux', trace });
  assert.equal(res.hops[0].respondsSmall, false);
  assert.equal(res.hops[0].okAtLarge, null, 'not asked, so nothing is claimed');
  assert.equal(res.mtuDropAtHop, null);
});

test('perHop survives a traceroute that is missing or throws', async () => {
  const { exec } = fakePing(blackholeAt(1372));
  const trace = async () => { throw new Error('traceroute not installed'); };
  const res = await pathMtuProbe({ host: 'h', perHop: true }, { exec, platform: 'linux', trace });
  assert.equal(res.ok, true);
  assert.equal(res.pathMtu, 1400);
  assert.equal(res.mtuDropAtHop, null);
  assert.deepEqual(res.hops, []);
});

test('an IPv6 literal uses the IPv6 header overhead', async () => {
  const { exec } = fakePing(() => ({ stdout: okOutput() }));
  const res = await pathMtuProbe({ host: '2001:db8::1', high: 1452 }, { exec, platform: 'linux' });
  assert.equal(res.overheadBytes, 48);
  assert.equal(res.pathMtu, 1500);
  assert.equal(res.recommendedMss, 1440);
});

test('mssFor leaves room for the IP and TCP headers, and refuses a negative MSS', () => {
  assert.equal(mssFor(1500, 28), 1460);
  assert.equal(mssFor(1400, 28), 1360);
  assert.equal(mssFor(1500, 48), 1440);
  assert.equal(mssFor(20, 28), null);
});

test('path_mtu rejects a hostile host before it reaches argv', async () => {
  const { exec, calls } = fakePing(() => ({ stdout: okOutput() }));
  const res = await pathMtuProbe({ host: '-rf /' }, { exec, platform: 'linux' });
  assert.equal(res.ok, false);
  assert.equal(res.error, 'invalid host');
  assert.equal(calls.length, 0);
});

test('path_mtu is reachable through the probe registry', async () => {
  const { exec } = fakePing(blackholeAt(1372));
  const res = await runProbe({ type: 'path_mtu', host: 'h' }, { path_mtu: { exec, platform: 'linux' } });
  assert.equal(res.type, 'path_mtu');
  assert.equal(res.pathMtu, 1400);
  assert.ok(res.ts, 'the registry stamps every result');
});
