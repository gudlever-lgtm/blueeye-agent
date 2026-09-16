'use strict';

// Path-MTU probe. Every case runs against a simulated network — a table of hops
// with per-link MTUs and a switch for whether the routers are allowed to send
// ICMP frag-needed — so the three verdicts the probe exists to separate
// (reduced / blackhole / no_response) are produced by the SAME code path a real
// path would drive, not by hand-fed strings.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const {
  pathMtuProbe, parsePingProbe, pingArgs, parseSsMss, OUTCOME, HOP_STATUS,
} = require('../src/probes/pathmtu');
const { runProbe, PROBE_TYPES } = require('../src/probes');

const FIX = path.join(__dirname, 'fixtures', 'pathmtu');
const fixture = (name) => fs.readFileSync(path.join(FIX, `${name}.txt`), 'utf8');

// --------------------------------------------------------------- simulator
//
// `hops` is the path: [{ hop, ip, mtu }], where `mtu` is the largest packet that
// link will carry. The MTU available at TTL n is the smallest mtu among hops
// 1..n, which is what makes the probe's per-hop ceiling assumption testable
// rather than assumed.
function simulate({
  hops,
  fragNeeded = true,
  platform = 'linux',
  silentHops = [],
  dropFirst = 0,
  localMtu = null,
}) {
  const calls = [];
  const attempts = new Map();

  // Recovers (size, ttl) from the argv the probe built, per platform. Doing it
  // from argv rather than from a side channel means a wrong flag shows up as a
  // wrong measurement, which is the point of the platform tests below.
  function decode(args) {
    const val = (flag) => {
      const i = args.indexOf(flag);
      return i >= 0 && args[i + 1] !== undefined ? Number(args[i + 1]) : null;
    };
    if (platform === 'win32') return { size: val('-l') + 28, ttl: val('-i') };
    if (platform === 'darwin') return { size: val('-s') + 28, ttl: val('-m') };
    return { size: val('-s') + 28, ttl: val('-t') };
  }

  // The smallest link MTU up to and including `ttl` hops (all of them when the
  // packet is not TTL-limited).
  function mtuUpTo(ttl) {
    const reached = ttl == null ? hops : hops.filter((h) => h.hop <= ttl);
    return reached.reduce((m, h) => Math.min(m, h.mtu), Infinity);
  }

  function limitingHop(size) {
    return hops.find((h) => h.mtu < size) || null;
  }

  const out = (name) => fixture(`${platform === 'win32' ? 'win' : platform === 'darwin' ? 'darwin' : 'linux'}-${name}`);

  function exec(bin, args, opts, cb) {
    calls.push({ bin, args });
    if (bin === 'ss') return cb(null, fixture('ss-tin'), '');
    const { size, ttl } = decode(args);

    // Ordinary, size-INDEPENDENT packet loss: the first N attempts at any
    // (size, ttl) are lost. `probes_per_size` is what has to see through this.
    const k = `${size}|${ttl}`;
    const n = (attempts.get(k) || 0) + 1;
    attempts.set(k, n);
    if (n <= dropFirst) return cb(new Error('timeout'), out('timeout'), '');

    // This host's own interface cannot even emit the packet.
    if (localMtu && size > localMtu) return cb(new Error('local'), out('local-error'), '');

    // A hop that answers nothing at all: not an MTU limit, not a fault.
    if (ttl != null && silentHops.includes(ttl)) return cb(new Error('timeout'), out('timeout'), '');

    if (size <= mtuUpTo(ttl)) {
      const last = hops[hops.length - 1];
      const isTarget = ttl == null || ttl >= last.hop;
      return cb(isTarget ? null : new Error('ttl'), out(isTarget ? 'reply' : 'ttl-exceeded'), '');
    }
    const lim = limitingHop(size);
    if (!fragNeeded || !lim) return cb(new Error('timeout'), out('timeout'), '');
    // A real router reports ITS next-hop MTU; the fixture carries 1420, so a
    // path whose limit is elsewhere must not be believed on that number alone.
    const text = out('frag-needed').replace(/mtu\s*[=]?\s*1420/i, (m) => m.replace('1420', String(lim.mtu)))
      .replace(/MTU 1420/, `MTU ${lim.mtu}`);
    return cb(new Error('frag'), text, '');
  }

  const tracerouteFn = async () => ({ hops: hops.map((h) => ({ hop: h.hop, ip: h.ip })) });
  return { exec, tracerouteFn, calls, platform };
}

const CLEAN = [
  { hop: 1, ip: '192.0.2.1', mtu: 1500 },
  { hop: 2, ip: '192.0.2.2', mtu: 1500 },
  { hop: 3, ip: '203.0.113.5', mtu: 1500 },
];
const NARROWED = [
  { hop: 1, ip: '192.0.2.1', mtu: 1500 },
  { hop: 2, ip: '192.0.2.2', mtu: 1500 },
  { hop: 3, ip: '198.51.100.7', mtu: 1420 },
  { hop: 4, ip: '203.0.113.5', mtu: 1420 },
];

const run = (spec, sim) => pathMtuProbe(spec, {
  exec: sim.exec, platform: sim.platform, tracerouteFn: sim.tracerouteFn, now: () => Date.now(),
});

// ------------------------------------------------------------ binary search
test('binary search finds the exact MTU at 576, 1420, 1500 and 9000', async () => {
  for (const mtu of [576, 1420, 1500, 9000]) {
    const sim = simulate({ hops: [{ hop: 1, ip: '192.0.2.1', mtu }] });
    // fragNeeded is on, but a router's volunteered MTU is only believed inside
    // the search window — so this exercises the search, not the shortcut.
    const r = await run({ host: '10.20.30.40', per_hop: false, max_size: 9216, min_size: 576 }, sim);
    assert.equal(r.path_mtu, mtu, `expected ${mtu}, got ${r.path_mtu}`);
    assert.equal(r.recommended_mss, mtu - 40);
  }
});

test('the search is bounded by max_size and never reports above it', async () => {
  const sim = simulate({ hops: [{ hop: 1, ip: '192.0.2.1', mtu: 9000 }] });
  const r = await run({ host: '10.20.30.40', per_hop: false, max_size: 1500 }, sim);
  assert.equal(r.path_mtu, 1500);
  assert.equal(r.blackhole_detected, false);
});

test('a router that volunteers its next-hop MTU short-circuits the search', async () => {
  const sim = simulate({ hops: [{ hop: 1, ip: '192.0.2.1', mtu: 1420 }] });
  const r = await run({ host: '10.20.30.40', per_hop: false }, sim);
  assert.equal(r.path_mtu, 1420);
  // control + top + (believed hint) — far fewer than a full bisection.
  assert.ok(sim.calls.length <= 4, `took ${sim.calls.length} pings`);
});

// ------------------------------------------------------------ classification
test('blocked ICMP on a narrowed path is a blackhole at the right hop', async () => {
  const sim = simulate({ hops: NARROWED, fragNeeded: false });
  const r = await run({ host: '10.20.30.40' }, sim);
  assert.equal(r.blackhole_detected, true);
  assert.equal(r.icmp_frag_needed_seen, false);
  assert.equal(r.path_mtu, 1420);
  assert.equal(r.mtu_drop_at_hop, 3);
  assert.equal(r.hops.find((h) => h.hop === 3).status, HOP_STATUS.BLACKHOLE);
  assert.equal(r.hops.find((h) => h.hop === 3).max_mtu, 1420);
});

test('the same path with ICMP allowed is `reduced`, and not a blackhole', async () => {
  const sim = simulate({ hops: NARROWED, fragNeeded: true });
  const r = await run({ host: '10.20.30.40' }, sim);
  assert.equal(r.blackhole_detected, false);
  assert.equal(r.icmp_frag_needed_seen, true);
  assert.equal(r.path_mtu, 1420);
  assert.equal(r.mtu_drop_at_hop, 3);
  assert.equal(r.hops.find((h) => h.hop === 3).status, HOP_STATUS.REDUCED);
});

test('a hop downstream of the drop inherits `reduced` — it is not re-diagnosed as a blackhole', async () => {
  const sim = simulate({ hops: NARROWED, fragNeeded: true });
  const r = await run({ host: '10.20.30.40' }, sim);
  const hop4 = r.hops.find((h) => h.hop === 4);
  assert.equal(hop4.status, HOP_STATUS.REDUCED, 'hop 4 adds no new restriction');
  assert.equal(hop4.max_mtu, 1420);
  assert.equal(r.mtu_drop_at_hop, 3, 'the drop is still attributed to hop 3 only');
});

test('a hop that answers no ICMP is `no_response` and does not affect the conclusion', async () => {
  const sim = simulate({ hops: CLEAN, silentHops: [2] });
  const r = await run({ host: '10.20.30.40' }, sim);
  const hop2 = r.hops.find((h) => h.hop === 2);
  assert.equal(hop2.status, HOP_STATUS.NO_RESPONSE);
  assert.equal(hop2.max_mtu, null);
  assert.equal(r.blackhole_detected, false);
  assert.equal(r.mtu_drop_at_hop, null);
  assert.equal(r.path_mtu, 1500);
  assert.equal(r.hops.find((h) => h.hop === 3).status, HOP_STATUS.OK);
});

test('ordinary size-independent loss is not an MTU limit', async () => {
  // Two of every three probes are lost, at every size. With probes_per_size=3
  // the true MTU still comes out; with 1 it would look like a blackhole.
  const sim = simulate({ hops: CLEAN, dropFirst: 2 });
  const r = await run({ host: '10.20.30.40', probes_per_size: 3 }, sim);
  assert.equal(r.path_mtu, 1500);
  assert.equal(r.blackhole_detected, false);
  assert.equal(r.mtu_drop_at_hop, null);
  assert.deepEqual([...new Set(r.hops.map((h) => h.status))], [HOP_STATUS.OK]);
});

test('a target that answers nothing at all is not reported as a blackhole', async () => {
  const sim = simulate({ hops: CLEAN, dropFirst: 99 });
  const r = await run({ host: '10.20.30.40', per_hop: false }, sim);
  assert.equal(r.path_mtu, null);
  assert.equal(r.blackhole_detected, false);
  assert.equal(r.recommended_mss, null);
});

test('a local interface MTU is not reported as a path fault', async () => {
  const sim = simulate({ hops: [{ hop: 1, ip: '192.0.2.1', mtu: 9000 }], localMtu: 1500 });
  const r = await run({ host: '10.20.30.40', max_size: 9216 }, sim);
  assert.equal(r.path_mtu, 1500);
  assert.equal(r.blackhole_detected, false, 'the host refused to send it; nothing was lost on the path');
  assert.equal(r.mtu_drop_at_hop, null, 'the local cap is not a drop on the path');
  assert.deepEqual([...new Set(r.hops.map((h) => h.status))], [HOP_STATUS.OK],
    'no hop is blamed for this host\'s own interface');
});

// ------------------------------------------------------------------ verdict
test('the probe reports ok:true even when it finds a blackhole', async () => {
  const sim = simulate({ hops: NARROWED, fragNeeded: false });
  const r = await run({ host: '10.20.30.40' }, sim);
  // A blackhole is a finding about the PATH. Reporting it as ok:false would make
  // the server's fleet-health verdict count this target as unreachable and take
  // the agent's status down with it.
  assert.equal(r.ok, true);
  assert.equal(r.blackhole_detected, true);
  assert.equal(r.type, 'path_mtu');
  assert.ok(r.duration_ms >= 0);
});

test('recommended_mss subtracts 40 on IPv4 and 60 on IPv6', async () => {
  const v4 = simulate({ hops: [{ hop: 1, ip: '192.0.2.1', mtu: 1420 }] });
  const a = await run({ host: '10.20.30.40', per_hop: false }, v4);
  assert.equal(a.recommended_mss, 1380);

  const v6 = simulate({ hops: [{ hop: 1, ip: '192.0.2.1', mtu: 1400 }] });
  const b = await run({ host: '2001:db8::1', per_hop: false, ip_version: 6, min_size: 1280 }, v6);
  assert.equal(b.ip_version, 6);
  assert.equal(b.recommended_mss, b.path_mtu - 60);
});

// ------------------------------------------------------------- OS parsing
test('parsePingProbe reads every outcome on Linux, macOS and Windows', () => {
  assert.equal(parsePingProbe(fixture('linux-reply')).outcome, OUTCOME.REPLY);
  assert.equal(parsePingProbe(fixture('linux-reply')).rttMs, 12.3);
  assert.equal(parsePingProbe(fixture('linux-frag-needed')).outcome, OUTCOME.FRAG_NEEDED);
  assert.equal(parsePingProbe(fixture('linux-frag-needed')).mtu, 1420);
  assert.equal(parsePingProbe(fixture('linux-frag-needed')).from, '198.51.100.7');
  assert.equal(parsePingProbe(fixture('linux-ttl-exceeded')).outcome, OUTCOME.TTL_EXCEEDED);
  assert.equal(parsePingProbe(fixture('linux-ttl-exceeded')).from, '192.0.2.1');
  assert.equal(parsePingProbe(fixture('linux-timeout')).outcome, OUTCOME.TIMEOUT);
  assert.equal(parsePingProbe(fixture('linux-local-error')).outcome, OUTCOME.LOCAL_ERROR);
  assert.equal(parsePingProbe(fixture('linux-local-error')).mtu, 1500);

  // macOS writes frag-needed and TTL-exceeded as "36 bytes from …", which also
  // matches the success pattern — these two cases are why the parser's test
  // order is load-bearing.
  assert.equal(parsePingProbe(fixture('darwin-reply')).outcome, OUTCOME.REPLY);
  assert.equal(parsePingProbe(fixture('darwin-reply')).rttMs, 12.35);
  assert.equal(parsePingProbe(fixture('darwin-frag-needed')).outcome, OUTCOME.FRAG_NEEDED);
  assert.equal(parsePingProbe(fixture('darwin-frag-needed')).mtu, 1420);
  assert.equal(parsePingProbe(fixture('darwin-ttl-exceeded')).outcome, OUTCOME.TTL_EXCEEDED);
  assert.equal(parsePingProbe(fixture('darwin-timeout')).outcome, OUTCOME.TIMEOUT);
  assert.equal(parsePingProbe(fixture('darwin-local-error')).outcome, OUTCOME.LOCAL_ERROR);

  // Windows writes its TTL-exceeded as "Reply from …" — the same prefix a
  // success uses.
  assert.equal(parsePingProbe(fixture('win-reply')).outcome, OUTCOME.REPLY);
  assert.equal(parsePingProbe(fixture('win-reply')).rttMs, 12);
  assert.equal(parsePingProbe(fixture('win-frag-needed')).outcome, OUTCOME.FRAG_NEEDED);
  assert.equal(parsePingProbe(fixture('win-frag-needed')).mtu, null, 'Windows never reports the MTU');
  assert.equal(parsePingProbe(fixture('win-ttl-exceeded')).outcome, OUTCOME.TTL_EXCEEDED);
  assert.equal(parsePingProbe(fixture('win-ttl-exceeded')).from, '192.0.2.1');
  assert.equal(parsePingProbe(fixture('win-timeout')).outcome, OUTCOME.TIMEOUT);
});

test('parsePingProbe never throws on garbage', () => {
  for (const g of [undefined, null, '', 'nonsense', 0, {}, []]) {
    assert.equal(typeof parsePingProbe(g).outcome, 'string');
  }
});

test('a blackhole is detected identically on all three platforms', async () => {
  for (const platform of ['linux', 'darwin', 'win32']) {
    const sim = simulate({ hops: NARROWED, fragNeeded: false, platform });
    const r = await run({ host: '10.20.30.40' }, sim);
    assert.equal(r.blackhole_detected, true, platform);
    assert.equal(r.path_mtu, 1420, platform);
    assert.equal(r.mtu_drop_at_hop, 3, platform);
  }
});

test('Windows sees a reduced path even though its ping never names the MTU', async () => {
  const sim = simulate({ hops: NARROWED, fragNeeded: true, platform: 'win32' });
  const r = await run({ host: '10.20.30.40' }, sim);
  assert.equal(r.icmp_frag_needed_seen, true);
  assert.equal(r.blackhole_detected, false);
  assert.equal(r.path_mtu, 1420, 'found by search, since the hint is unavailable');
});

// ------------------------------------------------------------- platform argv
test('pingArgs sets DF, size, count, timeout and TTL with each OS spelling', () => {
  const base = { ipVersion: 4, payload: 1472, timeoutMs: 1000, ttl: 5, host: 'h' };
  const linux = pingArgs({ ...base, platform: 'linux' });
  assert.deepEqual(linux, ['-4', '-M', 'do', '-s', '1472', '-c', '1', '-W', '1', '-t', '5', '--', 'h']);

  // macOS `-t` is the whole-run TIMEOUT and `-m` is the TTL — the opposite of
  // Linux, where `-t` is the TTL. Copying the Linux line here would silently
  // measure a different thing.
  const mac = pingArgs({ ...base, platform: 'darwin' });
  assert.deepEqual(mac, ['-D', '-s', '1472', '-c', '1', '-t', '1', '-m', '5', '--', 'h']);

  const win = pingArgs({ ...base, platform: 'win32' });
  assert.deepEqual(win, ['-4', '-f', '-l', '1472', '-n', '1', '-w', '1000', '-i', '5', 'h']);

  assert.ok(pingArgs({ ...base, platform: 'linux', ipVersion: 6 }).includes('-6'));
  assert.ok(!pingArgs({ ...base, platform: 'linux', ttl: null }).includes('-t'));
});

test('IPv6 path MTU is refused on macOS rather than measured with unverified flags', async () => {
  const sim = simulate({ hops: CLEAN, platform: 'darwin' });
  const r = await run({ host: '2001:db8::1', ip_version: 6 }, sim);
  assert.equal(r.ok, false);
  assert.match(r.error, /IPv6.*macOS/i);
  assert.equal(sim.calls.length, 0, 'nothing was executed');
});

test('IPv6 measures end-to-end and reports no hops (the trace parser reads IPv4 only)', async () => {
  const sim = simulate({ hops: [{ hop: 1, ip: '192.0.2.1', mtu: 1400 }] });
  const r = await run({ host: '2001:db8::1', ip_version: 6, per_hop: true }, sim);
  assert.deepEqual(r.hops, []);
  assert.equal(r.path_mtu, 1400);
  assert.ok(sim.calls.every((c) => c.args.includes('-6')));
});

// ------------------------------------------------------------- input safety
test('hostile, empty and malformed targets are refused without executing anything', async () => {
  const hostile = [
    '', '   ', '-f', '--flood', ';rm -rf /', '1.1.1.1; ls', '$(whoami)', '`id`', 'a b',
    'host|nc', 'host&&id', "host'", 'host"', 'x'.repeat(256), null, undefined, {}, [],
  ];
  for (const h of hostile) {
    const sim = simulate({ hops: CLEAN });
    const r = await run({ host: h }, sim);
    assert.equal(r.ok, false, `accepted ${JSON.stringify(h)}`);
    assert.equal(r.error, 'invalid host', `wrong reason for ${JSON.stringify(h)}`);
    assert.equal(sim.calls.length, 0, `executed something for ${JSON.stringify(h)}`);
  }
});

test('a bare number is passed through, as it is for every other probe', async () => {
  // `ping 42` is a legal, if odd, way to reach 0.0.0.42, and safeHost() — shared
  // with the ping and traceroute probes — accepts it. Rejecting it only here
  // would make this probe disagree with the rest of the agent for no gain.
  const sim = simulate({ hops: CLEAN });
  const r = await run({ host: 42, per_hop: false }, sim);
  assert.equal(r.ok, true);
  assert.equal(r.target, '42');
});

test('the target always lands after the end-of-options marker on Unix', async () => {
  const sim = simulate({ hops: CLEAN });
  await run({ host: '10.20.30.40', per_hop: false }, sim);
  for (const c of sim.calls) {
    const i = c.args.indexOf('--');
    assert.ok(i >= 0 && i === c.args.length - 2, `argv not terminated: ${c.args.join(' ')}`);
  }
});

test('sizes are clamped: max_size above the jumbo ceiling, min_size above max_size, garbage', async () => {
  const sim = simulate({ hops: [{ hop: 1, ip: '192.0.2.1', mtu: 100000 }] });
  const r = await run({ host: '10.20.30.40', per_hop: false, max_size: 99999, min_size: 'x' }, sim);
  assert.equal(r.path_mtu, 9216, 'clamped to the jumbo ceiling');

  const sim2 = simulate({ hops: CLEAN });
  const r2 = await run({ host: '10.20.30.40', per_hop: false, min_size: 9000, max_size: 1500 }, sim2);
  assert.ok(r2.path_mtu <= 1500, 'min_size can never exceed max_size');

  const sim3 = simulate({ hops: CLEAN });
  const r3 = await run({ host: '10.20.30.40', per_hop: false, probes_per_size: -5, timeout_ms: 'nope' }, sim3);
  assert.equal(r3.ok, true);
  assert.equal(r3.path_mtu, 1500);
});

test('a missing ping binary is reported as such, not as a blackhole', async () => {
  const enoent = (bin, args, opts, cb) => {
    const err = new Error('spawn ping ENOENT');
    err.code = 'ENOENT';
    cb(err, '', '');
  };
  const r = await pathMtuProbe({ host: '10.20.30.40', per_hop: false }, {
    exec: enoent, platform: 'linux', tracerouteFn: async () => ({ hops: [] }),
  });
  assert.equal(r.ok, false);
  assert.equal(r.error, 'ping not installed');
  assert.equal(r.blackhole_detected, false);
});

test('hops past the time budget are reported as skipped, never silently dropped', async () => {
  const sim = simulate({ hops: NARROWED });
  let t = 0;
  const r = await pathMtuProbe({ host: '10.20.30.40', budget_ms: 5000 }, {
    exec: sim.exec,
    platform: 'linux',
    tracerouteFn: sim.tracerouteFn,
    now: () => { t += 3000; return t; },
  });
  assert.equal(r.hops.length, NARROWED.length, 'every hop is accounted for');
  assert.ok(r.hops.some((h) => h.status === HOP_STATUS.SKIPPED));
  assert.equal(r.path_mtu, 1420, 'the end-to-end answer survives a truncated run');
});

// -------------------------------------------------------------------- MSS
test('parseSsMss picks the socket by its own local port', () => {
  const ss = fixture('ss-tin');
  assert.equal(parseSsMss(ss, 44312), 1380);
  assert.equal(parseSsMss(ss, 44100), 1460);
  assert.equal(parseSsMss(ss, 9999), null);
  assert.equal(parseSsMss('', 44312), null);
  assert.equal(parseSsMss(null, 44312), null);
});

test('the MSS check reads the negotiated MSS on Linux', async () => {
  const sim = simulate({ hops: NARROWED, fragNeeded: false });
  const sockets = [];
  const connectImpl = ({ host, port }, onConnect) => {
    const s = {
      localPort: 44312,
      setTimeout() {},
      on() {},
      destroy() { s.destroyed = true; },
      host,
      port,
    };
    sockets.push(s);
    setImmediate(onConnect);
    return s;
  };
  const r = await pathMtuProbe({ host: '10.20.30.40', tcp_port: 25 }, {
    exec: sim.exec, platform: 'linux', tracerouteFn: sim.tracerouteFn, connectImpl,
  });
  assert.equal(r.mss_supported, true);
  assert.equal(r.mss_observed, 1380);
  assert.equal(r.recommended_mss, 1380);
  assert.equal(sockets[0].destroyed, true, 'the probe socket is closed again');
  assert.equal(sockets[0].port, 25);
});

test('an MSS above the measured path is visible as the clamping gap', async () => {
  // The fixture's second socket negotiated 1460 while the path carries 1420.
  const sim = simulate({ hops: NARROWED, fragNeeded: false });
  const connectImpl = (_o, onConnect) => {
    const s = { localPort: 44100, setTimeout() {}, on() {}, destroy() {} };
    setImmediate(onConnect);
    return s;
  };
  const r = await pathMtuProbe({ host: '10.20.30.40', tcp_port: 443 }, {
    exec: sim.exec, platform: 'linux', tracerouteFn: sim.tracerouteFn, connectImpl,
  });
  assert.equal(r.mss_observed, 1460);
  assert.equal(r.recommended_mss, 1380);
  assert.ok(r.mss_observed > r.recommended_mss, 'this is what "MSS clamping is missing" looks like');
});

test('the MSS check is unsupported off Linux and skipped without a port', async () => {
  for (const platform of ['darwin', 'win32']) {
    const sim = simulate({ hops: CLEAN, platform });
    const r = await pathMtuProbe({ host: '10.20.30.40', per_hop: false, tcp_port: 25 }, {
      exec: sim.exec, platform, tracerouteFn: sim.tracerouteFn,
    });
    assert.equal(r.mss_supported, false, platform);
    assert.equal(r.mss_observed, null, platform);
  }
  const sim = simulate({ hops: CLEAN });
  const none = await run({ host: '10.20.30.40', per_hop: false }, sim);
  assert.equal(none.mss_observed, null);
  assert.ok(sim.calls.every((c) => c.bin !== 'ss'));
});

test('a refused TCP connection does not fail the probe', async () => {
  const sim = simulate({ hops: CLEAN });
  const connectImpl = (_o, _onConnect) => {
    const s = {
      localPort: null,
      setTimeout() {},
      on(ev, fn) { if (ev === 'error') setImmediate(() => fn(new Error('ECONNREFUSED'))); },
      destroy() {},
    };
    return s;
  };
  const r = await pathMtuProbe({ host: '10.20.30.40', per_hop: false, tcp_port: 25 }, {
    exec: sim.exec, platform: 'linux', tracerouteFn: sim.tracerouteFn, connectImpl,
  });
  assert.equal(r.ok, true);
  assert.equal(r.mss_supported, true);
  assert.equal(r.mss_observed, null);
  assert.equal(r.path_mtu, 1500);
});

// ------------------------------------------------------------- registration
test('path_mtu is registered and reachable through runProbe', async () => {
  assert.ok(PROBE_TYPES.includes('path_mtu'));
  const r = await runProbe({ type: 'path_mtu', host: '' });
  assert.equal(r.type, 'path_mtu');
  assert.equal(r.ok, false);
  assert.ok(r.ts, 'runProbe stamps ts');
});

test('the result carries every field of the documented schema', async () => {
  const sim = simulate({ hops: NARROWED, fragNeeded: false });
  const r = await run({ host: '10.20.30.40' }, sim);
  for (const k of ['test_type_placeholder']) void k;
  const expected = [
    'type', 'target', 'ok', 'ip_version', 'path_mtu', 'blackhole_detected',
    'icmp_frag_needed_seen', 'mtu_drop_at_hop', 'hops', 'mss_supported',
    'mss_observed', 'recommended_mss', 'duration_ms',
  ];
  for (const k of expected) assert.ok(k in r, `missing ${k}`);
  for (const h of r.hops) {
    assert.deepEqual(Object.keys(h).sort(), ['hop', 'ip', 'max_mtu', 'status']);
    assert.ok(Object.values(HOP_STATUS).includes(h.status));
  }
});
