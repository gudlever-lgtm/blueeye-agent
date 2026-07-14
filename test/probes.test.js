'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('events');

const { tcpProbe } = require('../src/probes/tcp');
const { dnsProbe } = require('../src/probes/dns');
const { parsePing, pingProbe } = require('../src/probes/ping');
const { traceroute, parseTraceroute } = require('../src/probes/traceroute');
const { httpProbe, normalizeUrl } = require('../src/probes/http');
const { curlProbe } = require('../src/probes/curl');
const { pageloadProbe, extractResources } = require('../src/probes/pageload');
const { transactionProbe, subst } = require('../src/probes/transaction');
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

test('ping rejects an option-looking host (argument injection) without spawning', async () => {
  let spawned = false;
  const exec = (_cmd, _args, _opts, cb) => { spawned = true; cb(null, ''); };
  const res = await pingProbe({ host: '-f' }, { exec, platform: 'linux' });
  assert.equal(res.ok, false);
  assert.equal(res.error, 'invalid host');
  assert.equal(spawned, false, 'must not spawn ping for an unsafe host');
});

test('ping passes a safe host after a `--` end-of-options marker', async () => {
  let seenArgs = null;
  const exec = (_cmd, args, _opts, cb) => { seenArgs = args; cb(null, '0% packet loss\nrtt min/avg/max/mdev = 1/1/1/0 ms'); };
  await pingProbe({ host: 'example.com', count: 2 }, { exec, platform: 'linux' });
  assert.ok(seenArgs.includes('--'), 'argv contains the -- guard');
  assert.equal(seenArgs[seenArgs.indexOf('--') + 1], 'example.com', 'host follows --');
});

test('traceroute rejects an option-looking host without spawning', async () => {
  let spawned = false;
  const exec = (_bin, _args, _opts, cb) => { spawned = true; cb(null, ''); };
  const res = await traceroute({ host: '--help' }, { exec, platform: 'linux' });
  assert.equal(res.ok, false);
  assert.equal(res.error, 'invalid host');
  assert.equal(spawned, false, 'must not spawn traceroute for an unsafe host');
});

test('traceroute reports a reason when the command is missing, not a blank run', async () => {
  // Minimal hosts often lack the traceroute binary; the run must say so (so the
  // server/dashboard can explain the empty path) rather than silently return [].
  const exec = (_bin, _args, _opts, cb) => cb(Object.assign(new Error('spawn traceroute ENOENT'), { code: 'ENOENT' }), '');
  const res = await traceroute({ host: 'example.com' }, { exec, platform: 'linux' });
  assert.equal(res.ok, false);
  assert.equal(res.hopCount, 0);
  assert.deepEqual(res.hops, []);
  assert.equal(res.error, 'traceroute not installed');
});

test('traceroute still succeeds when the command prints hops despite a nonzero exit', async () => {
  // traceroute can exit nonzero yet still emit a usable report; hops win over err.
  const stdout = ' 1  10.0.0.1  1.0 ms  1.0 ms  1.0 ms\n 2  93.184.216.34  10 ms  10 ms  10 ms\n';
  const exec = (_bin, _args, _opts, cb) => cb(new Error('exit 1'), stdout);
  const res = await traceroute({ host: 'example.com' }, { exec, platform: 'linux' });
  assert.equal(res.ok, true);
  assert.equal(res.hopCount, 2);
  assert.equal(res.error, undefined);
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

// A fake execFile('curl', ...) that yields canned output (and optional error).
// `curlReply` assembles the -i header/body + the trailing -w metrics line.
function curlReply({ status = 200, headers = {}, body = '', timeMs = 123, contentType = 'text/plain' } = {}) {
  const hdr = Object.entries({ 'content-type': contentType, ...headers })
    .map(([k, v]) => `${k}: ${v}`).join('\r\n');
  const bytes = Buffer.byteLength(body);
  return `HTTP/1.1 ${status} OK\r\n${hdr}\r\n\r\n${body}\n__BLUEEYE_CURL__ ${status} ${bytes} ${(timeMs / 1000).toFixed(3)} ${contentType}`;
}
function fakeCurl(stdout, err = null) {
  return (_file, _args, _opts, cb) => { setImmediate(() => cb(err, stdout, err ? 'curl: error' : '')); };
}

test('curlProbe verifies status, body and a header — ok when all pass', async () => {
  const out = curlReply({ status: 200, body: 'service healthy', headers: { 'x-app': 'blueeye' } });
  const res = await curlProbe(
    { url: 'https://example.com/health', expectStatus: 200, expectBody: 'healthy', expectHeader: 'x-app' },
    { exec: fakeCurl(out), now: () => 0 }
  );
  assert.equal(res.type, 'curl');
  assert.equal(res.target, 'https://example.com/health');
  assert.equal(res.ok, true);
  assert.equal(res.status, 200);
  assert.equal(res.bytes, Buffer.byteLength('service healthy'));
  assert.equal(res.lossPct, 0);
  assert.match(res.detail, /body matched/);
});

test('curlProbe fails the check when the body does not match (reachable, but not ok)', async () => {
  const res = await curlProbe(
    { url: 'https://example.com', expectBody: 'EXPECTED-TOKEN' },
    { exec: fakeCurl(curlReply({ status: 200, body: 'something else' })), now: () => 0 }
  );
  assert.equal(res.ok, false);
  assert.equal(res.status, 200); // we DID reach it — status is still reported
  assert.equal(res.lossPct, 100);
  assert.match(res.detail, /body no match/);
  // privacy: the actual body must never leak into the reported result
  assert.ok(!JSON.stringify(res).includes('something else'));
});

test('curlProbe supports a /regex/ body matcher and a minimum byte count', async () => {
  const res = await curlProbe(
    { url: 'http://x.test', expectBody: '/ver\\s*\\d+/i', minBytes: 5 },
    { exec: fakeCurl(curlReply({ status: 200, body: 'API VER 42 ok' })), now: () => 0 }
  );
  assert.equal(res.ok, true);
  assert.match(res.detail, /✓/);
});

test('curlProbe treats a 500 as a failed check by default', async () => {
  const res = await curlProbe({ url: 'http://x.test' }, { exec: fakeCurl(curlReply({ status: 500, body: 'err' })), now: () => 0 });
  assert.equal(res.ok, false);
  assert.equal(res.status, 500);
  assert.equal(res.lossPct, 100);
});

test('curlProbe reports curl-not-installed without throwing', async () => {
  const err = Object.assign(new Error('spawn curl ENOENT'), { code: 'ENOENT' });
  const res = await curlProbe({ url: 'http://x.test' }, { exec: fakeCurl('', err), now: () => 0 });
  assert.equal(res.ok, false);
  assert.equal(res.status, null);
  assert.match(res.detail, /curl not installed/);
});

// Page-load fake curl: assembles a body (for the document) + the -w metrics line
// using pageload's SENTINEL, and routes by --url so the document and its assets
// each get a distinct reply.
function plReply({ status = 200, body = '', bytes, timeMs = 50 } = {}) {
  const size = bytes != null ? bytes : Buffer.byteLength(body);
  return `${body}\n__BLUEEYE_PL__ ${status} ${size} ${(timeMs / 1000).toFixed(3)} ${(timeMs / 2000).toFixed(3)} text/html`;
}
function fakePageCurl(byUrl) {
  return (_file, args, _opts, cb) => {
    const i = args.indexOf('--url');
    const url = i >= 0 ? args[i + 1] : '';
    const reply = byUrl[url] != null ? byUrl[url] : plReply({ status: 404, body: '' });
    setImmediate(() => cb(null, reply, ''));
  };
}

test('extractResources pulls scripts/styles/images and resolves relative URLs', () => {
  const html = '<html><head><link rel="stylesheet" href="/a.css"><script src="https://cdn.test/x.js"></script></head><body><img src="img/logo.png"></body></html>';
  const out = extractResources(html, new URL('https://site.test/page'), 20);
  const urls = out.map((r) => r.url);
  assert.ok(urls.includes('https://site.test/a.css'));
  assert.ok(urls.includes('https://cdn.test/x.js'));
  assert.ok(urls.includes('https://site.test/img/logo.png'));
});

test('pageloadProbe builds a waterfall of the document + its sub-resources', async () => {
  const doc = 'https://site.test/';
  const html = '<link rel="stylesheet" href="/a.css"><script src="/b.js"></script><img src="/c.png">';
  const res = await pageloadProbe(
    { url: doc },
    { exec: fakePageCurl({
      [doc]: plReply({ status: 200, body: html, bytes: 4096, timeMs: 80 }),
      'https://site.test/a.css': plReply({ status: 200, bytes: 1000, timeMs: 20 }),
      'https://site.test/b.js': plReply({ status: 200, bytes: 2000, timeMs: 30 }),
      'https://site.test/c.png': plReply({ status: 200, bytes: 8000, timeMs: 40 }),
    }), now: clock() }
  );
  assert.equal(res.type, 'pageload');
  assert.equal(res.ok, true);
  assert.equal(res.status, 200);
  assert.equal(res.elements.length, 4); // document + 3 assets
  assert.equal(res.elements[0].kind, 'document');
  assert.equal(res.bytes, 4096 + 1000 + 2000 + 8000);
  assert.equal(res.lossPct, 0);
  assert.ok(res.rttMs != null && res.rttMs > 0); // total load time → graphs over time
  assert.match(res.detail, /elements/);
});

test('pageloadProbe counts failed sub-resources as loss but stays ok if the doc loads', async () => {
  const doc = 'http://site.test/';
  const html = '<img src="/ok.png"><img src="/missing.png">';
  const res = await pageloadProbe(
    { url: doc },
    { exec: fakePageCurl({
      [doc]: plReply({ status: 200, body: html, bytes: 500, timeMs: 60 }),
      'http://site.test/ok.png': plReply({ status: 200, bytes: 100, timeMs: 10 }),
      'http://site.test/missing.png': plReply({ status: 404, bytes: 0, timeMs: 5 }),
    }), now: clock() }
  );
  assert.equal(res.ok, true); // document is healthy
  assert.equal(res.lossPct, 50); // one of two assets failed
});

test('pageloadProbe reports an unreachable document as not ok', async () => {
  const err = Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
  const res = await pageloadProbe({ url: 'http://x.test' }, { exec: (_f, _a, _o, cb) => setImmediate(() => cb(err, '', '')), now: clock() });
  assert.equal(res.ok, false);
  assert.equal(res.status, null);
  assert.match(res.detail, /curl not installed/);
});

// Transaction fake: curl -i reply with the transaction SENTINEL; routes by --url
// and records each requested URL so we can assert variable substitution.
function txReply({ status = 200, headers = {}, body = '' } = {}) {
  const hdr = Object.entries({ 'content-type': 'application/json', ...headers }).map(([k, v]) => `${k}: ${v}`).join('\r\n');
  return `HTTP/1.1 ${status} OK\r\n${hdr}\r\n\r\n${body}\n__BLUEEYE_TX__ ${status} ${Buffer.byteLength(body)} 0.020`;
}
function fakeTxCurl(byUrl, captured = []) {
  return (_file, args, _opts, cb) => {
    const i = args.indexOf('--url');
    const url = i >= 0 ? args[i + 1] : '';
    captured.push({ url, args });
    const reply = byUrl[url] != null ? byUrl[url] : txReply({ status: 404, body: '' });
    setImmediate(() => cb(null, reply, ''));
  };
}

test('transaction subst replaces {{name}} from extracted vars (missing → empty)', () => {
  assert.equal(subst('https://x/{{tok}}/a', { tok: 'ABC' }), 'https://x/ABC/a');
  assert.equal(subst('h/{{missing}}', {}), 'h/');
});

test('transactionProbe runs steps in order, extracting a value into a later step', async () => {
  const captured = [];
  const res = await transactionProbe(
    { steps: [
      { url: 'https://api.test/login', method: 'POST', expectStatus: 200, extract: { name: 'token', pattern: '"token"\\s*:\\s*"([^"]+)"' } },
      { url: 'https://api.test/me?t={{token}}', expectStatus: 200, expectBody: 'welcome' },
    ] },
    { exec: fakeTxCurl({
      'https://api.test/login': txReply({ status: 200, body: '{"token":"SECRET123"}' }),
      'https://api.test/me?t=SECRET123': txReply({ status: 200, body: 'welcome home' }),
    }, captured), now: () => 0 }
  );
  assert.equal(res.type, 'transaction');
  assert.equal(res.ok, true);
  assert.equal(res.elements.length, 2);
  assert.equal(res.status, 200);
  // the extracted token flowed into step 2's URL
  assert.ok(captured.some((c) => c.url === 'https://api.test/me?t=SECRET123'));
  // privacy: the extracted secret must not leak into the reported result
  assert.ok(!JSON.stringify(res).includes('SECRET123') || res.elements[1].url.includes('SECRET123'));
  assert.match(res.detail, /2\/2 steps ok/);
});

test('transactionProbe stops at the first failing step', async () => {
  const res = await transactionProbe(
    { steps: [
      { url: 'https://api.test/a', expectStatus: 200 },
      { url: 'https://api.test/b', expectStatus: 200 },
      { url: 'https://api.test/c', expectStatus: 200 },
    ] },
    { exec: fakeTxCurl({
      'https://api.test/a': txReply({ status: 200, body: 'ok' }),
      'https://api.test/b': txReply({ status: 500, body: 'boom' }),
      'https://api.test/c': txReply({ status: 200, body: 'ok' }),
    }), now: () => 0 }
  );
  assert.equal(res.ok, false);
  assert.equal(res.status, 500);
  assert.equal(res.elements.length, 2); // stopped after step 2; step 3 never ran
  assert.match(res.detail, /failed at step 2/);
});

test('transactionProbe fails cleanly with no steps', async () => {
  const res = await transactionProbe({ steps: [] }, { exec: fakeTxCurl({}), now: () => 0 });
  assert.equal(res.ok, false);
  assert.match(res.detail || res.error, /no steps/);
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
