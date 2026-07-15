'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('events');
const os = require('os');
const fs = require('fs');
const path = require('path');

const { httpExecutor } = require('../src/transactions/executors/http');
const { tcpExecutor } = require('../src/transactions/executors/tcp');
const { dnsExecutor } = require('../src/transactions/executors/dns');
const { icmpExecutor } = require('../src/transactions/executors/icmp');
const { runTransaction } = require('../src/transactions/executors');
const { createResultBuffer } = require('../src/transactions/buffer');
const { createConfigStore } = require('../src/transactions/configStore');
const { createSecretStore } = require('../src/transactions/secretStore');
const { createTransactionManager } = require('../src/transactions/manager');
const { substitute } = require('../src/transactions/subst');
const { extract } = require('../src/transactions/extract');

// A fake Node http/https impl. `plan` is a function(urlString, opts) -> one of:
//   { status, body?, headers? } | { error: 'ECONNREFUSED' } | { timeout: true }
// Records every request into `calls` so substitution can be asserted.
function fakeHttp(plan) {
  const calls = [];
  const impl = {
    request(u, opts, cb) {
      const spec = plan(String(u), opts) || {};
      calls.push({ url: String(u), opts });
      const req = new EventEmitter();
      req.write = () => {};
      req.destroy = () => {};
      req.end = () => {
        setImmediate(() => {
          if (spec.timeout) { req.emit('timeout'); return; }
          if (spec.error) { const e = new Error('boom'); e.code = spec.error; req.emit('error', e); return; }
          const res = new EventEmitter();
          res.setEncoding = () => {};
          res.statusCode = spec.status;
          res.headers = spec.headers || {};
          cb(res);
          setImmediate(() => { if (spec.body != null) res.emit('data', spec.body); res.emit('end'); });
        });
      };
      return req;
    },
  };
  return { impl, calls };
}

const httpDeps = (plan, now) => { const f = fakeHttp(plan); return { deps: { httpImpl: f.impl, httpsImpl: f.impl, now: now || (() => 0) }, calls: f.calls }; };

// ---- http executor ----

test('http: multi-step ok, with secret substitution + variable extraction', async () => {
  let n = 0;
  const now = () => (n += 10); // each now() advances 10ms
  const { deps, calls } = httpDeps((url) => {
    if (url.includes('/login')) return { status: 200, body: '{"token":"abc123"}' };
    return { status: 200, body: 'ok welcome' };
  }, now);
  const test1 = {
    id: 1, type: 'http', config: { steps: [
      { method: 'POST', url: 'http://api/login', headers: { Authorization: 'Bearer {{secret:API_KEY}}' }, extract: { name: 'TOKEN', type: 'json', pattern: 'token' } },
      { method: 'GET', url: 'http://api/me?t={{TOKEN}}', expect_status: 200, expect_keyword: 'welcome' },
    ] },
    secrets: { API_KEY: 'super-secret' },
  };
  const r = await httpExecutor(test1, deps);
  assert.equal(r.status, 'ok');
  assert.equal(r.step_timings.length, 2);
  // secret was substituted into the header
  assert.equal(calls[0].opts.headers.Authorization, 'Bearer super-secret');
  // extracted TOKEN flowed into step 2's URL
  assert.ok(calls[1].url.includes('t=abc123'));
});

test('http: expect_status mismatch → fail with phase http_status', async () => {
  const { deps } = httpDeps(() => ({ status: 500, body: 'err' }));
  const r = await httpExecutor({ id: 1, type: 'http', config: { steps: [{ url: 'http://x/', expect_status: 200 }] } }, deps);
  assert.equal(r.status, 'fail');
  assert.equal(r.step_failed, 0);
  assert.equal(r.detail.phase, 'http_status');
});

test('http: expect_keyword missing → fail with phase keyword', async () => {
  const { deps } = httpDeps(() => ({ status: 200, body: 'nope' }));
  const r = await httpExecutor({ id: 1, type: 'http', config: { steps: [{ url: 'http://x/', expect_keyword: 'welcome' }] } }, deps);
  assert.equal(r.status, 'fail');
  assert.equal(r.detail.phase, 'keyword');
});

test('http: connection refused → fail with phase connect', async () => {
  const { deps } = httpDeps(() => ({ error: 'ECONNREFUSED' }));
  const r = await httpExecutor({ id: 1, type: 'http', config: { steps: [{ url: 'http://x/' }] } }, deps);
  assert.equal(r.status, 'fail');
  assert.equal(r.detail.phase, 'connect');
  assert.equal(r.detail.errno, 'ECONNREFUSED');
});

test('http: DNS failure → fail with phase dns', async () => {
  const { deps } = httpDeps(() => ({ error: 'ENOTFOUND' }));
  const r = await httpExecutor({ id: 1, type: 'http', config: { steps: [{ url: 'http://x/' }] } }, deps);
  assert.equal(r.detail.phase, 'dns');
});

test('http: timeout → status timeout, phase timeout', async () => {
  const { deps } = httpDeps(() => ({ timeout: true }));
  const r = await httpExecutor({ id: 1, type: 'http', config: { steps: [{ url: 'http://x/' }] } }, deps);
  assert.equal(r.status, 'timeout');
  assert.equal(r.detail.phase, 'timeout');
});

test('http: TLS error → phase tls', async () => {
  const { deps } = httpDeps(() => ({ error: 'CERT_HAS_EXPIRED' }));
  const r = await httpExecutor({ id: 1, type: 'http', config: { steps: [{ url: 'https://x/' }] } }, deps);
  assert.equal(r.detail.phase, 'tls');
});

// ---- tcp executor ----

function fakeSocketConnect(behavior) {
  return () => {
    const s = new EventEmitter();
    s.setTimeout = () => {};
    s.destroy = () => {};
    setImmediate(() => {
      if (behavior === 'connect') s.emit('connect');
      else if (behavior === 'timeout') s.emit('timeout');
      else { const e = new Error('x'); e.code = behavior; s.emit('error', e); }
    });
    return s;
  };
}

test('tcp: connect ok', async () => {
  const r = await tcpExecutor({ id: 1, type: 'tcp', target: 'db', config: { port: 5432 } }, { connect: fakeSocketConnect('connect'), now: () => 0 });
  assert.equal(r.status, 'ok');
});

test('tcp: refused → fail (phase connect)', async () => {
  const r = await tcpExecutor({ id: 1, type: 'tcp', target: 'db', config: { port: 5432 } }, { connect: fakeSocketConnect('ECONNREFUSED'), now: () => 0 });
  assert.equal(r.status, 'fail');
  assert.equal(r.detail.phase, 'connect');
});

test('tcp: timeout', async () => {
  const r = await tcpExecutor({ id: 1, type: 'tcp', target: 'db', config: { port: 5432 } }, { connect: fakeSocketConnect('timeout'), now: () => 0 });
  assert.equal(r.status, 'timeout');
});

// ---- dns executor ----

test('dns: resolves ok', async () => {
  const r = await dnsExecutor({ id: 1, type: 'dns', target: 'example.com', config: { record: 'A' } }, { resolver: { resolve: async () => ['1.2.3.4'] }, now: () => 0 });
  assert.equal(r.status, 'ok');
});

test('dns: expected answer mismatch → fail', async () => {
  const r = await dnsExecutor({ id: 1, type: 'dns', target: 'example.com', config: { record: 'A', expect: '9.9.9.9' } }, { resolver: { resolve: async () => ['1.2.3.4'] }, now: () => 0 });
  assert.equal(r.status, 'fail');
});

test('dns: NXDOMAIN → fail with phase dns', async () => {
  const r = await dnsExecutor({ id: 1, type: 'dns', target: 'nope', config: { record: 'A' } }, { resolver: { resolve: async () => { const e = new Error('nx'); e.code = 'ENOTFOUND'; throw e; } }, now: () => 0 });
  assert.equal(r.status, 'fail');
  assert.equal(r.detail.phase, 'dns');
});

// ---- icmp executor (canned ping output) ----

const LINUX_PING = 'PING x (1.2.3.4) 56(84) bytes.\n64 bytes from 1.2.3.4: icmp_seq=1 ttl=52 time=12.3 ms\n\n--- x ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss, time 0ms\nrtt min/avg/max/mdev = 12.3/12.3/12.3/0.0 ms';
const WIN_PING = 'Pinging x with 32 bytes of data:\nReply from 1.2.3.4: bytes=32 time=11ms TTL=52\n\nPing statistics for 1.2.3.4:\n    Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),\nApproximate round trip times in milli-seconds:\n    Minimum = 11ms, Maximum = 11ms, Average = 11ms';
const LOSS_PING = '--- x ping statistics ---\n1 packets transmitted, 0 received, 100% packet loss, time 0ms';

test('icmp: parses Linux output', async () => {
  const r = await icmpExecutor({ id: 1, type: 'icmp', target: 'x' }, { exec: (c, a, o, cb) => cb(null, LINUX_PING), platform: 'linux', now: () => 0 });
  assert.equal(r.status, 'ok');
  assert.equal(r.latency_ms, 12.3);
});

test('icmp: parses Windows output', async () => {
  const r = await icmpExecutor({ id: 1, type: 'icmp', target: 'x' }, { exec: (c, a, o, cb) => cb(null, WIN_PING), platform: 'win32', now: () => 0 });
  assert.equal(r.status, 'ok');
  assert.equal(r.latency_ms, 11);
});

test('icmp: 100% loss → fail', async () => {
  const r = await icmpExecutor({ id: 1, type: 'icmp', target: 'x' }, { exec: (c, a, o, cb) => cb(new Error('x'), LOSS_PING), platform: 'linux', now: () => 0 });
  assert.equal(r.status, 'fail');
});

test('icmp: ping binary missing → error', async () => {
  const r = await icmpExecutor({ id: 1, type: 'icmp', target: 'x' }, { exec: (c, a, o, cb) => { const e = new Error('nope'); e.code = 'ENOENT'; cb(e, ''); }, platform: 'linux', now: () => 0 });
  assert.equal(r.status, 'error');
  assert.equal(r.detail.errno, 'PING_MISSING');
});

test('icmp: timeout (killed)', async () => {
  const r = await icmpExecutor({ id: 1, type: 'icmp', target: 'x' }, { exec: (c, a, o, cb) => { const e = new Error('timeout'); e.killed = true; cb(e, ''); }, platform: 'linux', now: () => 0 });
  assert.equal(r.status, 'timeout');
});

test('icmp: SECURITY a target starting with "-" is rejected and ping is never spawned', async () => {
  let spawned = false;
  const r = await icmpExecutor({ id: 1, type: 'icmp', target: '-f' }, { exec: () => { spawned = true; }, platform: 'linux', now: () => 0 });
  assert.equal(r.status, 'error');
  assert.equal(r.detail.errno, 'INVALID_TARGET');
  assert.equal(spawned, false);
});

test('icmp: the host is placed after -- (end-of-options) on unix', async () => {
  let capturedArgs = null;
  await icmpExecutor({ id: 1, type: 'icmp', target: '1.2.3.4' }, { exec: (c, a, o, cb) => { capturedArgs = a; cb(null, LINUX_PING); }, platform: 'linux', now: () => 0 });
  assert.ok(capturedArgs.includes('--'));
  assert.equal(capturedArgs[capturedArgs.length - 1], '1.2.3.4');
});

// ---- runTransaction dispatch ----

test('runTransaction: unknown type → error, never throws', async () => {
  const r = await runTransaction({ id: 1, type: 'ftp' });
  assert.equal(r.status, 'error');
  assert.equal(r.detail.errno, 'UNKNOWN_TYPE');
  assert.equal(r.test_id, 1);
});

// ---- subst / extract units ----

test('subst: unknown placeholders resolve to empty (no literal leak)', () => {
  assert.equal(substitute('a={{secret:X}} b={{Y}}', { secrets: {}, vars: {} }), 'a= b=');
});

test('extract: json path + cookie', () => {
  assert.equal(extract({ type: 'json', pattern: 'data.token' }, { body: '{"data":{"token":"T"}}' }), 'T');
  assert.equal(extract({ type: 'cookie', pattern: 'sid' }, { headers: { 'set-cookie': ['sid=XYZ; Path=/'] } }), 'XYZ');
});

// ---- buffer ----

test('buffer drops the oldest on overflow (max 1000)', () => {
  const b = createResultBuffer({ max: 1000 });
  for (let i = 0; i < 1001; i += 1) b.push({ i });
  assert.equal(b.size(), 1000);
  assert.equal(b.droppedCount(), 1);
  const all = b.drain();
  assert.equal(all[0].i, 1); // index 0 was dropped
  assert.equal(b.size(), 0);
});

// ---- config store: secrets encrypted at rest ----

test('configStore round-trips config; secrets encrypted on disk, decrypted on load', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tx-'));
  const filePath = path.join(dir, 'transactions.json');
  const store = createConfigStore({ filePath, secretStore: createSecretStore('agent-token-xyz') });
  store.save([{ id: 1, type: 'http', config: { steps: [] }, secrets: { API_KEY: 'plaintext-secret' }, interval_sec: 60 }]);
  const onDisk = fs.readFileSync(filePath, 'utf8');
  assert.ok(!onDisk.includes('plaintext-secret'), 'secret must not appear in plaintext on disk');
  assert.ok(onDisk.includes('config_secrets'));
  const loaded = store.load();
  assert.equal(loaded.length, 1);
  assert.equal(loaded[0].secrets.API_KEY, 'plaintext-secret');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('configStore: a different token cannot decrypt the secrets', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tx-'));
  const filePath = path.join(dir, 'transactions.json');
  createConfigStore({ filePath, secretStore: createSecretStore('token-A') }).save([{ id: 1, type: 'http', secrets: { K: 'v' } }]);
  const loaded = createConfigStore({ filePath, secretStore: createSecretStore('token-B') }).load();
  assert.deepEqual(loaded[0].secrets, {}); // wrong key → no secrets (fail-safe)
  fs.rmSync(dir, { recursive: true, force: true });
});

// ---- manager: schedule, buffer, flush ----

function immediateStore() { let saved = []; return { save: (t) => { saved = t; }, load: () => saved, _saved: () => saved }; }

test('manager runs a test, buffers, and flushes a batch when online', async () => {
  const sent = [];
  const scheduled = [];
  const m = createTransactionManager({
    send: (o) => { sent.push(o); return true; },
    configStore: immediateStore(),
    buffer: createResultBuffer(),
    run: async (t) => ({ test_id: t.id, time: 't', status: 'ok', latency_ms: 5 }),
    setTimeoutFn: (fn) => { scheduled.push(fn); return { unref() {} }; },
    clearTimeoutFn: () => {},
    random: () => 0.5,
  });
  m.applyConfig([{ id: 1, type: 'tcp', target: 'db', interval_sec: 60, enabled: true }]);
  m.start();
  assert.equal(scheduled.length, 1, 'one test scheduled');
  await scheduled[scheduled.length - 1](); // fire a tick
  assert.equal(sent.length, 1);
  assert.equal(sent[0].type, 'transaction_result');
  assert.equal(sent[0].results[0].test_id, 1);
});

test('manager buffers while offline and flushes on reconnect', async () => {
  const sent = [];
  const scheduled = [];
  let online = false;
  const m = createTransactionManager({
    send: (o) => { if (!online) return false; sent.push(o); return true; },
    configStore: immediateStore(),
    buffer: createResultBuffer(),
    run: async (t) => ({ test_id: t.id, time: 't', status: 'ok', latency_ms: 5 }),
    setTimeoutFn: (fn) => { scheduled.push(fn); return { unref() {} }; },
    clearTimeoutFn: () => {},
    random: () => 0.5,
  });
  m.applyConfig([{ id: 1, type: 'tcp', target: 'db', interval_sec: 60, enabled: true }]);
  m.start();
  await scheduled[scheduled.length - 1]();
  assert.equal(sent.length, 0, 'nothing sent while offline');
  online = true;
  assert.equal(m.flush(), true);
  assert.equal(sent.length, 1);
  assert.equal(sent[0].results.length, 1);
});

test('manager: jitter stays within ±10% of interval', () => {
  const delays = [];
  const m = createTransactionManager({
    send: () => true, configStore: immediateStore(), buffer: createResultBuffer(),
    run: async () => ({ status: 'ok' }),
    setTimeoutFn: (fn, ms) => { delays.push(ms); return { unref() {} }; },
    clearTimeoutFn: () => {}, random: () => 0, // min jitter = 0.9x
  });
  m.applyConfig([{ id: 1, type: 'tcp', interval_sec: 100, enabled: true }]);
  m.start();
  assert.equal(delays[0], 90000); // 0.9 * 100s
});
