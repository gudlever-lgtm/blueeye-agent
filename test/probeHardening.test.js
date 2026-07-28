'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { safeHeader, dataArgs } = require('../src/probes/curlArgs');
const { compile, safeExec, safeTest } = require('../src/probes/safeRegex');
const { transactionProbe } = require('../src/probes/transaction');
const { curlProbe } = require('../src/probes/curl');
const { extract } = require('../src/transactions/extract');

// A fake execFile that records the argv it was handed and replies with a
// canned curl -i response plus the probe's trailing metrics line.
function recordingCurl(sentinel, { status = 200, body = 'hello' } = {}) {
  const calls = [];
  const exec = (cmd, args, _opts, cb) => {
    calls.push({ cmd, args });
    const out = `HTTP/1.1 ${status} OK\r\ncontent-type: text/plain\r\n\r\n${body}\n${sentinel} ${status} ${body.length} 0.01 text/plain`;
    setImmediate(() => cb(null, out, ''));
  };
  return { exec, calls };
}

test('safeHeader accepts a well-formed field and rejects curl @file reads', () => {
  assert.equal(safeHeader('Authorization: Bearer abc'), 'Authorization: Bearer abc');
  assert.equal(safeHeader('  X-Trace: 1  '), 'X-Trace: 1');
  // curl would read the headers from this local file.
  assert.equal(safeHeader('@/etc/shadow'), null);
  assert.equal(safeHeader('@/root/.ssh/id_rsa: x'), null);
  // Header/CRLF splitting and curl's "send empty header" shorthand.
  assert.equal(safeHeader('X-A: 1\r\nX-B: 2'), null);
  assert.equal(safeHeader('X-Empty;'), null);
  assert.equal(safeHeader(''), null);
  assert.equal(safeHeader(`X-Long: ${'a'.repeat(300)}`), null);
});

test('dataArgs always uses --data-raw so a body is never read from a file', () => {
  assert.deepEqual(dataArgs('@/etc/shadow'), ['--data-raw', '@/etc/shadow']);
  assert.deepEqual(dataArgs('a=1'), ['--data-raw', 'a=1']);
});

test('transaction step body goes out as --data-raw, never --data', async () => {
  const { exec, calls } = recordingCurl('__BLUEEYE_TX__');
  const res = await transactionProbe(
    { steps: [{ url: 'https://example.test/login', method: 'POST', data: '@/etc/shadow' }] },
    { exec }
  );
  assert.equal(res.ok, true);
  const { args } = calls[0];
  assert.ok(args.includes('--data-raw'), 'expected --data-raw');
  assert.ok(!args.includes('--data'), 'plain --data would read the local file');
  // The value is still sent verbatim — it is just never opened as a path.
  assert.equal(args[args.indexOf('--data-raw') + 1], '@/etc/shadow');
});

test('transaction step with an @file header is refused without running curl', async () => {
  const { exec, calls } = recordingCurl('__BLUEEYE_TX__');
  const res = await transactionProbe(
    { steps: [{ url: 'https://attacker.test/', method: 'POST', header: '@/etc/shadow' }] },
    { exec }
  );
  assert.equal(res.ok, false);
  assert.equal(calls.length, 0, 'curl must not be spawned for a refused header');
  assert.match(res.detail, /malformed request header/);
});

test('transaction step with a valid header still passes it through', async () => {
  const { exec, calls } = recordingCurl('__BLUEEYE_TX__');
  const res = await transactionProbe(
    { steps: [{ url: 'https://example.test/', header: 'Authorization: Bearer t' }] },
    { exec }
  );
  assert.equal(res.ok, true);
  const { args } = calls[0];
  assert.equal(args[args.indexOf('-H') + 1], 'Authorization: Bearer t');
});

test('safeRegex aborts a catastrophic pattern instead of hanging', () => {
  const rx = compile('^(a+)+$');
  const subject = `${'a'.repeat(60)}b`;
  const t0 = Date.now();
  assert.equal(safeTest(rx, subject, { timeoutMs: 150 }), false);
  const elapsed = Date.now() - t0;
  assert.ok(elapsed < 3000, `expected the match to be interrupted, took ${elapsed}ms`);
});

test('safeRegex still matches ordinary patterns', () => {
  const m = safeExec(compile('token=([a-z0-9]+)'), 'set-cookie: token=abc123; Path=/');
  assert.equal(m[1], 'abc123');
  assert.equal(safeExec(compile('nope'), 'body'), null);
  assert.equal(compile('('), null, 'a malformed pattern compiles to null, never throws');
  assert.equal(safeExec(null, 'body'), null);
});

test('safeRegex truncates an oversized subject', () => {
  const huge = `${'x'.repeat(300 * 1024)}needle`;
  assert.equal(safeTest(compile('needle'), huge), false, 'beyond the cap is not searched');
  assert.equal(safeTest(compile('needle'), `needle${'x'.repeat(300 * 1024)}`), true);
});

test('transaction extraction is bounded by safeRegex', async () => {
  const { exec } = recordingCurl('__BLUEEYE_TX__', { body: `${'a'.repeat(60)}b` });
  const res = await transactionProbe(
    {
      steps: [
        { url: 'https://example.test/', extract: { name: 'v', pattern: '^(a+)+$' } },
        { url: 'https://example.test/{{v}}' },
      ],
    },
    { exec }
  );
  // The runaway extraction resolves to "no capture", so the journey completes.
  assert.equal(res.ok, true);
});

test('curl probe body assertion is bounded by safeRegex', async () => {
  const { exec } = recordingCurl('__BLUEEYE_CURL__', { body: `${'a'.repeat(60)}b` });
  const res = await curlProbe(
    { url: 'https://example.test/', expectBody: '/^(a+)+$/' },
    { exec }
  );
  assert.equal(res.ok, false); // the assertion fails; the agent keeps running
});

test('transaction-config extraction is bounded by safeRegex', () => {
  assert.equal(extract({ type: 'regex', pattern: '^(a+)+$' }, { body: `${'a'.repeat(60)}b` }), null);
  assert.equal(extract({ type: 'regex', pattern: 'id=(\\d+)' }, { body: 'id=42' }), '42');
});
