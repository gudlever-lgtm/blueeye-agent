'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { resolveEffectiveServerUrl } = require('../src/serverUrl');

const redirect = (location, status = 301) => async () => ({ status, headers: location ? { location } : {} });
const ok = async () => ({ status: 200, headers: {} });

test('upgrades http→https when the server redirects to https on the same host', async () => {
  const out = await resolveEffectiveServerUrl({
    serverUrl: 'http://blueeye.example.dk',
    request: redirect('https://blueeye.example.dk/enroll/config'),
  });
  assert.equal(out, 'https://blueeye.example.dk');
});

test('preserves the redirect target port (e.g. :8443), not the original', async () => {
  const out = await resolveEffectiveServerUrl({
    serverUrl: 'http://host.example:3000',
    request: redirect('https://host.example:8443/enroll/config'),
  });
  assert.equal(out, 'https://host.example:8443');
});

test('leaves an already-https URL untouched and does not probe', async () => {
  let probed = false;
  const out = await resolveEffectiveServerUrl({
    serverUrl: 'https://blueeye.example.dk',
    request: async () => { probed = true; return redirect('http://x')(); },
  });
  assert.equal(out, 'https://blueeye.example.dk');
  assert.equal(probed, false);
});

test('leaves it unchanged on a normal 200 (no redirect)', async () => {
  const out = await resolveEffectiveServerUrl({ serverUrl: 'http://blueeye.example.dk', request: ok });
  assert.equal(out, 'http://blueeye.example.dk');
});

test('does NOT follow a redirect to a different host (open-redirect / MITM guard)', async () => {
  const out = await resolveEffectiveServerUrl({
    serverUrl: 'http://blueeye.example.dk',
    request: redirect('https://evil.example.com/enroll/config'),
  });
  assert.equal(out, 'http://blueeye.example.dk');
});

test('does NOT upgrade on a redirect without an https Location', async () => {
  const out = await resolveEffectiveServerUrl({
    serverUrl: 'http://blueeye.example.dk',
    request: redirect('/somewhere-relative'),
  });
  assert.equal(out, 'http://blueeye.example.dk');
});

test('leaves it unchanged when the server is unreachable over http', async () => {
  const out = await resolveEffectiveServerUrl({
    serverUrl: 'http://blueeye.example.dk',
    request: async () => { throw Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }); },
  });
  assert.equal(out, 'http://blueeye.example.dk');
});

test('handles 302/307/308 the same way as 301', async () => {
  for (const status of [302, 307, 308]) {
    const out = await resolveEffectiveServerUrl({
      serverUrl: 'http://blueeye.example.dk',
      request: redirect('https://blueeye.example.dk/enroll/config', status),
    });
    assert.equal(out, 'https://blueeye.example.dk', `status ${status}`);
  }
});

test('logs a warning when it upgrades', async () => {
  const warnings = [];
  await resolveEffectiveServerUrl({
    serverUrl: 'http://blueeye.example.dk',
    request: redirect('https://blueeye.example.dk/enroll/config'),
    logger: { warn: (m) => warnings.push(m) },
  });
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /HTTPS/);
});
