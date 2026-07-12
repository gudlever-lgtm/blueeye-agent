'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { runDoctor, formatReport } = require('../src/doctor');

// ---- fakes ----------------------------------------------------------------
const GOOD_CONFIG = { serverUrl: 'https://blueeye.example.dk', tokenPath: '/x/token', serverCertFingerprint: '' };
const okToken = () => ({ agentId: 7, token: 'tok' });

function makeRequest(map) {
  // map: { '/enroll/config': {status}|Error, '/agents/me/config': {status}|Error }
  return async ({ url }) => {
    const path = url.replace(/^https?:\/\/[^/]+/, '');
    const v = map[path];
    if (v instanceof Error) throw v;
    if (v === undefined) return { status: 404, json: null };
    return v;
  };
}

function fakeWs(behavior) {
  return class {
    constructor(url, opts) { this.url = url; this.opts = opts; this._h = {}; setImmediate(() => behavior(this)); }
    on(ev, cb) { (this._h[ev] = this._h[ev] || []).push(cb); return this; }
    emit(ev, ...a) { (this._h[ev] || []).forEach((cb) => cb(...a)); }
    terminate() {}
  };
}
const WS_CONNECTED = fakeWs((ws) => ws.emit('message', JSON.stringify({ type: 'connected' })));
const WS_401 = fakeWs((ws) => ws.emit('unexpected-response', {}, { statusCode: 401 }));
const WS_ERR = fakeWs((ws) => ws.emit('error', new Error('ECONNREFUSED')));

const baseDeps = {
  lookup: async () => ({ address: '10.0.0.9' }),
  tcpConnect: async () => {},
  tokenReader: okToken,
  WebSocketImpl: WS_CONNECTED,
  timeoutMs: 500,
};

const byName = (report, name) => report.checks.find((c) => c.name === name);

// ---- happy path ------------------------------------------------------------
test('all checks pass -> connected', async () => {
  const report = await runDoctor({
    ...baseDeps,
    config: GOOD_CONFIG,
    request: makeRequest({ '/enroll/config': { status: 200 }, '/agents/me/config': { status: 200 } }),
  });
  assert.equal(report.connected, true);
  assert.equal(report.failed.length, 0);
  for (const n of ['config', 'token', 'dns', 'tcp', 'http', 'auth', 'websocket']) {
    assert.ok(byName(report, n).ok, `${n} should pass`);
  }
});

// ---- config / token prerequisites -----------------------------------------
test('missing server URL fails config and stops early', async () => {
  const report = await runDoctor({ ...baseDeps, config: { serverUrl: '' } });
  assert.equal(report.connected, false);
  assert.equal(byName(report, 'config').ok, false);
  assert.match(byName(report, 'config').suggestion, /BLUEEYE_SERVER_URL/);
  // No network checks once the URL is unusable.
  assert.equal(byName(report, 'dns'), undefined);
});

test('no stored token fails token and skips auth/websocket', async () => {
  const report = await runDoctor({
    ...baseDeps,
    config: GOOD_CONFIG,
    tokenReader: () => null,
    request: makeRequest({ '/enroll/config': { status: 200 } }),
  });
  assert.equal(byName(report, 'token').ok, false);
  assert.match(byName(report, 'token').suggestion, /enroll/i);
  assert.equal(byName(report, 'auth').skipped, true);
  assert.equal(byName(report, 'websocket').skipped, true);
});

// ---- network layers --------------------------------------------------------
test('DNS failure is reported with a resolution suggestion', async () => {
  const report = await runDoctor({
    ...baseDeps,
    config: { ...GOOD_CONFIG, serverUrl: 'http://blueeye' },
    lookup: async () => { const e = new Error('not found'); e.code = 'ENOTFOUND'; throw e; },
    request: makeRequest({ '/enroll/config': { status: 200 }, '/agents/me/config': { status: 200 } }),
  });
  assert.equal(byName(report, 'dns').ok, false);
  assert.match(byName(report, 'dns').suggestion, /resolve|BLUEEYE_PUBLIC_URL|hosts/i);
});

test('literal IP host skips DNS', async () => {
  const report = await runDoctor({
    ...baseDeps,
    config: { ...GOOD_CONFIG, serverUrl: 'http://10.0.0.5:3000' },
    request: makeRequest({ '/enroll/config': { status: 200 }, '/agents/me/config': { status: 200 } }),
  });
  assert.equal(byName(report, 'dns').skipped, true);
});

test('TCP failure is reported with a firewall/port suggestion', async () => {
  const report = await runDoctor({
    ...baseDeps,
    config: GOOD_CONFIG,
    tcpConnect: async () => { const e = new Error('refused'); e.code = 'ECONNREFUSED'; throw e; },
    request: makeRequest({ '/enroll/config': { status: 200 }, '/agents/me/config': { status: 200 } }),
  });
  assert.equal(byName(report, 'tcp').ok, false);
  assert.match(byName(report, 'tcp').suggestion, /firewall|port/i);
});

// ---- HTTP / TLS ------------------------------------------------------------
test('TLS error suggests pinning the self-signed cert', async () => {
  const report = await runDoctor({
    ...baseDeps,
    config: GOOD_CONFIG,
    request: makeRequest({ '/enroll/config': new Error('self-signed certificate in certificate chain') }),
  });
  assert.equal(byName(report, 'http').ok, false);
  assert.match(byName(report, 'http').suggestion, /fingerprint|pin/i);
});

test('http→https redirect (301) is named precisely, with the https fix', async () => {
  const report = await runDoctor({
    ...baseDeps,
    config: { ...GOOD_CONFIG, serverUrl: 'http://blueeye.example.dk' },
    request: makeRequest({ '/enroll/config': { status: 301, headers: { location: 'https://blueeye.example.dk/enroll/config' } } }),
  });
  const http = byName(report, 'http');
  assert.equal(http.ok, false);
  assert.match(http.detail, /redirected .*301/i);
  assert.match(http.suggestion, /https/);
  assert.match(http.suggestion, /BLUEEYE_PUBLIC_URL|--server https/);
  // WebSocket can't run once HTTP is unusable.
  assert.equal(byName(report, 'websocket').skipped, true);
});

test('unreachable server suggests a curl probe', async () => {
  const report = await runDoctor({
    ...baseDeps,
    config: GOOD_CONFIG,
    request: makeRequest({ '/enroll/config': Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }) }),
  });
  assert.equal(byName(report, 'http').ok, false);
  assert.match(byName(report, 'http').suggestion, /curl/);
});

// ---- auth ------------------------------------------------------------------
test('401 on auth suggests re-enrollment', async () => {
  const report = await runDoctor({
    ...baseDeps,
    config: GOOD_CONFIG,
    request: makeRequest({ '/enroll/config': { status: 200 }, '/agents/me/config': { status: 401 } }),
  });
  assert.equal(byName(report, 'auth').ok, false);
  assert.match(byName(report, 'auth').suggestion, /re-enroll/i);
});

test('403 on auth points at the licence', async () => {
  const report = await runDoctor({
    ...baseDeps,
    config: GOOD_CONFIG,
    request: makeRequest({ '/enroll/config': { status: 200 }, '/agents/me/config': { status: 403 } }),
  });
  assert.equal(byName(report, 'auth').ok, false);
  assert.match(byName(report, 'auth').suggestion, /licen/i);
});

// ---- websocket -------------------------------------------------------------
test('websocket 401 is reported', async () => {
  const report = await runDoctor({
    ...baseDeps,
    config: GOOD_CONFIG,
    WebSocketImpl: WS_401,
    request: makeRequest({ '/enroll/config': { status: 200 }, '/agents/me/config': { status: 200 } }),
  });
  assert.equal(byName(report, 'websocket').ok, false);
  assert.equal(report.connected, false);
});

test('websocket blocked (HTTP works) suggests a proxy/upgrade issue', async () => {
  const report = await runDoctor({
    ...baseDeps,
    config: GOOD_CONFIG,
    WebSocketImpl: WS_ERR,
    request: makeRequest({ '/enroll/config': { status: 200 }, '/agents/me/config': { status: 200 } }),
  });
  assert.equal(byName(report, 'websocket').ok, false);
  assert.match(byName(report, 'websocket').suggestion, /proxy|firewall|upgrade/i);
});

// ---- formatting ------------------------------------------------------------
test('formatReport lists suggestions and a clear verdict', async () => {
  const report = await runDoctor({
    ...baseDeps,
    config: GOOD_CONFIG,
    request: makeRequest({ '/enroll/config': { status: 200 }, '/agents/me/config': { status: 401 } }),
  });
  const text = formatReport(report);
  assert.match(text, /✗ auth/);
  assert.match(text, /→ /);
  assert.match(text, /NOT CONNECTED/);
});
