'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { runSpeedtest, mbps } = require('../src/speedtest');

test('mbps converts bytes + ms to megabits/second', () => {
  assert.equal(mbps(1_000_000, 1000), 8); // 1 MB in 1 s = 8 Mbps
  assert.equal(mbps(1_000_000, 500), 16);
  assert.equal(mbps(1000, 0), null);
});

test('runSpeedtest downloads then uploads and reports Mbps', async () => {
  let t = 0;
  const now = () => { t += 500; return t; }; // +500ms per call -> 500ms per phase
  const body = Buffer.alloc(1_000_000, 0);
  const calls = [];
  const fetchImpl = async (url, opts) => {
    calls.push({ url: String(url), method: (opts && opts.method) || 'GET' });
    if (String(url).includes('/speedtest/download')) return { ok: true, status: 200, arrayBuffer: async () => body };
    return { ok: true, status: 200, json: async () => ({ bytes: 1_000_000 }) };
  };
  const r = await runSpeedtest({ serverUrl: 'http://srv', token: 't', bytes: 1_000_000, fetchImpl, now });
  assert.equal(r.ok, true);
  assert.equal(r.downBytes, 1_000_000);
  assert.equal(r.downMs, 500);
  assert.equal(r.downMbps, 16);
  assert.equal(r.upBytes, 1_000_000);
  assert.equal(r.upMbps, 16);
  assert.ok(calls.some((c) => c.url.includes('/speedtest/download')));
  assert.ok(calls.some((c) => c.method === 'POST' && c.url.includes('/speedtest/upload')));
});

test('runSpeedtest reports a download failure without throwing', async () => {
  const fetchImpl = async () => ({ ok: false, status: 500 });
  const r = await runSpeedtest({ serverUrl: 'http://srv', token: 't', bytes: 2048, fetchImpl });
  assert.equal(r.ok, false);
  assert.match(r.detail, /download/);
});

test('runSpeedtest throws TOKEN_REJECTED on a 401', async () => {
  const fetchImpl = async () => ({ ok: false, status: 401 });
  await assert.rejects(
    () => runSpeedtest({ serverUrl: 'http://srv', token: 't', bytes: 2048, fetchImpl }),
    (e) => e.code === 'TOKEN_REJECTED'
  );
});
