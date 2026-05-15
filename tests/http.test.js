import test from 'node:test';
import assert from 'node:assert/strict';

import { parseCurl } from './http.js';

test('parseCurl returnerer korrekt JSON-struktur ved 200', () => {
  const result = parseCurl('200 0.142000 0.098000 4821');
  assert.deepEqual(result, {
    statusCode: 200,
    responseTimeMs: 142,
    ttfbMs: 98,
    contentLength: 4821,
  });
});

test('HTTP 404 kaster fejl med statusCode 404 i result', () => {
  let thrown;
  try {
    parseCurl('404 0.050000 0.040000 120');
  } catch (err) {
    thrown = err;
  }
  assert.ok(thrown, 'parseCurl skal kaste ved 404');
  assert.match(thrown.message, /404/);
  assert.equal(thrown.result.statusCode, 404);
});

test('HTTP 500 kaster fejl med statusCode 500 i result', () => {
  let thrown;
  try {
    parseCurl('500 0.200000 0.150000 512');
  } catch (err) {
    thrown = err;
  }
  assert.ok(thrown, 'parseCurl skal kaste ved 500');
  assert.match(thrown.message, /500/);
  assert.equal(thrown.result.statusCode, 500);
});

test('parseCurl kaster ved uparsbart output', () => {
  assert.throws(() => parseCurl('garbage'));
});
