'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { computeBackoff } = require('../src/backoff');

test('computeBackoff grows exponentially and respects the cap (with jitter)', () => {
  const opts = { baseMs: 100, maxMs: 1000, factor: 2 };
  for (let i = 0; i < 100; i += 1) {
    // attempt 1 -> exp 100 -> jittered 50..100
    const a1 = computeBackoff(1, opts);
    assert.ok(a1 >= 50 && a1 <= 100, `attempt1=${a1}`);

    // attempt 3 -> exp 400 -> jittered 200..400
    const a3 = computeBackoff(3, opts);
    assert.ok(a3 >= 200 && a3 <= 400, `attempt3=${a3}`);

    // large attempt -> capped at 1000 -> jittered 500..1000
    const big = computeBackoff(20, opts);
    assert.ok(big >= 500 && big <= 1000, `big=${big}`);
  }
});
