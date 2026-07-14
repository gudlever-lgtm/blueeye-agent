'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { closeNetworkHandles } = require('../src/shutdown');

test('closes the undici global dispatcher and destroys the http/https agents', async () => {
  let closed = 0;
  const dispatcher = { close: async () => { closed += 1; } };
  const destroyed = [];
  const agents = [
    { destroy: () => destroyed.push('http') },
    { destroy: () => destroyed.push('https') },
  ];

  await closeNetworkHandles({ getDispatcher: () => dispatcher, agents });

  assert.equal(closed, 1);
  assert.deepEqual(destroyed, ['http', 'https']);
});

test('is a no-op (does not throw) when no dispatcher is installed', async () => {
  const destroyed = [];
  await closeNetworkHandles({
    getDispatcher: () => undefined, // fetch() was never called
    agents: [{ destroy: () => destroyed.push('http') }],
  });
  assert.deepEqual(destroyed, ['http']); // agents still drained
});

test('never lets a hanging dispatcher.close() block the exit', async () => {
  const timers = [];
  const fakeSetTimeout = (fn) => { timers.push(fn); return { unref() {} }; };
  const dispatcher = { close: () => new Promise(() => {}) }; // never resolves

  let done = false;
  const p = closeNetworkHandles({
    getDispatcher: () => dispatcher,
    agents: [],
    setTimeoutFn: fakeSetTimeout,
  }).then(() => { done = true; });

  // The race is still pending until the capped timer fires.
  await Promise.resolve();
  assert.equal(done, false);
  assert.equal(timers.length, 1);
  timers[0](); // fire the timeout cap
  await p;
  assert.equal(done, true);
});

test('a throwing dispatcher.close() is swallowed and agents still drain', async () => {
  const destroyed = [];
  await closeNetworkHandles({
    getDispatcher: () => ({ close: async () => { throw new Error('boom'); } }),
    agents: [{ destroy: () => destroyed.push('http') }],
  });
  assert.deepEqual(destroyed, ['http']);
});

test('a getDispatcher that throws does not abort teardown', async () => {
  const destroyed = [];
  await closeNetworkHandles({
    getDispatcher: () => { throw new Error('no globalThis'); },
    agents: [{ destroy: () => destroyed.push('https') }],
  });
  assert.deepEqual(destroyed, ['https']);
});
