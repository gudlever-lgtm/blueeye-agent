'use strict';

// The two process-level guards. They are the difference between "a log line"
// and "the monitoring stopped", so the SPLIT is what these assert: a rejection
// survives, an exception drains and exits non-zero.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('events');

const { installCrashGuards } = require('../src/lib/crashGuard');

function makeLogger() {
  const errors = [];
  return { errors, warn() {}, error(...args) { errors.push(args); } };
}

// A stand-in for `process`: same on/removeListener/emit surface, none of the
// consequences. Installing the real handlers in a test runner would fight the
// runner's own.
const fakeProc = () => new EventEmitter();

test('an unhandled rejection is logged with its Error and the process keeps running', () => {
  const logger = makeLogger();
  const proc = fakeProc();
  let exited = null;
  const detach = installCrashGuards({ logger, proc, exit: (c) => { exited = c; } });

  proc.emit('unhandledRejection', new Error('forgot a .catch()'));

  assert.equal(exited, null, 'a rejection must never exit the process');
  assert.equal(logger.errors.length, 1);
  assert.match(logger.errors[0][0], /Unhandled promise rejection/);
  assert.equal(logger.errors[0][1].message, 'forgot a .catch()');
  detach();
});

test('a non-Error rejection reason is still reported (as an Error, so it carries a stack)', () => {
  const logger = makeLogger();
  const proc = fakeProc();
  const detach = installCrashGuards({ logger, proc, exit: () => {} });

  proc.emit('unhandledRejection', 'just a string');

  assert.equal(logger.errors.length, 1);
  assert.ok(logger.errors[0][1] instanceof Error);
  assert.match(logger.errors[0][1].message, /non-Error rejection: just a string/);
  detach();
});

test('an uncaught exception runs the graceful teardown, then exits 1', async () => {
  const logger = makeLogger();
  const proc = fakeProc();
  let exited = null;
  let tornDown = 0;
  const detach = installCrashGuards({
    logger,
    proc,
    exit: (c) => { exited = c; },
    onFatal: async () => { tornDown += 1; },
  });

  proc.emit('uncaughtException', new Error('boom'));
  await new Promise((r) => setImmediate(r));

  assert.equal(tornDown, 1, 'the pool and sockets must get a chance to close');
  assert.equal(exited, 1, 'a supervisor needs a non-zero code to restart us');
  assert.match(logger.errors[0][0], /Uncaught exception/);
  detach();
});

test('a teardown that rejects still exits 1 rather than hanging', async () => {
  const logger = makeLogger();
  const proc = fakeProc();
  let exited = null;
  const detach = installCrashGuards({
    logger, proc, exit: (c) => { exited = c; },
    onFatal: () => Promise.reject(new Error('pool already gone')),
  });

  proc.emit('uncaughtException', new Error('boom'));
  await new Promise((r) => setImmediate(r));

  assert.equal(exited, 1);
  assert.ok(logger.errors.some((e) => /Graceful shutdown failed/.test(e[0])));
  detach();
});

test('a teardown that never settles is abandoned on the timeout', async () => {
  const logger = makeLogger();
  const proc = fakeProc();
  let exited = null;
  const detach = installCrashGuards({
    logger, proc, exit: (c) => { exited = c; },
    onFatal: () => new Promise(() => {}), // never resolves
    timeoutMs: 5,
  });

  proc.emit('uncaughtException', new Error('boom'));
  await new Promise((r) => setTimeout(r, 25));

  assert.equal(exited, 1, 'we are already in an unknown state; lingering has no upside');
  detach();
});

test('a second exception during teardown exits immediately instead of re-entering it', async () => {
  const logger = makeLogger();
  const proc = fakeProc();
  const exits = [];
  let tornDown = 0;
  const detach = installCrashGuards({
    logger, proc, exit: (c) => exits.push(c),
    onFatal: () => { tornDown += 1; return new Promise((r) => setTimeout(r, 50)); },
  });

  proc.emit('uncaughtException', new Error('first'));
  proc.emit('uncaughtException', new Error('second'));

  assert.equal(tornDown, 1, 'teardown must not run twice');
  assert.deepEqual(exits, [1], 'the second exception exits without another teardown');
  detach();
});

test('no onFatal is fine: it just exits 1', () => {
  const logger = makeLogger();
  const proc = fakeProc();
  let exited = null;
  const detach = installCrashGuards({ logger, proc, exit: (c) => { exited = c; } });

  proc.emit('uncaughtException', new Error('boom'));

  assert.equal(exited, 1);
  detach();
});

test('detach() removes both listeners, so a test can install them without leaking', () => {
  const proc = fakeProc();
  const detach = installCrashGuards({ logger: makeLogger(), proc, exit: () => {} });
  assert.equal(proc.listenerCount('unhandledRejection'), 1);
  assert.equal(proc.listenerCount('uncaughtException'), 1);
  detach();
  assert.equal(proc.listenerCount('unhandledRejection'), 0);
  assert.equal(proc.listenerCount('uncaughtException'), 0);
});
