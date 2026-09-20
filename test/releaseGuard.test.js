'use strict';

// An update that installs but never comes up used to end the agent.
//
// selfUpdate swaps `current` to the new release and restarts. If that release
// cannot start, systemd retries, hits its start limit and stops — and the host
// is off the fleet, which is the one state that needs a shell to fix. rollback()
// existed for exactly this and nothing called it.
//
// The guard is plain sh living outside the release tree, so these tests run the
// REAL script: a Node test of a shell script that only ever ran in Node would
// prove nothing about the day Node is what is broken.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const guard = require('../src/release/releaseGuard');

// A blue/green layout: two release dirs, `current` pointing at the new one and
// `.previous` recording the old — exactly what atomicInstall leaves behind.
function layout(t, { pending = null } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'blueeye-guard-'));
  t.after(() => { try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* ignore */ } });
  const releases = path.join(root, 'releases');
  const oldDir = path.join(releases, '0.27.0');
  const newDir = path.join(releases, '0.28.0');
  fs.mkdirSync(oldDir, { recursive: true });
  fs.mkdirSync(newDir, { recursive: true });
  const current = path.join(root, 'current');
  fs.symlinkSync(newDir, current);
  fs.writeFileSync(path.join(releases, '.previous'), oldDir);
  if (pending) fs.writeFileSync(path.join(releases, '.pending'), pending);

  const script = path.join(root, 'release-guard.sh');
  fs.writeFileSync(script, guard.guardScript(), { mode: 0o755 });

  return {
    root,
    releases,
    oldDir,
    newDir,
    current,
    // One start attempt, as systemd's ExecStartPre would run it.
    run: (limit = 3) => spawnSync('/bin/sh', [script, releases, current, String(limit)], { encoding: 'utf8' }),
    target: () => fs.realpathSync(current),
    pending: () => guard.readPending(releases),
  };
}

test('the guard counts starts and stays out of the way while attempts remain', (t) => {
  const l = layout(t, { pending: '0.28.0\n0\n' });

  const first = l.run();
  assert.equal(first.status, 0);
  assert.deepEqual(l.pending(), { version: '0.28.0', attempts: 1 });
  assert.equal(l.target(), fs.realpathSync(l.newDir), 'a first failed start must not roll anything back');

  l.run();
  assert.equal(l.pending().attempts, 2);
  assert.equal(l.target(), fs.realpathSync(l.newDir));
});

test('at the limit it repoints current at the previous release and clears the marker', (t) => {
  const l = layout(t, { pending: '0.28.0\n0\n' });

  l.run(); // 1
  l.run(); // 2
  l.run(); // 3 — still counting up to the limit
  const rolled = l.run(); // the start that exceeds it

  assert.equal(rolled.status, 0);
  assert.match(rolled.stderr, /rolled back/);
  assert.equal(l.target(), fs.realpathSync(l.oldDir), 'the host must come back on the known-good release');
  assert.equal(l.pending(), null, 'a cleared marker is what stops it rolling back for ever');
});

test('a confirmed release is never rolled back, however often it restarts', (t) => {
  const l = layout(t, { pending: '0.28.0\n0\n' });
  l.run();

  // What the agent does once it has held a server connection.
  assert.equal(guard.confirmRelease(l.releases), true);

  for (let i = 0; i < 6; i += 1) assert.equal(l.run().status, 0);
  assert.equal(l.target(), fs.realpathSync(l.newDir));
  assert.equal(l.pending(), null);
});

test('with no previous release it gives up rather than looping for ever', (t) => {
  const l = layout(t, { pending: '0.28.0\n9\n' });
  fs.rmSync(path.join(l.releases, '.previous'));

  const out = l.run();
  assert.equal(out.status, 0);
  assert.match(out.stderr, /no previous release/);
  assert.equal(l.target(), fs.realpathSync(l.newDir), 'nothing better to run');
  assert.equal(l.pending(), null, 'the marker must not re-arm a rollback that cannot happen');
});

test('a garbled marker is treated as a fresh attempt, not a crash', (t) => {
  const l = layout(t, { pending: 'not-a-version\nnonsense\n' });
  const out = l.run();
  assert.equal(out.status, 0, out.stderr);
  assert.equal(l.pending().attempts, 1);
});

test('no marker means no update is waiting to prove itself — the guard does nothing', (t) => {
  const l = layout(t);
  const out = l.run();
  assert.equal(out.status, 0);
  assert.equal(out.stderr, '');
  assert.equal(l.target(), fs.realpathSync(l.newDir));
});

test('markPending / readPending / confirmRelease round-trip', (t) => {
  const l = layout(t);
  assert.equal(guard.readPending(l.releases), null);
  assert.equal(guard.markPending(l.releases, '0.28.0'), true);
  assert.deepEqual(guard.readPending(l.releases), { version: '0.28.0', attempts: 0 });
  assert.equal(guard.confirmRelease(l.releases), true);
  assert.equal(guard.readPending(l.releases), null);
  // Best-effort everywhere: a path that cannot be written is not an exception.
  assert.equal(guard.markPending('', '0.28.0'), false);
  assert.equal(guard.readPending(''), null);
});

test('ensureInstalled writes the guard outside the release tree, and wires systemd', (t) => {
  const l = layout(t);
  const unitDir = path.join(l.root, 'systemd');
  fs.mkdirSync(unitDir, { recursive: true });
  fs.writeFileSync(path.join(unitDir, 'blueeye-agent.service'), '[Service]\nExecStart=/usr/bin/node x\n');
  const calls = [];

  const first = guard.ensureInstalled({
    installDir: l.root, releasesDir: l.releases, currentLink: l.current, unitDir,
    exec: (cmd, args) => { calls.push([cmd, ...args].join(' ')); return { status: 0 }; },
  });
  assert.equal(first.ok, true);
  assert.equal(first.changed, true);

  const guardPath = path.join(l.root, 'bin', 'release-guard.sh');
  assert.ok(fs.existsSync(guardPath), 'the guard must not live under releases/ — that is what gets swapped');
  assert.ok(!path.resolve(guardPath).startsWith(path.resolve(l.releases) + path.sep));
  const conf = fs.readFileSync(path.join(unitDir, 'blueeye-agent.service.d', '20-release-guard.conf'), 'utf8');
  assert.match(conf, /ExecStartPre=-\/bin\/sh/);
  assert.match(conf, new RegExp(l.releases.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.ok(calls.some((c) => c === 'systemctl daemon-reload'));

  // Idempotent: a second run changes nothing and does not reload systemd again.
  calls.length = 0;
  const second = guard.ensureInstalled({
    installDir: l.root, releasesDir: l.releases, currentLink: l.current, unitDir,
    exec: (cmd, args) => { calls.push([cmd, ...args].join(' ')); return { status: 0 }; },
  });
  assert.equal(second.changed, false);
  assert.deepEqual(calls, []);
});

test('ensureInstalled reports rather than throws where it cannot act', () => {
  // No blue/green layout (a docker or legacy in-place install).
  const none = guard.ensureInstalled({ releasesDir: '', currentLink: '' });
  assert.equal(none.ok, false);
  assert.match(none.reason, /layout/);
});

// ---------------------------------------------------------------- the agent half

const { startFakeServer } = require('../test-support/fakeServer');
const { createAgentRuntime } = require('../src/runtime');
const { silentLogger } = require('../src/logger');

const onceEvent = (emitter, name) => new Promise((resolve) => emitter.once(name, resolve));
function withTimeout(promise, ms, message) {
  let timer;
  const timeout = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message || `timeout ${ms}ms`)), ms); timer.unref(); });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

test('the agent confirms a release only after the connection has held', async (t) => {
  const l = layout(t, { pending: '0.28.0\n1\n' });
  const server = await startFakeServer({ validTokens: ['valid'], monitorConfig: { source: 'proc' } });
  t.after(async () => { await server.close(); });

  const runtime = createAgentRuntime({
    config: { serverUrl: server.url, heartbeatMs: 10000, backoff: { baseMs: 30, maxMs: 120, factor: 2 } },
    token: 'valid', agentId: 1, logger: silentLogger,
    capabilities: { sources: ['proc'], agentVersion: '0.28.0', managed: 'systemd' },
    hsflowdManager: { enable: async () => ({}), disable: async () => ({}), status: async () => ({}) },
    releasesDir: l.releases,
    // Short enough for a test; the point is that it is not "on connect".
    confirmReleaseAfterMs: 150,
  });
  t.after(() => runtime.stop());

  const confirmed = onceEvent(runtime, 'release-confirmed');
  runtime.start();
  await withTimeout(onceEvent(runtime, 'connected'), 4000, 'never connected');

  // Connected is not confirmed: the marker is still there, so a release that
  // connects and then dies is still rolled back.
  assert.deepEqual(l.pending(), { version: '0.28.0', attempts: 1 }, 'confirmed on connect alone');

  const proof = await withTimeout(confirmed, 4000, 'never confirmed');
  assert.equal(proof.version, '0.28.0');
  assert.equal(l.pending(), null, 'a release that held its connection must stop being a rollback candidate');
});

test('an agent with no pending release confirms nothing', async (t) => {
  const l = layout(t); // no marker
  const server = await startFakeServer({ validTokens: ['valid'], monitorConfig: { source: 'proc' } });
  t.after(async () => { await server.close(); });

  const runtime = createAgentRuntime({
    config: { serverUrl: server.url, heartbeatMs: 10000, backoff: { baseMs: 30, maxMs: 120, factor: 2 } },
    token: 'valid', agentId: 1, logger: silentLogger,
    capabilities: { sources: ['proc'], agentVersion: '0.28.0', managed: 'systemd' },
    hsflowdManager: { enable: async () => ({}), disable: async () => ({}), status: async () => ({}) },
    releasesDir: l.releases,
    confirmReleaseAfterMs: 50,
  });
  t.after(() => runtime.stop());

  let confirmedFired = false;
  runtime.on('release-confirmed', () => { confirmedFired = true; });
  runtime.start();
  await withTimeout(onceEvent(runtime, 'connected'), 4000, 'never connected');
  await new Promise((r) => setTimeout(r, 200));
  assert.equal(confirmedFired, false);
});
