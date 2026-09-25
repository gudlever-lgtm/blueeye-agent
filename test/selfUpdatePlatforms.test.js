'use strict';

// Self-update used to be systemd only, which meant a Windows fleet could be
// updated exactly one way: someone logging into every host and re-running the
// installer. The download, the signature check and the blue/green install are
// the same everywhere — only the restart and the symlink swap differ, and those
// are what is tested here.

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { createSelfUpdater } = require('../src/selfUpdate');
const releaseGuard = require('../src/release/releaseGuard');
const { detectManaged, isSelfUpdatable } = require('../src/capabilities');

const silent = { info() {}, warn() {}, error() {} };

test('the restart target follows the runtime, then the platform', () => {
  const mk = (over) => createSelfUpdater({ logger: silent, ...over });
  assert.equal(mk({ runtime: 'systemd', platform: 'win32' }).restartKind(), 'systemd', 'an explicit runtime wins');
  assert.equal(mk({ platform: 'win32' }).restartKind(), 'windows-service');
  assert.equal(mk({ platform: 'darwin' }).restartKind(), 'launchd');
  assert.equal(mk({ platform: 'linux' }).restartKind(), 'systemd');
});

test('launchd is restarted by kickstarting its job label', () => {
  const calls = [];
  const updater = createSelfUpdater({
    logger: silent,
    platform: 'darwin',
    launchdLabel: 'com.blueeye.agent',
    exec: (cmd, args) => { calls.push([cmd, args]); return { status: 0 }; },
  });
  const r = updater.restart();
  assert.equal(r.ok, true);
  assert.deepEqual(calls, [['launchctl', ['kickstart', '-k', 'system/com.blueeye.agent']]]);
});

test('a Windows service is restarted by a detached child, because it cannot stop itself', () => {
  const spawned = [];
  let unrefs = 0;
  const updater = createSelfUpdater({
    logger: silent,
    platform: 'win32',
    serviceName: 'BlueEyeAgent',
    spawnImpl: (cmd, args, opts) => { spawned.push({ cmd, args, opts }); return { unref: () => { unrefs += 1; } }; },
    exec: () => { throw new Error('the foreground path must not be used on Windows'); },
  });
  const r = updater.restart();
  assert.equal(r.ok, true);
  assert.equal(spawned.length, 1);
  assert.equal(spawned[0].cmd, 'cmd.exe');
  assert.equal(spawned[0].opts.detached, true, 'it has to outlive the process being stopped');
  assert.ok(spawned[0].args.join(' ').includes('net stop "BlueEyeAgent"'));
  assert.ok(spawned[0].args.join(' ').includes('net start "BlueEyeAgent"'));
  assert.equal(unrefs, 1, 'and must not hold the event loop open');
});

test('a restart that cannot even be launched is reported, not swallowed', () => {
  const updater = createSelfUpdater({
    logger: silent,
    platform: 'win32',
    spawnImpl: () => { throw new Error('EPERM'); },
  });
  const r = updater.restart();
  assert.equal(r.ok, false);
  assert.match(r.detail, /EPERM/);
});

test('Windows has no atomic link replace, so the swap removes and recreates', () => {
  const calls = [];
  const fsImpl = {
    rmSync: (p, o) => calls.push(['rm', p, o]),
    symlinkSync: (target, p, type) => calls.push(['symlink', target, p, type || null]),
    renameSync: (a, b) => calls.push(['rename', a, b]),
  };
  releaseGuard.repointCurrent('C:\\\\opt\\\\current', 'C:\\\\opt\\\\releases\\\\1.2.3', { fsImpl, platform: 'win32' });
  assert.deepEqual(calls.map((c) => c[0]), ['rm', 'symlink']);
  assert.equal(calls[1][3], 'junction', 'a junction needs no privilege; a directory symlink does');

  calls.length = 0;
  releaseGuard.repointCurrent('/opt/current', '/opt/releases/1.2.3', { fsImpl, platform: 'linux' });
  assert.deepEqual(calls.map((c) => c[0]), ['rm', 'symlink', 'rename'], 'POSIX keeps the atomic rename');
});

test('the in-process guard counts starts and then rolls back', () => {
  const files = new Map();
  const dirs = new Set(['/opt/releases/1.0.0']);
  const fsImpl = {
    readFileSync: (p) => {
      if (!files.has(String(p))) { const e = new Error('ENOENT'); e.code = 'ENOENT'; throw e; }
      return files.get(String(p));
    },
    writeFileSync: (p, v) => files.set(String(p), String(v)),
    rmSync: (p) => files.delete(String(p)),
    symlinkSync: (target, p) => files.set(`link:${p}`, String(target)),
    renameSync: (a, b) => { files.set(`link:${b}`, files.get(`link:${a}`)); files.delete(`link:${a}`); },
    statSync: (p) => {
      if (!dirs.has(String(p))) { const e = new Error('ENOENT'); e.code = 'ENOENT'; throw e; }
      return { isDirectory: () => true };
    },
  };
  const opts = { releasesDir: '/opt/releases', currentLink: '/opt/current', attempts: 3, fsImpl, platform: 'linux' };

  assert.equal(releaseGuard.enforceStartup(opts).action, 'none', 'nothing is waiting to prove itself');

  releaseGuard.markPending('/opt/releases', '2.0.0', { fsImpl });
  files.set('/opt/releases/.previous', '/opt/releases/1.0.0');

  assert.deepEqual(
    [1, 2, 3].map(() => releaseGuard.enforceStartup(opts).action),
    ['counted', 'counted', 'counted']
  );
  const verdict = releaseGuard.enforceStartup(opts);
  assert.equal(verdict.action, 'rolled-back');
  assert.equal(verdict.previous, '/opt/releases/1.0.0');
  assert.equal(files.get('link:/opt/current'), '/opt/releases/1.0.0');
  assert.equal(files.has('/opt/releases/.pending'), false, 'the marker is cleared, not re-armed');
});

test('out of attempts with nothing to roll back to, the loop stays visible', () => {
  const files = new Map();
  const fsImpl = {
    readFileSync: (p) => {
      if (!files.has(String(p))) { const e = new Error('ENOENT'); e.code = 'ENOENT'; throw e; }
      return files.get(String(p));
    },
    writeFileSync: (p, v) => files.set(String(p), String(v)),
    rmSync: (p) => files.delete(String(p)),
    symlinkSync: () => { throw new Error('must not repoint anything'); },
    statSync: () => { const e = new Error('ENOENT'); e.code = 'ENOENT'; throw e; },
  };
  files.set('/opt/releases/.pending', '2.0.0\n9\n');
  const verdict = releaseGuard.enforceStartup({ releasesDir: '/opt/releases', currentLink: '/opt/current', attempts: 3, fsImpl });
  assert.equal(verdict.action, 'exhausted');
  assert.equal(files.has('/opt/releases/.pending'), false);
});

test('a launchd job is detected, and Windows waits for the installer to say so', () => {
  const noFiles = () => false;
  assert.equal(detectManaged({ env: { XPC_SERVICE_NAME: 'com.blueeye.agent' }, fileExists: noFiles }), 'launchd');
  assert.equal(detectManaged({ env: { XPC_SERVICE_NAME: '0' }, fileExists: noFiles }), 'unmanaged', 'an interactive shell is not a job');
  assert.equal(detectManaged({ env: { BLUEEYE_RUNTIME: 'windows-service' }, fileExists: noFiles }), 'windows-service');
  assert.equal(detectManaged({ env: {}, fileExists: noFiles }), 'unmanaged', 'a Windows host without the marker declines updates, as before');
  assert.equal(isSelfUpdatable('windows-service'), true);
  assert.equal(isSelfUpdatable('launchd'), true);
  assert.equal(isSelfUpdatable('docker'), false);
  assert.equal(isSelfUpdatable('unmanaged'), false);
});
