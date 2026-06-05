'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const { createSelfUpdater } = require('../src/selfUpdate');

const quiet = { info() {}, warn() {}, error() {} };

const BODY = Buffer.from('agent-source-tarball-bytes');
const SHA = crypto.createHash('sha256').update(BODY).digest('hex');

function makeFakeFs() {
  return {
    writes: [],
    removed: [],
    mkdtempSync: () => '/tmp/blueeye-update-test',
    writeFileSync(p, buf) { this.writes.push({ p, len: buf.length }); },
    rmSync(p) { this.removed.push(p); },
  };
}

function okFetch(body = BODY) {
  return async (_url, _opts) => ({ ok: true, status: 200, arrayBuffer: async () => body });
}

test('update() downloads, verifies the checksum, extracts and installs deps', async () => {
  const calls = [];
  const exec = (cmd, args, opts) => { calls.push({ cmd, args, opts }); return { status: 0 }; };
  const fsImpl = makeFakeFs();
  const updater = createSelfUpdater({ installDir: '/opt/blueeye-agent', serviceName: 'blueeye-agent', exec, fsImpl, logger: quiet });

  const out = await updater.update({ serverUrl: 'http://server', token: 'tok', expectedSha: SHA, fetchImpl: okFetch() });

  assert.equal(out.ok, true);
  assert.equal(out.sha, SHA);
  // Extracted into the install dir.
  const tar = calls.find((c) => c.cmd === 'tar');
  assert.ok(tar, 'tar was invoked');
  assert.deepEqual(tar.args.slice(-2), ['-C', '/opt/blueeye-agent']);
  // Dependencies refreshed in the install dir.
  const npm = calls.find((c) => c.cmd === 'npm');
  assert.deepEqual(npm.args, ['ci', '--omit=dev']);
  assert.equal(npm.opts.cwd, '/opt/blueeye-agent');
  // Temp dir cleaned up.
  assert.equal(fsImpl.removed.length, 1);
});

test('update() refuses to install on a checksum mismatch (no extract)', async () => {
  const calls = [];
  const exec = (cmd, args) => { calls.push({ cmd, args }); return { status: 0 }; };
  const updater = createSelfUpdater({ installDir: '/opt/x', exec, fsImpl: makeFakeFs(), logger: quiet });

  await assert.rejects(
    () => updater.update({ serverUrl: 'http://s', token: 't', expectedSha: 'a'.repeat(64), fetchImpl: okFetch() }),
    /checksum mismatch/
  );
  assert.equal(calls.find((c) => c.cmd === 'tar'), undefined, 'must not extract on mismatch');
});

test('update() throws when the download is not ok', async () => {
  const updater = createSelfUpdater({ installDir: '/opt/x', exec: () => ({ status: 0 }), fsImpl: makeFakeFs(), logger: quiet });
  const badFetch = async () => ({ ok: false, status: 500, arrayBuffer: async () => Buffer.alloc(0) });
  await assert.rejects(
    () => updater.update({ serverUrl: 'http://s', token: 't', expectedSha: SHA, fetchImpl: badFetch }),
    /download failed/
  );
});

test('update() falls back to npm install when npm ci fails', async () => {
  const calls = [];
  const exec = (cmd, args, opts) => {
    calls.push({ cmd, args, opts });
    if (cmd === 'npm' && args[0] === 'ci') return { status: 1, stderr: 'no lockfile' };
    return { status: 0 };
  };
  const updater = createSelfUpdater({ installDir: '/opt/x', exec, fsImpl: makeFakeFs(), logger: quiet });

  const out = await updater.update({ serverUrl: 'http://s', token: 't', expectedSha: SHA, fetchImpl: okFetch() });
  assert.equal(out.ok, true);
  assert.ok(calls.some((c) => c.cmd === 'npm' && c.args[0] === 'install'), 'fell back to npm install');
});

test('update() surfaces an extract failure', async () => {
  const exec = (cmd) => (cmd === 'tar' ? { status: 1, stderr: 'tar: bad' } : { status: 0 });
  const updater = createSelfUpdater({ installDir: '/opt/x', exec, fsImpl: makeFakeFs(), logger: quiet });
  await assert.rejects(
    () => updater.update({ serverUrl: 'http://s', token: 't', expectedSha: SHA, fetchImpl: okFetch() }),
    /could not extract/
  );
});

test('restart() asks systemd to restart the unit without blocking', () => {
  const calls = [];
  const exec = (cmd, args) => { calls.push({ cmd, args }); return { status: 0 }; };
  const updater = createSelfUpdater({ serviceName: 'blueeye-agent', exec, fsImpl: makeFakeFs(), logger: quiet });
  updater.restart();
  const sc = calls.find((c) => c.cmd === 'systemctl');
  assert.deepEqual(sc.args, ['--no-block', 'restart', 'blueeye-agent']);
});
