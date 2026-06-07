'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

const { createSelfUpdater } = require('../src/selfUpdate');
const { canonicalize } = require('../src/release/canonicalize');

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const pubPem = publicKey.export({ type: 'spki', format: 'pem' });
const sign = (obj) => crypto.sign(null, Buffer.from(canonicalize(obj)), privateKey).toString('base64');
const sha = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
const quiet = { info() {}, error() {} };

function fakeRelease(tarball, manifest, sig) {
  return {
    ok: true,
    status: 200,
    headers: {
      get(name) {
        const k = String(name).toLowerCase();
        if (k === 'x-release-manifest') return Buffer.from(JSON.stringify(manifest)).toString('base64');
        if (k === 'x-release-signature') return sig;
        return null;
      },
    },
    arrayBuffer: async () => Uint8Array.from(tarball).buffer,
  };
}

// Records fs operations so we can assert the swap sequence without a real FS.
function recordingFs(prevTarget) {
  const ops = [];
  return {
    ops,
    mkdtempSync: () => '/tmp/u',
    writeFileSync: (p) => ops.push(['write', p]),
    mkdirSync: (p) => ops.push(['mkdir', p]),
    rmSync: (p) => ops.push(['rm', p]),
    readlinkSync: () => { if (prevTarget) return prevTarget; throw new Error('ENOENT'); },
    symlinkSync: (target, link) => ops.push(['symlink', target, link]),
    renameSync: (a, b) => ops.push(['rename', a, b]),
    readdirSync: () => [],
    readFileSync: () => prevTarget || '',
  };
}

const LAYOUT = { releasesDir: '/opt/blueeye-agent/releases', currentLink: '/opt/blueeye-agent/current' };

test('a signed update with the symlink layout extracts a NEW release dir and atomically swaps current', async () => {
  const tarball = Buffer.from('agent-0.3.0-bytes');
  const manifest = { version: '0.3.0', sha256: sha(tarball), size: tarball.length };
  const sig = sign(manifest);
  const execCalls = [];
  const fsr = recordingFs('/opt/blueeye-agent/releases/0.2.0');
  const updater = createSelfUpdater({
    ...LAYOUT,
    exec: (cmd, args, opts) => { execCalls.push({ cmd, args, cwd: opts && opts.cwd }); return { status: 0 }; },
    fsImpl: fsr,
    logger: quiet,
  });

  const r = await updater.update({ serverUrl: 'http://s', token: 't', signature: sig, publicKey: pubPem, fetchImpl: async () => fakeRelease(tarball, manifest, sig) });
  assert.equal(r.version, '0.3.0');

  const tar = execCalls.find((c) => c.cmd === 'tar');
  assert.deepEqual(tar.args.slice(-2), ['-C', '/opt/blueeye-agent/releases/0.3.0']); // extracted into the NEW dir
  const npm = execCalls.find((c) => c.cmd === 'npm');
  assert.equal(npm.cwd, '/opt/blueeye-agent/releases/0.3.0'); // deps installed in the NEW dir

  // Atomic swap: a temp symlink renamed over `current`.
  assert.ok(fsr.ops.some(([op, a, b]) => op === 'symlink' && a === '/opt/blueeye-agent/releases/0.3.0' && b === '/opt/blueeye-agent/current.next'));
  assert.ok(fsr.ops.some(([op, a, b]) => op === 'rename' && a === '/opt/blueeye-agent/current.next' && b === '/opt/blueeye-agent/current'));
  // Previous release recorded for rollback.
  assert.ok(fsr.ops.some(([op, p]) => op === 'write' && p === '/opt/blueeye-agent/releases/.previous'));
});

test('rollback repoints current at the recorded previous release', () => {
  const fsr = recordingFs();
  fsr.readFileSync = () => '/opt/blueeye-agent/releases/0.2.0';
  const updater = createSelfUpdater({ ...LAYOUT, fsImpl: fsr, exec: () => ({ status: 0 }), logger: quiet });
  const r = updater.rollback();
  assert.equal(r.ok, true);
  assert.equal(r.previous, '/opt/blueeye-agent/releases/0.2.0');
  assert.ok(fsr.ops.some(([op, a, b]) => op === 'symlink' && a === '/opt/blueeye-agent/releases/0.2.0' && b === '/opt/blueeye-agent/current.next'));
  assert.ok(fsr.ops.some(([op, a, b]) => op === 'rename' && a === '/opt/blueeye-agent/current.next' && b === '/opt/blueeye-agent/current'));
});

test('rollback is a no-op result without the layout', () => {
  const updater = createSelfUpdater({ releasesDir: '', currentLink: '', fsImpl: recordingFs(), exec: () => ({ status: 0 }), logger: quiet });
  assert.equal(updater.rollback().ok, false);
});

test('without the layout, a signed update still extracts in place (back-compat)', async () => {
  const tarball = Buffer.from('agent-inplace');
  const manifest = { version: '0.3.0', sha256: sha(tarball), size: tarball.length };
  const sig = sign(manifest);
  const execCalls = [];
  const updater = createSelfUpdater({
    releasesDir: '', currentLink: '', installDir: '/opt/blueeye-agent',
    exec: (cmd, args, opts) => { execCalls.push({ cmd, args, cwd: opts && opts.cwd }); return { status: 0 }; },
    fsImpl: { mkdtempSync: () => '/tmp/u', writeFileSync() {}, rmSync() {} },
    logger: quiet,
  });
  await updater.update({ serverUrl: 'http://s', token: 't', signature: sig, publicKey: pubPem, fetchImpl: async () => fakeRelease(tarball, manifest, sig) });
  const tar = execCalls.find((c) => c.cmd === 'tar');
  assert.deepEqual(tar.args.slice(-2), ['-C', '/opt/blueeye-agent']); // in place
});
