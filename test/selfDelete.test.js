'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { createSelfDeleter } = require('../src/selfDelete');

test('wipeToken overwrites the token then unlinks it (0600), never leaving cleartext', () => {
  const writes = [];
  const removed = [];
  const fsImpl = {
    existsSync: () => true,
    statSync: () => ({ size: 120 }),
    writeFileSync: (p, data, opts) => writes.push({ p, len: data.length, mode: opts && opts.mode, isBuffer: Buffer.isBuffer(data) }),
    rmSync: (p) => removed.push(p),
  };
  const d = createSelfDeleter({
    installDir: '/opt/blueeye-agent',
    tokenPath: '/opt/blueeye-agent/.blueeye-agent/token',
    fsImpl,
    spawnImpl: () => ({ unref() {} }),
    logger: { warn() {} },
  });
  d.wipeToken();
  assert.equal(writes.length, 1);
  assert.equal(writes[0].isBuffer, true); // random bytes, not the token
  assert.ok(writes[0].len >= 64);
  assert.equal(writes[0].mode, 0o600);
  assert.deepEqual(removed, ['/opt/blueeye-agent/.blueeye-agent/token']);
});

test('remove() spawns a DETACHED uninstall.sh --yes with the right service + install dir', () => {
  let spawned = null;
  const d = createSelfDeleter({
    installDir: '/opt/blueeye-agent',
    serviceName: 'blueeye-agent',
    uninstallPath: '/opt/blueeye-agent/uninstall.sh',
    fsImpl: { existsSync: () => false },
    spawnImpl: (cmd, args, opts) => { spawned = { cmd, args, opts }; return { unref() {} }; },
    logger: { warn() {} },
  });
  d.remove();
  assert.equal(spawned.cmd, 'sh');
  assert.equal(spawned.opts.detached, true);
  assert.equal(spawned.opts.stdio, 'ignore');
  assert.match(spawned.args[1], /uninstall\.sh' --yes/);
  assert.match(spawned.args[1], /SERVICE_NAME='blueeye-agent'/);
  assert.match(spawned.args[1], /BLUEEYE_INSTALL_DIR='\/opt\/blueeye-agent'/);
});
