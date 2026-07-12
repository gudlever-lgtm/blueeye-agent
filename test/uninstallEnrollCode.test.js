'use strict';

// uninstall.sh must clear the stored one-time enrollment code so it can never be
// reused on a later re-install (and rejected by the server as expired/exhausted).
// The code lives in a systemd drop-in (${UNIT}.d/20-enroll.conf); the risky case is
// an ORPHANED drop-in — unit file already gone — which older uninstall.sh left behind
// because the removal was gated on the unit file's existence.
//
// These drive the REAL script in a sandbox (temp UNIT/state/log dirs, stubbed
// systemctl/docker on PATH). The script's teardown is root-gated, so skip when the
// test runner isn't root or bash isn't available rather than report a false failure.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const REPO_ROOT = path.join(__dirname, '..');
const UNINSTALL = path.join(REPO_ROOT, 'uninstall.sh');
const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
const haveBash = spawnSync('bash', ['-c', 'exit 0']).status === 0;
const SKIP = !isRoot || !haveBash;
const skipReason = !haveBash ? 'bash unavailable' : 'must run as root (teardown is root-gated)';

// Build a sandbox with no-op systemctl/docker stubs and run uninstall.sh --yes
// against temp paths. Returns { unitDir } so the caller can assert on the drop-in.
function runUninstall({ makeUnitFile }) {
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'blueeye-uninstall-'));
  const stub = path.join(sandbox, 'bin');
  fs.mkdirSync(stub, { recursive: true });
  for (const name of ['systemctl', 'docker']) {
    const p = path.join(stub, name);
    fs.writeFileSync(p, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  }

  const unit = path.join(sandbox, 'blueeye-agent.service');
  const unitDir = `${unit}.d`;
  fs.mkdirSync(unitDir, { recursive: true });
  fs.writeFileSync(path.join(unitDir, '20-enroll.conf'),
    '[Service]\nEnvironment=BLUEEYE_ENROLLMENT_CODE=STALE-CODE\n');
  if (makeUnitFile) fs.writeFileSync(unit, '[Unit]\n');

  const res = spawnSync('bash', [UNINSTALL, '--yes'], {
    env: {
      ...process.env,
      PATH: `${stub}:${process.env.PATH}`,
      UNIT: unit,
      SERVICE_NAME: 'blueeye-agent',
      BLUEEYE_INSTALL_DIR: path.join(sandbox, 'absent-install'),
      BLUEEYE_STATE_DIR: path.join(sandbox, 'absent-state'),
      BLUEEYE_LOG_DIR: path.join(sandbox, 'absent-log'),
      CONTAINER: '__absent__', IMAGE: '__absent__', TOKEN_VOLUME: '__absent__',
    },
    encoding: 'utf8',
  });
  return { sandbox, unit, unitDir, res };
}

test('uninstall clears an ORPHANED enrollment-code drop-in (unit file already gone)', { skip: SKIP && skipReason }, () => {
  const { sandbox, unitDir, res } = runUninstall({ makeUnitFile: false });
  try {
    assert.equal(res.status, 0, res.stderr);
    assert.equal(fs.existsSync(path.join(unitDir, '20-enroll.conf')), false, 'enrollment code must be cleared');
    assert.equal(fs.existsSync(unitDir), false, 'empty drop-in dir should be removed');
  } finally {
    fs.rmSync(sandbox, { recursive: true, force: true });
  }
});

test('uninstall clears the enrollment-code drop-in in a normal systemd removal', { skip: SKIP && skipReason }, () => {
  const { sandbox, unit, unitDir, res } = runUninstall({ makeUnitFile: true });
  try {
    assert.equal(res.status, 0, res.stderr);
    assert.equal(fs.existsSync(path.join(unitDir, '20-enroll.conf')), false, 'enrollment code must be cleared');
    assert.equal(fs.existsSync(unit), false, 'unit file should be removed');
  } finally {
    fs.rmSync(sandbox, { recursive: true, force: true });
  }
});
