'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { createToolInstaller, ALLOWED_TOOLS } = require('../src/toolInstaller');

// A scripted exec: `present` is the set of binaries `command -v` should find;
// `installResults` maps a manager bin to the result of its install attempt(s).
function makeExec({ present = ['apt-get'], installResults = {}, record = [] } = {}) {
  return async (cmd, args) => {
    record.push({ cmd, args });
    if (cmd === 'sh' && args[0] === '-c') {
      const bin = String(args[1]).replace('command -v ', '').trim();
      return { ok: present.includes(bin), stdout: present.includes(bin) ? `/usr/bin/${bin}` : '', stderr: '' };
    }
    // refresh (apt-get update) → benign ok
    if (cmd === 'apt-get' && args[0] === 'update') return { ok: true, stdout: '', stderr: '' };
    const res = installResults[cmd];
    if (typeof res === 'function') return res(args);
    return res || { ok: true, stdout: '', stderr: '' };
  };
}

test('refuses a tool that is not on the allowlist (no exec at all)', async () => {
  const record = [];
  const installer = createToolInstaller({ exec: makeExec({ record }) });
  const r = await installer.installTool({ tool: 'rm-rf-everything' });
  assert.equal(r.ok, false);
  assert.match(r.detail, /not allowed/);
  assert.equal(record.length, 0); // never shelled out
});

test('refuses a blank/missing tool', async () => {
  const installer = createToolInstaller({ exec: makeExec() });
  assert.equal((await installer.installTool({})).ok, false);
  assert.equal((await installer.installTool({ tool: '   ' })).ok, false);
});

test('installs traceroute via apt and maps to the apt package name', async () => {
  const record = [];
  const installer = createToolInstaller({ exec: makeExec({ present: ['apt-get'], record }) });
  const r = await installer.installTool({ tool: 'traceroute' });
  assert.equal(r.ok, true);
  assert.equal(r.installed, true);
  assert.equal(r.manager, 'apt');
  assert.equal(r.package, 'traceroute');
  const install = record.find((c) => c.cmd === 'apt-get' && c.args[0] === 'install');
  assert.deepEqual(install.args, ['install', '-y', '--no-install-recommends', 'traceroute']);
});

test('maps mtr to the distro-specific package (apt: mtr-tiny, dnf: mtr)', async () => {
  const apt = await createToolInstaller({ exec: makeExec({ present: ['apt-get'] }) }).installTool({ tool: 'mtr' });
  assert.equal(apt.package, 'mtr-tiny');
  const dnf = await createToolInstaller({ exec: makeExec({ present: ['dnf'] }) }).installTool({ tool: 'mtr' });
  assert.equal(dnf.manager, 'dnf');
  assert.equal(dnf.package, 'mtr');
});

test('surfaces a permission error as a distinct, root-hinting reason', async () => {
  const installer = createToolInstaller({
    exec: makeExec({ present: ['apt-get'], installResults: { 'apt-get': (args) => (args[0] === 'update' ? { ok: true } : { ok: false, stderr: 'E: Could not open lock file - Permission denied' }) } }),
  });
  const r = await installer.installTool({ tool: 'traceroute' });
  assert.equal(r.ok, false);
  assert.match(r.detail, /requires root/);
});

test('reports when no supported package manager is present', async () => {
  const installer = createToolInstaller({ exec: makeExec({ present: [] }) });
  const r = await installer.installTool({ tool: 'traceroute' });
  assert.equal(r.ok, false);
  assert.match(r.detail, /no supported package manager/);
});

test('refuses a tool with no package for the detected manager (tcptraceroute on zypper)', async () => {
  const installer = createToolInstaller({ exec: makeExec({ present: ['zypper'] }) });
  const r = await installer.installTool({ tool: 'tcptraceroute' });
  assert.equal(r.ok, false);
  assert.match(r.detail, /no zypper package/);
});

test('the allowlist is the documented diagnostic set', () => {
  assert.deepEqual([...ALLOWED_TOOLS].sort(), ['mtr', 'tcptraceroute', 'traceroute']);
});
