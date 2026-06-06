'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { renderHsflowdConf, hsflowdOptions } = require('../src/sflow/hsflowdConfig');
const { createHsflowdManager, STATES } = require('../src/sflow/hsflowd');

// ---- config renderer ------------------------------------------------------

test('renderHsflowdConf points the collector at the local agent by default', () => {
  const conf = renderHsflowdConf();
  assert.match(conf, /collector \{ ip = 127\.0\.0\.1 {2}udpport = 6343 \}/);
  assert.match(conf, /sampling = 256/);
  assert.match(conf, /polling = 20/);
  assert.match(conf, /pcap \{ dev = eth0 \}/);
});

test('renderHsflowdConf honours overrides', () => {
  const conf = renderHsflowdConf({ collectorPort: 7000, samplingRate: 1000, pollingSecs: 30, device: 'ens5' });
  assert.match(conf, /udpport = 7000/);
  assert.match(conf, /sampling = 1000/);
  assert.match(conf, /polling = 30/);
  assert.match(conf, /pcap \{ dev = ens5 \}/);
});

test('renderHsflowdConf rejects unsafe / out-of-range values (no config injection)', () => {
  const conf = renderHsflowdConf({ device: 'eth0\n  evil { }', samplingRate: -5, collectorPort: 999999 });
  assert.doesNotMatch(conf, /evil/);
  assert.match(conf, /pcap \{ dev = eth0 \}/); // fell back to default
  assert.match(conf, /sampling = 256/);
  assert.match(conf, /udpport = 6343/);
  // exactly one sflow block, no stray braces from the injected newline
  assert.equal((conf.match(/sflow \{/g) || []).length, 1);
});

test('hsflowdOptions exposes the effective, sanitised values', () => {
  assert.deepEqual(hsflowdOptions({ samplingRate: 512 }), {
    collectorIp: '127.0.0.1', collectorPort: 6343, samplingRate: 512, pollingSecs: 20, device: 'eth0',
  });
});

// ---- lifecycle manager: a scripted fake exec ------------------------------

// Builds a fake exec that matches on the command line and returns a scripted
// result, recording every call. `handlers` maps a substring -> result (or fn).
function fakeExec(handlers = []) {
  const calls = [];
  const exec = async (cmd, args = []) => {
    const line = [cmd, ...args].join(' ');
    calls.push(line);
    for (const [match, res] of handlers) {
      if (line.includes(match)) return typeof res === 'function' ? res(line) : res;
    }
    return { ok: true, exitCode: 0, spawnError: null, stdout: '', stderr: '' };
  };
  exec.calls = calls;
  return exec;
}

const OK = { ok: true, exitCode: 0, spawnError: null, stdout: '', stderr: '' };
const isActive = { ok: true, exitCode: 0, spawnError: null, stdout: 'active\n', stderr: '' };
const installed = ['command -v hsflowd', OK];
const notInstalled = ['command -v hsflowd', { ok: false, exitCode: 1, spawnError: null, stdout: '', stderr: '' }];

test('STATES is the agreed status vocabulary', () => {
  assert.deepEqual(STATES, [
    'active', 'inactive', 'failed', 'not_installed', 'install_failed', 'permission_denied', 'unknown',
  ]);
});

test('status: not installed -> not_installed', async () => {
  const m = createHsflowdManager({ exec: fakeExec([notInstalled]), platform: 'linux' });
  assert.deepEqual(await m.status(), { state: 'not_installed', detail: null });
});

test('status maps systemctl is-active', async () => {
  const m = createHsflowdManager({
    exec: fakeExec([installed, ['is-active', isActive]]),
    platform: 'linux',
  });
  assert.equal((await m.status()).state, 'active');
});

test('non-linux host -> unknown (never claims a state it cannot observe)', async () => {
  const m = createHsflowdManager({ exec: fakeExec([]), platform: 'darwin' });
  assert.equal((await m.status()).state, 'unknown');
});

test('docker runtime defers to the sidecar instead of self-managing', async () => {
  const exec = fakeExec([]);
  const m = createHsflowdManager({ exec, platform: 'linux', runtime: 'docker' });
  const r = await m.enable();
  assert.equal(r.state, 'not_installed');
  assert.match(r.detail, /sidecar/);
  assert.equal(exec.calls.length, 0, 'must not shell out on a containerised agent');
});

test('enable: builds hsflowd from source when missing, writes conf, enables+starts, reports active', async () => {
  const writes = [];
  const calls = [];
  let installedNow = false; // becomes true after `make install`
  const exec = async (cmd, args = []) => {
    const line = [cmd, ...args].join(' ');
    calls.push(line);
    if (line.includes('command -v apt-get')) return { ...OK, stdout: '/usr/bin/apt-get' };
    if (line.startsWith('apt-get install')) return OK;          // build deps
    if (line.includes('git clone')) return OK;
    if (line.startsWith('make') && line.includes(' install')) { installedNow = true; return OK; }
    if (line.startsWith('make')) return OK;                      // FEATURES build / schedule
    if (line.includes('command -v hsflowd')) return installedNow ? OK : { ok: false, exitCode: 1, stdout: '' };
    if (line.includes('is-active')) return isActive;
    return OK;
  };
  const m = createHsflowdManager({
    exec, platform: 'linux', runtime: 'systemd',
    readFile: () => null, writeFile: async (p, c) => { writes.push([p, c]); },
  });
  const r = await m.enable({ samplingRate: 512 });
  assert.equal(r.state, 'active');
  assert.equal(writes.length, 1);
  assert.equal(writes[0][0], '/etc/hsflowd.conf');
  assert.match(writes[0][1], /sampling = 512/);
  assert.ok(calls.some((c) => c.startsWith('apt-get install') && c.includes('clang') && c.includes('libpcap-dev')), 'installs build deps incl. clang');
  assert.ok(calls.some((c) => c.includes('git clone') && c.includes('host-sflow')), 'clones host-sflow');
  assert.ok(calls.some((c) => c.startsWith('make') && c.includes('FEATURES=PCAP')), 'builds the PCAP module only');
  assert.ok(calls.some((c) => c.startsWith('make') && c.includes('FEATURES=PCAP') && c.includes(' install')), 'make install carries FEATURES so mod_pcap is installed');
  assert.ok(calls.some((c) => c.startsWith('make') && c.includes(' schedule')), 'make schedule (systemd unit)');
  assert.ok(calls.some((c) => c.includes('systemctl enable hsflowd')));
  assert.ok(calls.some((c) => c.includes('systemctl restart hsflowd')));
});

test('enable is idempotent: unchanged conf on an active service does nothing', async () => {
  const desired = renderHsflowdConf({ samplingRate: 256 });
  const exec = fakeExec([installed, ['is-active', isActive]]);
  const writes = [];
  const m = createHsflowdManager({
    exec, platform: 'linux', runtime: 'systemd',
    readFile: () => desired,           // already exactly what we'd write
    writeFile: async (p, c) => writes.push([p, c]),
  });
  const r = await m.enable({ samplingRate: 256 });
  assert.equal(r.state, 'active');
  assert.equal(writes.length, 0, 'must not rewrite an identical conf');
  assert.ok(!exec.calls.some((c) => c.includes('restart')), 'must not restart when nothing changed');
});

test('enable surfaces install failure (no apt for build deps) without looping', async () => {
  const exec = fakeExec([
    notInstalled,
    ['command -v apt-get', { ok: false, exitCode: 1, stdout: '' }],
  ]);
  const m = createHsflowdManager({ exec, platform: 'linux', runtime: 'unmanaged', readFile: () => null });
  const r = await m.enable();
  assert.equal(r.state, 'install_failed');
  assert.match(r.detail, /apt-get/);
});

test('enable reports permission_denied when systemctl is refused', async () => {
  const denied = { ok: false, exitCode: 1, spawnError: null, stdout: '', stderr: 'Failed to enable: Access denied' };
  const exec = fakeExec([installed, ['systemctl enable', denied], ['is-active', isActive]]);
  const m = createHsflowdManager({
    exec, platform: 'linux', runtime: 'systemd',
    readFile: () => null, writeFile: async () => {},
  });
  const r = await m.enable();
  assert.equal(r.state, 'permission_denied');
});

test('enable retries past a transient dpkg lock on the build deps, then builds + succeeds', async () => {
  let aptCalls = 0;
  let installedNow = false;
  const exec = async (cmd, args = []) => {
    const line = [cmd, ...args].join(' ');
    if (line.includes('command -v apt-get')) return OK;
    if (line.startsWith('apt-get install')) {
      aptCalls += 1;
      if (aptCalls < 2) return { ok: false, exitCode: 100, stderr: 'E: Could not get lock /var/lib/dpkg/lock-frontend' };
      return OK;
    }
    if (line.includes('git clone')) return OK;
    if (line.startsWith('make') && line.includes(' install')) { installedNow = true; return OK; }
    if (line.startsWith('make')) return OK;
    if (line.includes('command -v hsflowd')) return installedNow ? OK : { ok: false, exitCode: 1, stdout: '' };
    if (line.includes('is-active')) return isActive;
    return OK;
  };
  const m = createHsflowdManager({
    exec, platform: 'linux', runtime: 'systemd', retryDelayMs: 1,
    readFile: () => null, writeFile: async () => {},
  });
  const r = await m.enable();
  assert.equal(r.state, 'active');
  assert.equal(aptCalls, 2, 'should retry the locked apt once');
});

test('disable stops+disables but leaves the package installed', async () => {
  const inactive = { ok: true, stdout: 'inactive\n' };
  const exec = fakeExec([installed, ['disable --now', OK], ['is-active', inactive]]);
  const m = createHsflowdManager({ exec, platform: 'linux', runtime: 'systemd' });
  const r = await m.disable();
  assert.equal(r.state, 'inactive');
  assert.ok(exec.calls.some((c) => c.includes('systemctl disable --now hsflowd')));
  assert.ok(!exec.calls.some((c) => c.includes('apt-get') && c.includes('remove')));
});

test('disable on a not-installed host is a no-op', async () => {
  const exec = fakeExec([notInstalled]);
  const m = createHsflowdManager({ exec, platform: 'linux', runtime: 'unmanaged' });
  assert.equal((await m.disable()).state, 'not_installed');
});
