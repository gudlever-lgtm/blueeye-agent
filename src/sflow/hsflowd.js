'use strict';

const { execFile } = require('child_process');
const fs = require('fs');
const { renderHsflowdConf } = require('./hsflowdConfig');

// Self-managed lifecycle for the Host sFlow daemon (hsflowd) on a Linux host the
// agent runs ON. On enable it installs hsflowd if missing, renders
// /etc/hsflowd.conf pointed at the local collector, and enables+starts the
// service — then reports the ACTUAL state it observes. Everything is idempotent
// (re-enable / re-disable are no-ops that just re-report) and every OS
// interaction (command exec, file IO) is injectable, so the state machine is
// fully unit-testable without touching a real system.
//
// Privilege model: the agent already runs with the privilege it needs for
// network probing, and uses that same privilege here (apt / writing the conf /
// systemctl). A genuine permission error is surfaced as its own distinct state
// rather than retried forever.
//
// States (mirror the server's status vocabulary):
//   active | inactive | failed | not_installed | install_failed |
//   permission_denied | unknown
const STATES = Object.freeze([
  'active', 'inactive', 'failed', 'not_installed', 'install_failed', 'permission_denied', 'unknown',
]);

const CONF_PATH = '/etc/hsflowd.conf';
const SERVICE = 'hsflowd';
const silentLogger = { info() {}, warn() {}, error() {} };

// Wraps execFile so it NEVER rejects: callers branch on the resolved shape. A
// missing binary surfaces as spawnError (e.g. 'ENOENT'); a non-zero exit as
// exitCode.
function defaultExec(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: 180000, ...opts }, (err, stdout, stderr) => {
      resolve({
        ok: !err,
        exitCode: err && typeof err.code === 'number' ? err.code : err ? null : 0,
        spawnError: err && typeof err.code === 'string' ? err.code : null,
        stdout: String(stdout || ''),
        stderr: String(stderr || ''),
      });
    });
  });
}

function isPermissionResult(r) {
  if (!r) return false;
  if (r.spawnError === 'EACCES' || r.spawnError === 'EPERM') return true;
  const s = `${r.stderr || ''}`.toLowerCase();
  return (
    s.includes('permission denied') ||
    s.includes('must be root') ||
    s.includes('are you root') ||
    s.includes('access denied') ||
    s.includes('operation not permitted') ||
    s.includes('authentication is required')
  );
}

function isDpkgLockResult(r) {
  const s = `${r.stderr || ''}${r.stdout || ''}`.toLowerCase();
  return s.includes('could not get lock') || s.includes('dpkg frontend') || s.includes('unable to acquire');
}

function firstLine(s) {
  const line = String(s || '').split('\n').map((x) => x.trim()).find(Boolean);
  return line ? line.slice(0, 200) : null;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function createHsflowdManager({
  exec = defaultExec,
  readFile = (p) => {
    try { return fs.readFileSync(p, 'utf8'); } catch { return null; }
  },
  writeFile = (p, c) => fs.promises.writeFile(p, c),
  platform = process.platform,
  // capabilities.managed: 'systemd' | 'unmanaged' | 'docker'. A containerised
  // agent cannot apt-install onto / control the host's systemd, so it defers to
  // the hsflowd sidecar instead of trying.
  runtime = 'unmanaged',
  logger = silentLogger,
  confPath = CONF_PATH,
  installRetries = 3,
  retryDelayMs = 2000,
} = {}) {
  const result = (state, detail = null) => ({ state, detail });

  async function isInstalled() {
    const r = await exec('sh', ['-c', `command -v ${SERVICE} || test -x /usr/sbin/${SERVICE}`]);
    return r.ok;
  }

  // Maps `systemctl is-active` to our vocabulary. Returns 'permission_denied'
  // when systemctl refuses, 'unknown' when systemd isn't present.
  async function activeState() {
    const r = await exec('systemctl', ['is-active', SERVICE]);
    if (isPermissionResult(r)) return 'permission_denied';
    if (r.spawnError === 'ENOENT') return 'unknown'; // no systemd on this host
    const s = r.stdout.trim();
    if (s === 'active' || s === 'activating' || s === 'reloading') return 'active';
    if (s === 'failed') return 'failed';
    return 'inactive'; // inactive | deactivating | unknown
  }

  // Observe-only: the current state, no side effects.
  async function status() {
    try {
      if (platform !== 'linux') return result('unknown', 'hsflowd is Linux-only');
      if (runtime === 'docker') return result('not_installed', 'containerised agent — run the hsflowd sidecar');
      if (!(await isInstalled())) return result('not_installed');
      return result(await activeState());
    } catch (err) {
      return result('unknown', err && err.message);
    }
  }

  // apt-get install with retry on the dpkg lock. Returns { ok } on success or
  // { ok:false, state, detail } on a terminal failure.
  async function install() {
    const haveApt = await exec('sh', ['-c', 'command -v apt-get']);
    if (!haveApt.ok) return { ok: false, ...result('install_failed', 'apt-get is not available on this host') };

    const env = { ...process.env, DEBIAN_FRONTEND: 'noninteractive' };
    let last = null;
    for (let attempt = 1; attempt <= installRetries; attempt += 1) {
      // eslint-disable-next-line no-await-in-loop
      const r = await exec('apt-get', ['install', '-y', SERVICE], { env });
      last = r;
      if (r.ok) break;
      if (isPermissionResult(r)) return { ok: false, ...result('permission_denied', 'apt-get install requires root') };
      if (isDpkgLockResult(r) && attempt < installRetries) {
        logger.warn(`hsflowd: apt is locked, retrying (${attempt}/${installRetries})...`);
        // eslint-disable-next-line no-await-in-loop
        await sleep(retryDelayMs * attempt);
        continue;
      }
      break; // some other apt failure — stop, do not loop
    }
    // Verify by presence rather than trusting the exit code alone.
    if (await isInstalled()) return { ok: true };
    return { ok: false, ...result('install_failed', firstLine(last && (last.stderr || last.stdout)) || 'apt-get install failed') };
  }

  // Converge hsflowd to enabled+running with the given collector/sampling config.
  // Idempotent: an unchanged conf on an already-active service is a no-op.
  async function enable(opts = {}) {
    try {
      if (platform !== 'linux') return result('unknown', 'hsflowd is Linux-only');
      if (runtime === 'docker') {
        return result('not_installed', 'containerised agent — run the hsflowd sidecar (docker-compose.hsflowd.yml)');
      }

      if (!(await isInstalled())) {
        const inst = await install();
        if (!inst.ok) return result(inst.state, inst.detail);
        logger.info('hsflowd: installed.');
      }

      const desired = renderHsflowdConf(opts);
      const confChanged = readFile(confPath) !== desired;
      if (confChanged) {
        try {
          await writeFile(confPath, desired);
        } catch (err) {
          if (err && (err.code === 'EACCES' || err.code === 'EPERM')) {
            return result('permission_denied', `cannot write ${confPath}`);
          }
          return result('failed', `cannot write ${confPath}: ${err && err.message}`);
        }
      } else if ((await activeState()) === 'active') {
        return result('active'); // nothing to do
      }

      const en = await exec('systemctl', ['enable', SERVICE]);
      if (isPermissionResult(en)) return result('permission_denied', 'systemctl enable failed');

      // restart picks up a changed conf; start is enough for a stopped service.
      const action = confChanged ? 'restart' : 'start';
      const st = await exec('systemctl', [action, SERVICE]);
      if (isPermissionResult(st)) return result('permission_denied', `systemctl ${action} failed`);

      return result(await activeState());
    } catch (err) {
      return result('unknown', err && err.message);
    }
  }

  // Stop + disable, but leave the package installed for a fast re-enable.
  // Idempotent: a not-installed host is a no-op.
  async function disable() {
    try {
      if (platform !== 'linux') return result('unknown', 'hsflowd is Linux-only');
      if (runtime === 'docker') return result('not_installed', 'containerised agent — manage the hsflowd sidecar');
      if (!(await isInstalled())) return result('not_installed');

      const r = await exec('systemctl', ['disable', '--now', SERVICE]);
      if (isPermissionResult(r)) return result('permission_denied', 'systemctl disable failed');
      return result(await activeState());
    } catch (err) {
      return result('unknown', err && err.message);
    }
  }

  return { status, enable, disable };
}

module.exports = { createHsflowdManager, STATES };
