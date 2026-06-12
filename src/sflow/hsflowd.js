'use strict';

const { execFile } = require('child_process');
const fs = require('fs');
const os = require('os');
const { renderHsflowdConf, pickSamplingDevice, MANAGED_MARKER } = require('./hsflowdConfig');

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
// hsflowd is NOT in the Debian/Ubuntu archives — it ships from sflow.org. So we
// build it from source (github.com/sflow/host-sflow) at enable time.
const REPO_URL = 'https://github.com/sflow/host-sflow';
const BUILD_DIR = '/usr/local/src/host-sflow';
// host-sflow builds its core sFlow lib with gcc but its Linux modules with
// clang, and links libpcap for the PCAP (packet-sampling) module.
const BUILD_DEPS = ['git', 'build-essential', 'clang', 'libpcap-dev'];
// Build ONLY the PCAP module — packet sampling, i.e. the src/dst flow data. The
// "HOST" meta-feature pulls in KVM/OVS/NFLOG/DOCKER/DBUS and their heavy dev
// dependencies (libvirt-dev, …), none of which we need: the agent already
// reports interface counters, and core hsflowd still polls counters anyway.
const BUILD_FEATURES = 'PCAP';
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
  // For picking the sampled NIC when none is configured / the configured one is
  // stale. Injectable so the resolution is unit-testable without a real host.
  listInterfaces = () => os.networkInterfaces(),
  readRoute = () => { try { return fs.readFileSync('/proc/net/route', 'utf8'); } catch { return ''; } },
  platform = process.platform,
  // capabilities.managed: 'systemd' | 'unmanaged' | 'docker'. A containerised
  // agent cannot apt-install onto / control the host's systemd, so it defers to
  // the hsflowd sidecar instead of trying.
  runtime = 'unmanaged',
  logger = silentLogger,
  confPath = CONF_PATH,
  repoUrl = REPO_URL,
  buildDir = BUILD_DIR,
  gitRef = null,
  installRetries = 3,
  retryDelayMs = 2000,
} = {}) {
  const result = (state, detail = null) => ({ state, detail });

  async function isInstalled() {
    const r = await exec('sh', ['-c', `command -v ${SERVICE} || test -x /usr/sbin/${SERVICE} || test -x /usr/local/sbin/${SERVICE}`]);
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

  // Whether the host's hsflowd conf was written by THIS agent (the managed
  // marker). The in-memory "we enabled it" flag does not survive an agent
  // restart, so this is how a fresh process recognises an exporter a previous
  // run provisioned — a delete or a source change can then stop it, while a
  // pre-existing operator-managed hsflowd is never touched. Observe-only.
  function isManaged() {
    if (platform !== 'linux' || runtime === 'docker') return false;
    const conf = readFile(confPath);
    return typeof conf === 'string' && conf.includes(MANAGED_MARKER);
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

  // apt-get install with retry on the dpkg lock. Returns { ok:true } or
  // { ok:false, state, detail }. Used for hsflowd's BUILD dependencies (these
  // ARE in apt) — not for hsflowd itself.
  async function aptInstall(packages) {
    const haveApt = await exec('sh', ['-c', 'command -v apt-get']);
    if (!haveApt.ok) return { ok: false, state: 'install_failed', detail: 'apt-get is not available on this host' };

    const env = { ...process.env, DEBIAN_FRONTEND: 'noninteractive' };
    let last = null;
    for (let attempt = 1; attempt <= installRetries; attempt += 1) {
      // eslint-disable-next-line no-await-in-loop
      const r = await exec('apt-get', ['install', '-y', '--no-install-recommends', ...packages], { env });
      last = r;
      if (r.ok) return { ok: true };
      if (isPermissionResult(r)) return { ok: false, state: 'permission_denied', detail: 'apt-get install requires root' };
      if (isDpkgLockResult(r) && attempt < installRetries) {
        logger.warn(`hsflowd: apt is locked, retrying (${attempt}/${installRetries})...`);
        // eslint-disable-next-line no-await-in-loop
        await sleep(retryDelayMs * attempt);
        continue;
      }
      break; // some other apt failure — stop, do not loop
    }
    return { ok: false, state: 'install_failed', detail: firstLine(last && (last.stderr || last.stdout)) || 'apt-get install failed' };
  }

  // hsflowd is NOT packaged in Debian/Ubuntu — it ships from sflow.org. So build
  // it from source: install the build deps (which ARE in apt), clone, then
  // `make FEATURES="HOST PCAP"` (PCAP = packet sampling — the src/dst data, not
  // just counters), `make install`, and `make schedule` to register the systemd
  // service. Idempotent: an existing checkout/binary is reused. Returns
  // { ok:true } or { ok:false, state, detail }.
  async function install() {
    const deps = await aptInstall(BUILD_DEPS);
    if (!deps.ok) return deps;

    // Reuse an existing checkout if present (so re-enable doesn't re-clone).
    const branch = gitRef ? `--branch ${gitRef} ` : '';
    const clone = await exec('sh', ['-c',
      `test -d ${buildDir}/.git || git clone --depth 1 ${branch}${repoUrl} ${buildDir}`]);
    if (isPermissionResult(clone)) return { ok: false, state: 'permission_denied', detail: 'cannot write the build directory' };
    if (!clone.ok) return { ok: false, state: 'install_failed', detail: `git clone failed: ${firstLine(clone.stderr) || 'unknown'}` };

    // FEATURES must be passed to EVERY target (build + install + schedule): the
    // install target ships only the modules in the current feature set, so
    // without it mod_pcap.so is never installed and hsflowd runs with no packet
    // sampling. `make schedule` then installs+enables the systemd unit.
    const feat = `FEATURES=${BUILD_FEATURES}`;
    for (const step of [[feat], [feat, 'install'], [feat, 'schedule']]) {
      // eslint-disable-next-line no-await-in-loop
      const r = await exec('make', ['-C', buildDir, ...step]);
      if (isPermissionResult(r)) return { ok: false, state: 'permission_denied', detail: `make ${step[step.length - 1]} failed` };
      if (!r.ok) return { ok: false, state: 'install_failed', detail: `make ${step.join(' ')} failed: ${firstLine(r.stderr) || 'unknown'}` };
    }

    if (await isInstalled()) return { ok: true };
    return { ok: false, state: 'install_failed', detail: 'built hsflowd but the binary was not found' };
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

      // Resolve which NIC hsflowd samples: honour an explicit, existing device;
      // otherwise auto-detect (default route) so a stale/blank 'eth0' on a cloud
      // instance doesn't silently export counters only and produce no flows.
      const device = pickSamplingDevice({
        configured: opts.device || null,
        interfaces: Object.keys(listInterfaces() || {}),
        routeText: readRoute(),
      });
      if (device && device !== opts.device) {
        logger.info(`hsflowd: sampling interface '${device}'${opts.device ? ` (configured '${opts.device}' not found)` : ' (auto-detected)'}`);
      }
      const desired = renderHsflowdConf(device ? { ...opts, device } : opts);
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

  return { status, enable, disable, isManaged };
}

module.exports = { createHsflowdManager, STATES };
