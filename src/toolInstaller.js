'use strict';

const { execFile } = require('child_process');

// Agent-enforced allowlist of diagnostic tools the agent is willing to install
// when the server asks. This is the security boundary: the server can REQUEST an
// install, but the agent only ever installs something on this list — a blank,
// unknown or unlisted tool is refused outright. So a compromised or buggy server
// can never push an arbitrary package name through the agent onto the host.
//
// Each tool maps to its package name per package manager (most are identically
// named; the exceptions — e.g. Debian's `mtr-tiny` — are spelled out). A null
// means "this manager has no package for this tool" (refused for that host).
const TOOLS = Object.freeze({
  traceroute: { apt: 'traceroute', dnf: 'traceroute', yum: 'traceroute', zypper: 'traceroute', apk: 'traceroute', pacman: 'traceroute' },
  mtr: { apt: 'mtr-tiny', dnf: 'mtr', yum: 'mtr', zypper: 'mtr', apk: 'mtr', pacman: 'mtr' },
  tcptraceroute: { apt: 'tcptraceroute', dnf: 'tcptraceroute', yum: 'tcptraceroute', zypper: null, apk: 'tcptraceroute', pacman: 'tcptraceroute' },
});

const ALLOWED = Object.freeze(Object.keys(TOOLS));

// Supported package managers in detection order, each with the fixed argv for a
// NON-interactive install. The package name is the only variable, and it always
// comes from the allowlist above — never from the wire — so there is no shell
// and nothing to interpolate from server input.
const MANAGERS = Object.freeze([
  { name: 'apt', bin: 'apt-get', refresh: ['update'], args: (pkg) => ['install', '-y', '--no-install-recommends', pkg], env: { DEBIAN_FRONTEND: 'noninteractive' } },
  { name: 'dnf', bin: 'dnf', args: (pkg) => ['install', '-y', pkg] },
  { name: 'yum', bin: 'yum', args: (pkg) => ['install', '-y', pkg] },
  { name: 'zypper', bin: 'zypper', args: (pkg) => ['--non-interactive', 'install', pkg] },
  { name: 'apk', bin: 'apk', args: (pkg) => ['add', pkg] },
  { name: 'pacman', bin: 'pacman', args: (pkg) => ['-S', '--noconfirm', pkg] },
]);

// Wraps execFile so it NEVER rejects: callers branch on the resolved shape. A
// missing binary surfaces as spawnError ('ENOENT'); a non-zero exit as exitCode.
function defaultExec(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: 180000, ...opts }, (err, stdout, stderr) => {
      resolve({
        ok: !err,
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
  return s.includes('permission denied') || s.includes('must be root') || s.includes('are you root')
    || s.includes('access denied') || s.includes('operation not permitted') || s.includes('authentication is required');
}

function isLockResult(r) {
  const s = `${r.stderr || ''}${r.stdout || ''}`.toLowerCase();
  return s.includes('could not get lock') || s.includes('unable to acquire') || s.includes('dpkg frontend')
    || s.includes('database is locked') || s.includes('unable to lock');
}

function firstLine(s) {
  return String(s || '').split('\n').map((x) => x.trim()).filter(Boolean)[0] || '';
}

// Creates the tool installer. `exec` is injectable so the whole flow is unit-
// testable without touching a real package manager.
function createToolInstaller({ logger = { info() {}, warn() {}, error() {} }, exec = defaultExec, retries = 3 } = {}) {
  // Finds the first supported package manager actually present on the host.
  async function detectManager() {
    for (const m of MANAGERS) {
      // `command -v` is a shell builtin; the bin name is from our fixed list,
      // not the wire, so there is nothing injectable here.
      const probe = await exec('sh', ['-c', `command -v ${m.bin}`]);
      if (probe.ok) return m;
    }
    return null;
  }

  // Installs an allowlisted tool. Returns a structured result (never throws):
  //   { ok, installed, tool, manager?, package?, detail? }
  async function installTool({ tool } = {}) {
    const name = String(tool || '').trim().toLowerCase();
    if (!ALLOWED.includes(name)) {
      return { ok: false, installed: false, tool: name, detail: `tool not allowed: ${name || '(none)'}` };
    }
    const mgr = await detectManager();
    if (!mgr) return { ok: false, installed: false, tool: name, detail: 'no supported package manager found' };
    const pkg = TOOLS[name][mgr.name];
    if (!pkg) return { ok: false, installed: false, tool: name, manager: mgr.name, detail: `no ${mgr.name} package for ${name}` };

    const env = { ...process.env, ...(mgr.env || {}) };
    // Refresh the index first where it matters (apt) so the package resolves;
    // best-effort — a stale index still often has the package.
    if (mgr.refresh) await exec(mgr.bin, mgr.refresh, { env });

    let last = null;
    for (let attempt = 1; attempt <= Math.max(1, retries); attempt += 1) {
      const r = await exec(mgr.bin, mgr.args(pkg), { env });
      last = r;
      if (r.ok) return { ok: true, installed: true, tool: name, manager: mgr.name, package: pkg };
      if (isPermissionResult(r)) {
        return { ok: false, installed: false, tool: name, manager: mgr.name, package: pkg, detail: `${mgr.bin} install requires root` };
      }
      // Only a transient lock is worth retrying; a genuine failure is final.
      if (attempt < retries && isLockResult(r)) continue;
      break;
    }
    return {
      ok: false, installed: false, tool: name, manager: mgr.name, package: pkg,
      detail: firstLine(last && (last.stderr || last.stdout)) || `${mgr.bin} install failed`,
    };
  }

  return { installTool, detectManager };
}

module.exports = { createToolInstaller, ALLOWED_TOOLS: ALLOWED, TOOL_PACKAGES: TOOLS };
