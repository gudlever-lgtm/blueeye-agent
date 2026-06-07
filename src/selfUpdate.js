'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { verifyManifest } = require('./release/verifyManifest');

// Self-update for systemd-managed agents. Given the server URL + token and the
// command's expectations, it:
//   1. downloads the signed release (or legacy source bundle),
//   2. verifies it — Ed25519 signature over the manifest + sha256 + version for a
//      signed release (fails CLOSED), or sha256 for the legacy bundle,
//   3. INSTALLS it: with the versioned `releases/<v>` + `current` symlink layout
//      it extracts a NEW release dir and atomically repoints `current` (keeping
//      the previous release for rollback); otherwise it extracts in place,
//   4. installs deps (npm ci --omit=dev, falling back to npm install),
//   5. (caller then) asks systemd to restart onto the new code.
//
// Docker/unmanaged agents are not updated here (the host rebuilds those) — the
// caller checks `managed` first. Everything is injectable for tests.
function createSelfUpdater({
  installDir = path.join(__dirname, '..'),
  serviceName = process.env.BLUEEYE_SERVICE_NAME || 'blueeye-agent',
  // Atomic, rollback-able layout (set by the systemd installer): versioned
  // release dirs + a `current` symlink the service runs from. When BOTH are set
  // (and a version is known), an update extracts a new release dir and atomically
  // repoints `current`. Unset -> legacy in-place extract over installDir.
  releasesDir = process.env.BLUEEYE_RELEASES_DIR || '',
  currentLink = process.env.BLUEEYE_CURRENT_LINK || '',
  keepReleases = 3,
  exec = spawnSync,
  fsImpl = fs,
  logger = console,
} = {}) {
  function fail(code, message) {
    const err = new Error(message);
    err.code = code;
    return err;
  }

  // Downloads + verifies + installs the new release. Throws (with a `.code`) on
  // any failure; resolves with { ok, sha, version } on success. Does NOT restart.
  async function update({ serverUrl, token, expectedSha, expectedVersion, signature, publicKey, fetchImpl }) {
    const doFetch = fetchImpl || (typeof fetch === 'function' ? fetch : null);
    if (!doFetch) throw fail('NO_FETCH', 'no fetch implementation available');

    // A `signature` in the command marks a SIGNED release: download the signed
    // artifact and verify its Ed25519 signature (authenticity) before anything
    // touches disk. Without one, fall back to the legacy source bundle (sha256
    // only) so existing deployments keep working.
    const signed = !!signature;
    const base = String(serverUrl || '').replace(/\/+$/, '');
    const url = `${base}${signed ? '/enroll/agent-release.tgz' : '/enroll/agent-source.tgz'}`;
    logger.info(`[update] downloading ${url}`);
    const res = await doFetch(url, { headers: { Authorization: `Bearer ${token}` } });
    if (!res || !res.ok) throw fail('DOWNLOAD_FAILED', `download failed (HTTP ${res ? res.status : '?'})`);

    const buf = Buffer.from(await res.arrayBuffer());
    const sha = crypto.createHash('sha256').update(buf).digest('hex');
    let version = expectedVersion || null;
    if (signed) {
      // Fail CLOSED: never install a signed release we can't authenticate.
      if (!publicKey) throw fail('NO_PUBLIC_KEY', 'no release public key configured — refusing to install a signed release');
      const header = (name) => (res.headers && typeof res.headers.get === 'function' ? res.headers.get(name) : null);
      const manifestB64 = header('x-release-manifest');
      const sig = header('x-release-signature') || signature;
      if (!manifestB64 || !sig) throw fail('NO_MANIFEST', 'signed release is missing its manifest/signature');
      let manifest;
      try {
        manifest = JSON.parse(Buffer.from(manifestB64, 'base64').toString('utf8'));
      } catch {
        throw fail('BAD_MANIFEST', 'release manifest is not valid JSON');
      }
      if (!verifyManifest(manifest, sig, publicKey)) {
        throw fail('SIGNATURE_INVALID', 'release signature did not verify — refusing to install');
      }
      if (manifest.sha256 !== sha) {
        throw fail('CHECKSUM_MISMATCH', `checksum mismatch (manifest ${manifest.sha256}, got ${sha}) — refusing to install`);
      }
      if (expectedVersion && manifest.version !== expectedVersion) {
        throw fail('VERSION_MISMATCH', `version mismatch (expected ${expectedVersion}, got ${manifest.version}) — refusing to install`);
      }
      version = manifest.version;
      logger.info(`[update] signature OK (v${manifest.version}, sha ${sha.slice(0, 12)}…)`);
    } else {
      if (expectedSha && sha !== expectedSha) {
        throw fail('CHECKSUM_MISMATCH', `checksum mismatch (expected ${expectedSha}, got ${sha}) — refusing to install`);
      }
      logger.info(`[update] checksum OK (${sha})`);
    }

    installRelease(buf, version);
    return { ok: true, sha, version };
  }

  // Writes the verified tarball to a temp file and installs it — atomically
  // (versioned swap) when the layout is configured and a version is known,
  // otherwise in place.
  function installRelease(buf, version) {
    const tmp = fsImpl.mkdtempSync(path.join(os.tmpdir(), 'blueeye-update-'));
    const tgz = path.join(tmp, 'agent.tgz');
    fsImpl.writeFileSync(tgz, buf);
    try {
      if (releasesDir && currentLink && version) atomicInstall(tgz, version);
      else inPlaceInstall(tgz);
    } finally {
      try { fsImpl.rmSync(tmp, { recursive: true, force: true }); } catch { /* best-effort cleanup */ }
    }
  }

  function npmInstall(cwd) {
    let r = exec('npm', ['ci', '--omit=dev'], { cwd, encoding: 'utf8' });
    if (!r || r.status !== 0) {
      r = exec('npm', ['install', '--omit=dev'], { cwd, encoding: 'utf8' });
      if (!r || r.status !== 0) throw fail('NPM_FAILED', `dependency install failed: ${(r && (r.stderr || r.error)) || 'unknown error'}`);
    }
  }

  function inPlaceInstall(tgz) {
    logger.info(`[update] extracting to ${installDir}`);
    const r = exec('tar', ['-xzf', tgz, '-C', installDir], { encoding: 'utf8' });
    if (!r || r.status !== 0) throw fail('EXTRACT_FAILED', `could not extract source: ${(r && (r.stderr || r.error)) || 'unknown error'}`);
    logger.info('[update] installing dependencies (npm ci --omit=dev)');
    npmInstall(installDir);
  }

  // Blue/green: extract into releases/<version>, install deps there, then
  // atomically repoint `current` (rename over the symlink is atomic on POSIX), so
  // a crash mid-update never leaves a half-written LIVE tree. Records the prior
  // release for rollback() and prunes old ones.
  function atomicInstall(tgz, version) {
    const newDir = path.join(releasesDir, String(version));
    try { fsImpl.mkdirSync(releasesDir, { recursive: true }); } catch { /* exists */ }
    try { fsImpl.rmSync(newDir, { recursive: true, force: true }); } catch { /* none */ }
    fsImpl.mkdirSync(newDir, { recursive: true });

    logger.info(`[update] extracting to ${newDir}`);
    const r = exec('tar', ['-xzf', tgz, '-C', newDir], { encoding: 'utf8' });
    if (!r || r.status !== 0) throw fail('EXTRACT_FAILED', `could not extract source: ${(r && (r.stderr || r.error)) || 'unknown error'}`);
    logger.info('[update] installing dependencies (npm ci --omit=dev)');
    npmInstall(newDir);

    let prev = null;
    try { prev = fsImpl.readlinkSync(currentLink); } catch { /* first install / not a link */ }

    logger.info(`[update] swapping ${currentLink} -> ${newDir}`);
    const tmpLink = `${currentLink}.next`;
    try { fsImpl.rmSync(tmpLink, { force: true }); } catch { /* none */ }
    fsImpl.symlinkSync(newDir, tmpLink);
    fsImpl.renameSync(tmpLink, currentLink); // atomic replace of the symlink

    if (prev && path.resolve(prev) !== path.resolve(newDir)) {
      try { fsImpl.writeFileSync(path.join(releasesDir, '.previous'), prev); } catch { /* best-effort */ }
    }
    pruneReleases(newDir, prev);
  }

  // Keep current + previous (+ up to keepReleases total); remove older dirs.
  // Best-effort — pruning must never fail an otherwise-good update.
  function pruneReleases(currentDir, prevDir) {
    try {
      const keep = new Set([currentDir, prevDir].filter(Boolean).map((p) => path.basename(p)));
      const entries = fsImpl.readdirSync(releasesDir).filter((n) => !n.startsWith('.'));
      if (entries.length <= keepReleases) return;
      const removable = entries.filter((n) => !keep.has(n)).sort(compareVersions);
      const overflow = entries.length - keepReleases;
      for (const n of removable.slice(0, overflow)) {
        try { fsImpl.rmSync(path.join(releasesDir, n), { recursive: true, force: true }); } catch { /* best-effort */ }
      }
    } catch { /* best-effort */ }
  }

  // Repoints `current` back to the previously-installed release (recorded at swap
  // time). Returns { ok, previous? , reason? }. For an operator/watchdog to call
  // if the new release fails to come up.
  function rollback() {
    if (!releasesDir || !currentLink) return { ok: false, reason: 'no-layout' };
    let prev = '';
    try { prev = String(fsImpl.readFileSync(path.join(releasesDir, '.previous'), 'utf8')).trim(); } catch { return { ok: false, reason: 'no-previous' }; }
    if (!prev) return { ok: false, reason: 'no-previous' };
    const tmpLink = `${currentLink}.next`;
    try { fsImpl.rmSync(tmpLink, { force: true }); } catch { /* none */ }
    fsImpl.symlinkSync(prev, tmpLink);
    fsImpl.renameSync(tmpLink, currentLink);
    logger.info(`[update] rolled back ${currentLink} -> ${prev}`);
    return { ok: true, previous: prev };
  }

  // Asks systemd to restart this unit. --no-block enqueues the job in PID 1, so it
  // completes even though this process is terminated during the stop phase
  // (systemd then starts a fresh instance running the just-installed code).
  function restart() {
    logger.info(`[update] requesting restart of ${serviceName}`);
    return exec('systemctl', ['--no-block', 'restart', serviceName], { encoding: 'utf8' });
  }

  return { update, restart, rollback, installRelease };
}

// Numeric, dotted-version compare for prune ordering (oldest first).
function compareVersions(a, b) {
  const pa = String(a).split('.');
  const pb = String(b).split('.');
  for (let i = 0; i < Math.max(pa.length, pb.length); i += 1) {
    const na = parseInt(pa[i], 10);
    const nb = parseInt(pb[i], 10);
    if (Number.isNaN(na) || Number.isNaN(nb)) {
      const c = String(pa[i] || '').localeCompare(String(pb[i] || ''));
      if (c !== 0) return c;
    } else if (na !== nb) {
      return na - nb;
    }
  }
  return 0;
}

module.exports = { createSelfUpdater };
