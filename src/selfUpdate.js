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
  //
  // `requireSigned` (or env BLUEEYE_REQUIRE_SIGNED_UPDATES) forces the signed
  // path; a pinned `publicKey` implies it. Injectable so tests can exercise both.
  async function update({ serverUrl, token, expectedSha, expectedVersion, signature, publicKey, fetchImpl, requireSigned }) {
    const doFetch = fetchImpl || (typeof fetch === 'function' ? fetch : null);
    if (!doFetch) throw fail('NO_FETCH', 'no fetch implementation available');

    // A `signature` in the command marks a SIGNED release: download the signed
    // artifact and verify its Ed25519 signature (authenticity) before anything
    // touches disk. Without one, fall back to the legacy source bundle (sha256
    // only) so existing deployments keep working.
    const signed = !!signature;

    // Fail CLOSED against a signature downgrade. If this agent has pinned a
    // release public key (the installer bakes it in) or signed updates are
    // explicitly required, refuse ANY update that arrives without a signature —
    // otherwise a malicious/compromised server, or an on-path attacker on a
    // plain-HTTP link, could simply omit the signature to force the weaker
    // legacy path and get arbitrary code executed as the agent's (often root) user.
    const requireSignedEnv = /^(1|true|yes|on)$/i.test(String(process.env.BLUEEYE_REQUIRE_SIGNED_UPDATES || '').trim());
    const mustBeSigned = requireSigned === true || !!publicKey || requireSignedEnv;
    if (!signed && mustBeSigned) {
      throw fail('SIGNATURE_REQUIRED', 'refusing unsigned update: a release public key is pinned or signed updates are required (possible signature downgrade)');
    }
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
      // Legacy source bundle: the sha256 is the ONLY integrity check, so it is
      // mandatory. Without it we would extract and execute unverified bytes — the
      // exact fail-open hole the signed path closes. Refuse rather than trust.
      if (!expectedSha) {
        throw fail('NO_CHECKSUM', 'legacy update carries no sha256 to verify against — refusing to install unverified code');
      }
      if (sha !== expectedSha) {
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
  // Guards against tar-slip: list the archive and reject any member with an
  // absolute path or a `..` that would escape the extraction root, BEFORE we
  // extract. Portable (list-then-extract on the same local file) and needs no
  // tar lib. The signed path is already authenticated; this also covers the
  // legacy sha-only bundle where the bytes' provenance is weaker.
  function assertSafeTar(tgz) {
    const r = exec('tar', ['-tzf', tgz], { encoding: 'utf8' });
    if (!r || r.status !== 0) {
      throw fail('EXTRACT_FAILED', `could not read archive listing: ${(r && (r.stderr || r.error)) || 'unknown error'}`);
    }
    const names = String(r.stdout || '').split('\n').map((s) => s.trim()).filter(Boolean);
    for (const name of names) {
      const norm = path.normalize(name);
      if (path.isAbsolute(name) || norm === '..' || norm.startsWith(`..${path.sep}`) || norm.startsWith('../')) {
        throw fail('UNSAFE_ARCHIVE', `refusing to extract: archive contains an unsafe path "${name}"`);
      }
    }

    // Defense in depth: a name-only check can't catch a symlink/hardlink member
    // whose *target* escapes the root (e.g. `link -> /etc` followed by
    // `link/passwd`), which `tar -xzf` would follow on extraction. Inspect the
    // verbose listing's type flag and refuse any link member. Best-effort: if the
    // verbose listing isn't available we still have the name check above.
    const v = exec('tar', ['-tvzf', tgz], { encoding: 'utf8' });
    if (v && v.status === 0 && v.stdout) {
      for (const line of String(v.stdout).split('\n')) {
        const type = line.trim()[0];
        if (type === 'l' || type === 'h') {
          throw fail('UNSAFE_ARCHIVE', `refusing to extract: archive contains a link member (${line.trim().slice(0, 80)})`);
        }
      }
    }
  }

  function installRelease(buf, version) {
    const tmp = fsImpl.mkdtempSync(path.join(os.tmpdir(), 'blueeye-update-'));
    const tgz = path.join(tmp, 'agent.tgz');
    fsImpl.writeFileSync(tgz, buf);
    try {
      assertSafeTar(tgz);
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
  // A release `version` becomes a directory name under releasesDir (and is then
  // rm -rf'd + recreated), so it MUST be a plain, self-contained token. In the
  // legacy/unsigned path `version` is `expectedVersion`, taken verbatim from the
  // server's update command — an unvalidated value like '../../../etc' would let
  // a malicious/compromised server escape the releases root and delete an
  // arbitrary directory as the agent's (often root) user before any payload is
  // even extracted. Reject anything that isn't a bare release token, and assert
  // the resolved path stays inside releasesDir. (The signed path passes the
  // authenticated manifest.version, but validating it too is cheap defense.)
  function assertSafeVersion(version) {
    const v = String(version);
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(v) || v.includes('..')) {
      throw fail('BAD_VERSION', `refusing update: unsafe release version "${v}"`);
    }
    const root = path.resolve(releasesDir);
    const resolved = path.resolve(root, v);
    if (resolved !== path.join(root, v) || !(resolved + path.sep).startsWith(root + path.sep)) {
      throw fail('BAD_VERSION', `refusing update: release version "${v}" escapes the releases directory`);
    }
    return v;
  }

  function atomicInstall(tgz, version) {
    const newDir = path.join(releasesDir, assertSafeVersion(version));
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
