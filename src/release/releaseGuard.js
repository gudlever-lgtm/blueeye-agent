'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

// Rolling back a release that never comes up.
//
// selfUpdate installs blue/green: a new release dir, then an atomic swap of the
// `current` symlink, keeping the previous release for rollback(). Nothing ever
// CALLED rollback(). So a release that installs but cannot start — a bad
// dependency, a syntax error, a Node too old — left the host in the one state
// this whole design exists to avoid: systemd retries, gives up at its start
// limit, and the agent is gone. No connection, therefore no server-driven
// recovery, therefore a shell on a host that is not supposed to need one.
//
// The guard has to survive the very failure it recovers from, so it cannot be
// part of the release it is judging:
//
//   * it is plain `sh`, not Node — a release whose Node code will not parse must
//     still be recoverable;
//   * it lives in <installDir>/bin, OUTSIDE releases/, so a swap never replaces
//     it, and `.pending` lives beside `.previous` in releases/;
//   * systemd runs it as ExecStartPre, so it gets a turn BEFORE the code that
//     may be broken, on every start attempt.
//
// The protocol is one file, `releases/.pending`:
//
//   line 1  the version that was just swapped in
//   line 2  how many times it has been started without confirming
//
// Each start increments line 2. The agent deletes the file once it has held a
// verified server connection (confirmRelease below) — that, not "the process
// started", is what proves a release works. At the limit the guard repoints
// `current` at `.previous` and clears the marker, so the next start runs the
// release that was known good.

const PENDING = '.pending';
const PREVIOUS = '.previous';
const DEFAULT_ATTEMPTS = 3;

// How long a connection has to hold before the release is called good. Long
// enough that a process which connects and then dies on its first real work
// does not confirm itself; short enough that a genuine update settles quickly.
const DEFAULT_CONFIRM_MS = 60_000;

function pendingPath(releasesDir) {
  return path.join(releasesDir, PENDING);
}

// Marks the release just swapped in as unproven. Called by the updater right
// after the symlink swap — while the OLD, known-good process is still running,
// which is the only moment the marker can be written by code that is certainly
// working.
function markPending(releasesDir, version, { fsImpl = fs } = {}) {
  if (!releasesDir || !version) return false;
  try {
    fsImpl.writeFileSync(pendingPath(releasesDir), `${version}\n0\n`, { mode: 0o644 });
    return true;
  } catch {
    return false; // best-effort: a missing marker only costs the rollback, not the update
  }
}

// The release proved itself. Deleting the marker is what stops the guard
// counting this release's starts — and it is deliberately NOT called on
// startup: a process that starts and immediately dies would otherwise confirm
// the release that is killing it.
function confirmRelease(releasesDir, { fsImpl = fs } = {}) {
  if (!releasesDir) return false;
  try {
    fsImpl.rmSync(pendingPath(releasesDir), { force: true });
    return true;
  } catch {
    return false;
  }
}

// What the guard sees, for the agent's own logging and for tests.
function readPending(releasesDir, { fsImpl = fs } = {}) {
  if (!releasesDir) return null;
  let raw;
  try {
    raw = String(fsImpl.readFileSync(pendingPath(releasesDir), 'utf8'));
  } catch {
    return null;
  }
  const [version = '', attempts = '0'] = raw.split('\n');
  const n = Number.parseInt(attempts, 10);
  return { version: version.trim(), attempts: Number.isFinite(n) ? n : 0 };
}

// The guard itself. POSIX sh, no Node, no jq, no bashisms — it runs on a host
// whose agent may be unable to start at all.
//
// $1 = releases dir, $2 = current symlink, $3 = max attempts.
function guardScript() {
  return `#!/bin/sh
# BlueEyes release guard — installed by the agent, NOT part of a release.
#
# Runs before every start of the agent service. If the release that is current
# has been started too many times without ever confirming itself (the agent
# deletes .pending once it has held a server connection), repoint 'current' at
# the previous release so the next start runs known-good code.
#
# Deliberately boring: no Node, no pipefail, no arrays. It has to work on the
# day the agent itself does not.
set -eu

RELEASES="\${1:-\${BLUEEYE_RELEASES_DIR:-}}"
CURRENT="\${2:-\${BLUEEYE_CURRENT_LINK:-}}"
LIMIT="\${3:-${DEFAULT_ATTEMPTS}}"

[ -n "$RELEASES" ] || exit 0
[ -n "$CURRENT" ] || exit 0

PENDING="$RELEASES/${PENDING}"
PREVIOUS="$RELEASES/${PREVIOUS}"

# Nothing to judge: no update is waiting to prove itself.
[ -f "$PENDING" ] || exit 0

VERSION=$(sed -n 1p "$PENDING" 2>/dev/null || true)
ATTEMPTS=$(sed -n 2p "$PENDING" 2>/dev/null || true)
case "$ATTEMPTS" in
  ''|*[!0-9]*) ATTEMPTS=0 ;;
esac

if [ "$ATTEMPTS" -lt "$LIMIT" ]; then
  ATTEMPTS=$((ATTEMPTS + 1))
  printf '%s\\n%s\\n' "$VERSION" "$ATTEMPTS" > "$PENDING"
  exit 0
fi

# Out of attempts. Roll back if we kept a previous release; otherwise there is
# nothing better to run, so clear the marker and let it start — a boot loop the
# operator can see beats a silent one this script keeps re-arming.
PREV=""
[ -f "$PREVIOUS" ] && PREV=$(cat "$PREVIOUS" 2>/dev/null || true)

if [ -n "$PREV" ] && [ -d "$PREV" ]; then
  # rm + ln, not 'mv' onto the symlink: mv follows a destination that is a
  # symlink TO A DIRECTORY and would move the new link INSIDE the release
  # instead of replacing it. rm -f removes the link, never its target, and the
  # service is not running yet, so the moment without a 'current' is harmless.
  rm -f "$CURRENT"
  ln -s "$PREV" "$CURRENT"
  printf 'blueeye release guard: %s failed to confirm after %s starts — rolled back to %s\\n' \\
    "$VERSION" "$ATTEMPTS" "$PREV" >&2
else
  printf 'blueeye release guard: %s failed to confirm after %s starts, and no previous release is kept\\n' \\
    "$VERSION" "$ATTEMPTS" >&2
fi
rm -f "$PENDING"
exit 0
`;
}

// The systemd drop-in that runs the guard. Separate from the unit so the agent
// can add it to an EXISTING install (every agent in the field predates this
// file) without rewriting a unit somebody may have edited.
function dropIn({ guardPath, releasesDir, currentLink, attempts = DEFAULT_ATTEMPTS }) {
  return `[Service]
# Roll back a release that never confirmed itself. See src/release/releaseGuard.js.
ExecStartPre=-/bin/sh ${guardPath} ${releasesDir} ${currentLink} ${attempts}
`;
}

// Writes the guard + its drop-in if they are missing or out of date, and asks
// systemd to reload when anything changed. Best-effort throughout: an agent that
// cannot write here (not root, no systemd, a container) simply has no guard, and
// says so once rather than failing to start.
//
// Returns { ok, changed, reason? } for the caller to log.
function ensureInstalled({
  installDir = '',
  releasesDir = process.env.BLUEEYE_RELEASES_DIR || '',
  currentLink = process.env.BLUEEYE_CURRENT_LINK || '',
  serviceName = process.env.BLUEEYE_SERVICE_NAME || 'blueeye-agent',
  unitDir = process.env.BLUEEYE_UNIT_DIR || '/etc/systemd/system',
  attempts = DEFAULT_ATTEMPTS,
  fsImpl = fs,
  exec = spawnSync,
} = {}) {
  if (!releasesDir || !currentLink) return { ok: false, changed: false, reason: 'no blue/green layout' };
  // The guard must not live inside a release dir — that is the thing being
  // swapped. Default to <installDir>/bin, falling back to the parent of the
  // releases dir, which is the install root in the standard layout.
  const root = installDir || path.dirname(releasesDir);
  const binDir = path.join(root, 'bin');
  const guardPath = path.join(binDir, 'release-guard.sh');
  const unit = path.join(unitDir, `${serviceName}.service`);
  const conf = path.join(`${unit}.d`, '20-release-guard.conf');

  let changed = false;
  const write = (file, content, mode) => {
    let existing = null;
    try { existing = String(fsImpl.readFileSync(file, 'utf8')); } catch { /* absent */ }
    if (existing === content) return;
    fsImpl.mkdirSync(path.dirname(file), { recursive: true });
    fsImpl.writeFileSync(file, content, { mode });
    changed = true;
  };

  try {
    write(guardPath, guardScript(), 0o755);
  } catch (err) {
    return { ok: false, changed, reason: `cannot write ${guardPath} (${err.message})` };
  }

  try {
    if (!fsImpl.existsSync(unit)) return { ok: true, changed, reason: 'no systemd unit — guard installed but not wired' };
    write(conf, dropIn({ guardPath, releasesDir, currentLink, attempts }), 0o644);
  } catch (err) {
    return { ok: false, changed, reason: `cannot write ${conf} (${err.message})` };
  }

  if (changed) {
    try { exec('systemctl', ['daemon-reload'], { encoding: 'utf8' }); } catch { /* best-effort */ }
  }
  return { ok: true, changed };
}


// Repoints `current` at a release directory.
//
// On POSIX this is a temp symlink plus a rename, which is atomic: there is no
// instant where `current` does not exist. Windows has no atomic replace for a
// directory junction — rename onto an existing name fails — so there it is a
// remove followed by a create, and the gap is covered by WHEN it happens: the
// swap during an update runs while the old process is still serving, and the
// swap during a rollback runs before the service has started.
function repointCurrent(currentLink, target, { fsImpl = fs, platform = process.platform } = {}) {
  if (platform === 'win32') {
    try { fsImpl.rmSync(currentLink, { recursive: false, force: true }); } catch { /* absent */ }
    // 'junction' rather than 'dir': a junction needs no privilege, a directory
    // symlink needs SeCreateSymbolicLink or developer mode.
    fsImpl.symlinkSync(target, currentLink, 'junction');
    return;
  }
  const tmpLink = `${currentLink}.next`;
  try { fsImpl.rmSync(tmpLink, { force: true }); } catch { /* none */ }
  fsImpl.symlinkSync(target, tmpLink);
  fsImpl.renameSync(tmpLink, currentLink); // atomic replace of the symlink
}

// The guard, in Node, for the hosts that have no ExecStartPre to run the sh one:
// a Windows service and a launchd job. Same protocol, same file, same decision —
// count this start, and past the limit repoint `current` at the previous release.
//
// The difference is WHO acts on it. Under systemd the guard runs before the
// agent, so it can simply hand the next start the old code. Here the agent is
// already running the unproven release when it gets to look, so a rollback has
// to be followed by the process exiting: the service manager then starts again,
// on the release this call just restored. The caller decides that (it owns
// process exit); this returns what happened.
//
//   { action: 'none' }         nothing is waiting to prove itself
//   { action: 'counted' }      counted this start, keep going
//   { action: 'rolled-back' }  `current` now points at `previous` — EXIT so the
//                              service manager starts it
//   { action: 'exhausted' }    out of attempts and no previous release kept;
//                              nothing better to run, so keep going and let the
//                              loop be visible
function enforceStartup({
  releasesDir = process.env.BLUEEYE_RELEASES_DIR || '',
  currentLink = process.env.BLUEEYE_CURRENT_LINK || '',
  attempts: limit = DEFAULT_ATTEMPTS,
  fsImpl = fs,
  platform = process.platform,
} = {}) {
  if (!releasesDir || !currentLink) return { action: 'none', reason: 'no blue/green layout' };
  const pending = readPending(releasesDir, { fsImpl });
  if (!pending) return { action: 'none' };

  if (pending.attempts < limit) {
    try {
      fsImpl.writeFileSync(pendingPath(releasesDir), `${pending.version}\n${pending.attempts + 1}\n`, { mode: 0o644 });
    } catch { /* best-effort: a marker we cannot write only costs the rollback */ }
    return { action: 'counted', version: pending.version, attempts: pending.attempts + 1 };
  }

  let previous = '';
  try { previous = String(fsImpl.readFileSync(path.join(releasesDir, PREVIOUS), 'utf8')).trim(); } catch { /* none kept */ }
  const usable = previous && (() => {
    try { return fsImpl.statSync(previous).isDirectory(); } catch { return false; }
  })();

  if (!usable) {
    // Clearing the marker matters: re-arming it would hide the loop behind a
    // guard that keeps "handling" it. Let the restarts be visible instead.
    confirmRelease(releasesDir, { fsImpl });
    return { action: 'exhausted', version: pending.version, attempts: pending.attempts };
  }

  repointCurrent(currentLink, previous, { fsImpl, platform });
  confirmRelease(releasesDir, { fsImpl });
  return { action: 'rolled-back', version: pending.version, attempts: pending.attempts, previous };
}

module.exports = {
  PENDING, PREVIOUS, DEFAULT_ATTEMPTS, DEFAULT_CONFIRM_MS,
  pendingPath, markPending, confirmRelease, readPending,
  guardScript, dropIn, ensureInstalled,
  repointCurrent, enforceStartup,
};
