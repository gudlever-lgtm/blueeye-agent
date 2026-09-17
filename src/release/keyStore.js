'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

// Where this host's PINNED release key lives once the server has re-keyed it.
//
// The key the agent verifies self-updates against is baked in at install time
// (the systemd drop-in `10-release-key.conf`, read as BLUEEYE_RELEASE_PUBLIC_KEY).
// That is fine until the server's signing key changes — a rotation, a
// regenerated key, or one whose private half can no longer be decrypted. From
// then on every update the server can produce is refused, and the only way out
// was a shell on the host. There is no shell on the host: an installed agent is
// managed FROM the server, so the server sends a `rekey` command and the agent
// stores the new anchor itself.
//
// Two places, on purpose:
//   1. this file, beside the agent's token — always written, always readable by
//      the agent, and the value that wins at startup;
//   2. the systemd drop-in, best-effort — so a human reading the unit sees the
//      key the agent is actually using, and an agent started with a stale
//      environment is not handed the old key back.
// The file wins over the environment because it is the more recent authority:
// it is only ever written by a rekey this agent accepted.

const FILE_NAME = 'release-key.pem';

function looksLikePem(value) {
  return typeof value === 'string' && value.includes('BEGIN PUBLIC KEY');
}

// The pinned-key path for a given token path (same directory — the one place
// the agent is guaranteed to be able to write).
function pinnedKeyPath(tokenPath) {
  const dir = tokenPath ? path.dirname(String(tokenPath)) : path.join(__dirname, '..', '..', '.blueeye-agent');
  return path.join(dir, FILE_NAME);
}

// Accepts PEM or base64-of-PEM (the form the systemd unit carries) and returns
// a normalised PEM, or '' when it is neither.
function normalizePem(value) {
  if (looksLikePem(value)) return String(value);
  if (typeof value === 'string' && value.trim()) {
    try {
      const decoded = Buffer.from(value.trim(), 'base64').toString('utf8');
      if (looksLikePem(decoded)) return decoded;
    } catch { /* not base64 */ }
  }
  return '';
}

// Parses the key and confirms it is an Ed25519 PUBLIC key — a rekey that stores
// anything else would leave the agent unable to verify any release at all.
// Returns { ok, pem?, fingerprint?, reason? }; never throws.
function validatePublicKey(value, { fsImpl = fs } = {}) { // eslint-disable-line no-unused-vars
  const pem = normalizePem(value);
  if (!pem) return { ok: false, reason: 'not a PEM public key' };
  let key;
  try {
    key = crypto.createPublicKey({ key: pem, format: 'pem' });
  } catch (err) {
    return { ok: false, reason: `unreadable public key (${err.message})` };
  }
  if (key.asymmetricKeyType !== 'ed25519') {
    return { ok: false, reason: `expected an ed25519 key, got ${key.asymmetricKeyType || 'unknown'}` };
  }
  const normalised = key.export({ type: 'spki', format: 'pem' }).toString();
  return { ok: true, pem: normalised, fingerprint: crypto.createHash('sha256').update(normalised).digest('hex') };
}

function readPinnedKey(file, { fsImpl = fs } = {}) {
  try {
    const raw = fsImpl.readFileSync(file, 'utf8');
    return looksLikePem(raw) ? raw : '';
  } catch {
    return '';
  }
}

// Writes the anchor atomically (temp file + rename) so a crash mid-write can
// never leave a truncated key that would refuse every future update.
function writePinnedKey(file, pem, { fsImpl = fs } = {}) {
  fsImpl.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  fsImpl.writeFileSync(tmp, pem.endsWith('\n') ? pem : `${pem}\n`, { mode: 0o644 });
  fsImpl.renameSync(tmp, file);
  return file;
}

// Best-effort: keep the systemd drop-in in step with the stored key, so the unit
// a person reads says what the agent actually trusts. Never fatal — the stored
// file is the authority, and a container/unmanaged agent has no unit at all.
// Returns { ok, path? , reason? }.
function syncSystemdDropIn(pem, {
  serviceName = process.env.BLUEEYE_SERVICE_NAME || 'blueeye-agent',
  unitDir = process.env.BLUEEYE_UNIT_DIR || '/etc/systemd/system',
  fsImpl = fs,
  exec = spawnSync,
} = {}) {
  const unit = path.join(unitDir, `${serviceName}.service`);
  try {
    if (!fsImpl.existsSync(unit)) return { ok: false, reason: 'no systemd unit on this host' };
  } catch (err) {
    return { ok: false, reason: err.message };
  }
  const dropInDir = `${unit}.d`;
  const dropIn = path.join(dropInDir, '10-release-key.conf');
  try {
    fsImpl.mkdirSync(dropInDir, { recursive: true });
    const b64 = Buffer.from(pem, 'utf8').toString('base64');
    fsImpl.writeFileSync(dropIn, `[Service]\nEnvironment=BLUEEYE_RELEASE_PUBLIC_KEY=${b64}\n`, { mode: 0o644 });
  } catch (err) {
    return { ok: false, reason: `could not write ${dropIn} (${err.message})` };
  }
  // daemon-reload so the next restart picks the new environment up. The running
  // process already has the key in memory, so no restart is needed now.
  try { exec('systemctl', ['daemon-reload'], { encoding: 'utf8' }); } catch { /* best-effort */ }
  return { ok: true, path: dropIn };
}

// The fingerprint the dashboard shows next to a key (sha256 of the PEM).
function fingerprintOf(pem) {
  return crypto.createHash('sha256').update(String(pem)).digest('hex');
}

module.exports = {
  FILE_NAME, pinnedKeyPath, normalizePem, validatePublicKey, readPinnedKey,
  writePinnedKey, syncSystemdDropIn, fingerprintOf, looksLikePem, tmpdir: os.tmpdir,
};
