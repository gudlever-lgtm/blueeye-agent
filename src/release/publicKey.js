'use strict';

// Embedded Ed25519 PUBLIC key the agent uses to verify SIGNED release tarballs
// before installing them — the agent's release trust anchor. It MUST be the same
// key pair as blueeye-server's AGENT_RELEASE_PUBLIC_KEY, generated with
// blueeye-licens scripts/generate-signing-key.js (a SEPARATE key from the
// license key). The public key is not secret.
//
// INSTALLATION: set BLUEEYE_RELEASE_PUBLIC_KEY (PEM or base64-of-PEM) at
// provisioning, or replace the placeholder. Until a real key is configured, a
// SIGNED update is REFUSED (fail-closed) — the agent never installs code it
// cannot authenticate.
const EMBEDDED_RELEASE_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
REPLACE_WITH_BLUEEYE_AGENT_RELEASE_PUBLIC_KEY
-----END PUBLIC KEY-----`;

function looksLikePem(value) {
  return typeof value === 'string' && value.includes('BEGIN PUBLIC KEY');
}

function isReleaseKeyConfigured(publicKey) {
  return looksLikePem(publicKey) && !publicKey.includes('REPLACE_WITH_BLUEEYE_AGENT_RELEASE_PUBLIC_KEY');
}

// Resolves the release public key, most recent authority first:
//   1. the key PINNED ON THIS HOST by an accepted `rekey` command
//      (<state dir>/release-key.pem — see src/release/keyStore.js). The server
//      manages an installed agent; when its signing key changes it re-keys the
//      agent over the command channel, and that decision must survive a restart
//      even though the unit's environment still carries the old key.
//   2. BLUEEYE_RELEASE_PUBLIC_KEY (PEM or base64) — what the installer baked in.
//   3. the embedded constant.
// Returns '' when only the placeholder is present, so callers fail closed.
function resolveReleasePublicKey(env = process.env, { pinnedPath = '', readPinned = null } = {}) {
  if (pinnedPath && typeof readPinned === 'function') {
    const pinned = readPinned(pinnedPath);
    if (isReleaseKeyConfigured(pinned)) return pinned;
  }
  const raw = env.BLUEEYE_RELEASE_PUBLIC_KEY;
  let key = EMBEDDED_RELEASE_PUBLIC_KEY;
  if (raw && raw.trim()) {
    if (looksLikePem(raw)) {
      key = raw;
    } else {
      try {
        const decoded = Buffer.from(raw, 'base64').toString('utf8');
        key = looksLikePem(decoded) ? decoded : raw;
      } catch {
        key = raw;
      }
    }
  }
  return isReleaseKeyConfigured(key) ? key : '';
}

module.exports = { EMBEDDED_RELEASE_PUBLIC_KEY, resolveReleasePublicKey, isReleaseKeyConfigured };
