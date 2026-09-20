'use strict';

const { verifyManifest } = require('./release/verifyManifest');

// Authenticity of a server -> agent COMMAND.
//
// By default a command is trusted because it arrived on the authenticated
// WebSocket: whoever holds that socket can ask the agent to self-update,
// self-delete or install a package. For the privileged commands that puts the
// whole fleet's integrity on the server never being wrong — so those can carry
// an Ed25519 signature made with the same release key the agent already pins for
// signed updates, and the agent checks it before acting.
//
// The field is `commandSignature`, NOT `signature`: on an update command
// `signature` is already taken — it signs the RELEASE MANIFEST, which
// authenticates the payload to install, not the instruction to install it.
//
// The signed payload is the command MINUS `commandSignature` and MINUS `id`.
// `id` is a correlation token the transport stamps on at send time (the agent
// echoes it back on the ack); it carries no authority, and it is assigned after
// the command is built, so it cannot be part of what was signed.
//
// Policy — verifyCommand():
//   signature + pinned key   -> must verify, or the command is refused
//   no signature, lenient    -> allowed (backward compatible with older servers)
//   no signature, strict     -> refused
// Strict mode is BLUEEYE_REQUIRE_SIGNED_COMMANDS, the command-channel twin of
// BLUEEYE_REQUIRE_SIGNED_UPDATES.

// How far a signed command's issuedAt may sit from the agent's clock. Bounds the
// window in which a captured command can be replayed, while tolerating ordinary
// clock skew on an on-prem host.
const MAX_SKEW_MS = 5 * 60 * 1000;

// The exact bytes the server signed: everything except the signature itself and
// the transport correlation id.
function signedPayload(command) {
  const payload = {};
  for (const [k, v] of Object.entries(command || {})) {
    if (k === 'commandSignature' || k === 'id') continue;
    payload[k] = v;
  }
  return payload;
}

const TRUTHY = /^(1|true|yes|on)$/i;

// Is the agent configured to REQUIRE signed privileged commands?
function requireSignedCommands(env = process.env) {
  return TRUTHY.test(String(env.BLUEEYE_REQUIRE_SIGNED_COMMANDS || '').trim());
}

// REKEY IS DIFFERENT, and is strict by default.
//
// The lenient default above is a deliberate backward-compatibility choice for
// update/delete/install-tool: an older server cannot sign, and those commands
// are bounded — `delete` removes the agent, which is loud and visible in the
// fleet list, and `update` installs a release whose own manifest signature is
// still checked separately.
//
// `rekey` is not bounded in the same way. It replaces the trust anchor, and
// every signature check AFTERWARDS is made against the new key. Accepting an
// unsigned one turns a single moment of access to the socket into permanent,
// SILENT code execution on the host: the attacker rekeys to their own key, and
// from then on their releases verify. That is a qualitatively different thing
// from deleting an agent somebody will notice is gone.
//
// So: when this agent already trusts a key, a rekey must be signed WITH THAT
// KEY — which is exactly what a legitimate rotation looks like, and what the
// server does automatically whenever it can sign (services/commandSigner.js).
//
// The cost, stated plainly: this closes the recover-a-fleet-whose-server-lost-
// its-signing-key path, because that is the one case where the server cannot
// produce the required signature. That path is not gone, it now needs the level
// of authority it always should have — someone with access to the host sets
// BLUEEYE_ALLOW_UNSIGNED_REKEY=1 in the unit (or re-runs the installer). Being
// able to re-anchor a host's trust remotely, with no signature and no host
// access, was never a smaller privilege than root on that host.
//
// A fresh install with NO key pinned is unaffected: there is nothing to
// downgrade, the anchor arrived by trust-on-first-use anyway, and refusing here
// would break provisioning for no gain.
function allowUnsignedRekey(env = process.env) {
  return TRUTHY.test(String(env.BLUEEYE_ALLOW_UNSIGNED_REKEY || '').trim());
}

// Returns { ok: true, signed } or { ok: false, reason }. Never throws — the
// caller turns a refusal into a declined command, not a crash.
function verifyCommand(command, {
  publicKey = '',
  agentId = null,
  strict = false,
  // True for the one command that replaces the trust anchor. See
  // allowUnsignedRekey() above for why it does not follow the lenient default.
  isRekey = false,
  allowUnsignedRekeyOverride = allowUnsignedRekey(),
  now = () => Date.now(),
  maxSkewMs = MAX_SKEW_MS,
} = {}) {
  const signature = command && command.commandSignature;
  if (!signature) {
    if (strict) return { ok: false, reason: 'refused: unsigned command (this agent requires signed commands)' };
    if (isRekey && publicKey && !allowUnsignedRekeyOverride) {
      return {
        ok: false,
        reason: 'refused: an unsigned rekey cannot replace a trust anchor this agent already holds. '
          + 'A legitimate rotation is signed with the key being replaced. To re-anchor a host whose '
          + 'server can no longer sign, set BLUEEYE_ALLOW_UNSIGNED_REKEY=1 on the host and restart, '
          + 'or re-run the installer.',
      };
    }
    return { ok: true, signed: false };
  }
  // A signature we cannot check is worse than none: fail closed rather than
  // accept it because it "looks signed".
  if (!publicKey) return { ok: false, reason: 'refused: command is signed but no release public key is configured' };
  if (!verifyManifest(signedPayload(command), signature, publicKey)) {
    return { ok: false, reason: 'refused: command signature verification failed' };
  }
  // A valid signature over a payload naming neither an agent nor a time is
  // replayable at every other agent, for ever. Require both.
  if (command.agentId == null) return { ok: false, reason: 'refused: signed command names no agent' };
  if (agentId != null && String(command.agentId) !== String(agentId)) {
    return { ok: false, reason: 'refused: command was signed for a different agent' };
  }
  const issuedAt = Date.parse(command.issuedAt || '');
  if (!Number.isFinite(issuedAt)) return { ok: false, reason: 'refused: signed command has no valid issuedAt' };
  if (Math.abs(now() - issuedAt) > maxSkewMs) {
    return { ok: false, reason: 'refused: signed command is outside the accepted time window (replay?)' };
  }
  return { ok: true, signed: true };
}

module.exports = { verifyCommand, requireSignedCommands, allowUnsignedRekey, signedPayload, MAX_SKEW_MS };
