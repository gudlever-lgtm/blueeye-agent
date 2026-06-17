#!/usr/bin/env bash
set -euo pipefail

# BlueEye agent — systemd (tar.gz) installer. NOT Docker. This is the canonical
# bare-Linux install: it lays out /opt/blueeye-agent/releases/<version> with a
# `current` symlink and a systemd service, so the server can later push SIGNED
# releases that swap atomically (with rollback). The token + action log live
# outside the release dir, so updates never touch them.
#
#   BLUEEYE_SERVER_URL=https://server.example \
#   BLUEEYE_ENROLLMENT_CODE=<one-time-code> \
#   sudo ./scripts/install-systemd.sh
#
# Optional env:
#   BLUEEYE_INSTALL_DIR          (/opt/blueeye-agent)
#   SERVICE_NAME                 (blueeye-agent)
#   BLUEEYE_RELEASE_PUBLIC_KEY   PEM or base64-of-PEM — the release trust anchor for
#                                signed self-updates. Optional: auto-fetched from the
#                                server (GET /enroll/agent-release-key) when unset.

SERVER_URL="${BLUEEYE_SERVER_URL:?set BLUEEYE_SERVER_URL (e.g. https://server.example)}"
CODE="${BLUEEYE_ENROLLMENT_CODE:-}"
INSTALL_DIR="${BLUEEYE_INSTALL_DIR:-/opt/blueeye-agent}"
SERVICE_NAME="${SERVICE_NAME:-blueeye-agent}"
RELEASES="$INSTALL_DIR/releases"
STATE_DIR="/var/lib/blueeye-agent"
LOG_DIR="/var/log/blueeye-agent"
UNIT="/etc/systemd/system/${SERVICE_NAME}.service"

[ "$(id -u)" = "0" ] || { echo "run with sudo (root)" >&2; exit 1; }
command -v node >/dev/null || { echo "Node.js (>=20) is required" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
NODE_BIN=$(command -v node)

# Fail fast on a first install that can't get credentials: neither a stored token
# nor a one-time enrollment code. Without one the agent exits 1 on every boot and
# systemd's Restart= turns that into a crash-loop. (A token already present means a
# prior enrollment succeeded, so a code-less re-run/upgrade is fine.)
if [ -z "$CODE" ] && [ ! -f "$STATE_DIR/token" ]; then
  echo "ERROR: no stored token at $STATE_DIR/token and no BLUEEYE_ENROLLMENT_CODE set." >&2
  echo "       A first-time agent needs a one-time enrollment code from the dashboard:" >&2
  echo "         BLUEEYE_SERVER_URL=$SERVER_URL BLUEEYE_ENROLLMENT_CODE=<code> sudo ./scripts/install-systemd.sh" >&2
  exit 1
fi

mkdir -p "$RELEASES" "$STATE_DIR" "$LOG_DIR"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# 1) Fetch the latest SIGNED release (preferred) or fall back to the source bundle.
if curl -fsSL "$SERVER_URL/enroll/agent-release" -o "$TMP/meta.json" 2>/dev/null; then
  VERSION="$(node -e "process.stdout.write(String(require('$TMP/meta.json').version || ''))")"
  echo "Installing signed agent release v$VERSION ..."
  curl -fsSL "$SERVER_URL/enroll/agent-release.tgz" -o "$TMP/agent.tgz"
else
  VERSION="source-$(date +%Y%m%d%H%M%S)"
  echo "No signed release published; installing the source bundle ($VERSION) ..."
  curl -fsSL "$SERVER_URL/enroll/agent-source.tgz" -o "$TMP/agent.tgz"
fi

DEST="$RELEASES/$VERSION"
rm -rf "$DEST"; mkdir -p "$DEST"
tar -xzf "$TMP/agent.tgz" -C "$DEST"
( cd "$DEST" && (npm ci --omit=dev || npm install --omit=dev) )

# 2) Point `current` at the new release (atomic: temp symlink, then mv -T).
ln -sfn "$DEST" "$INSTALL_DIR/current.next"
mv -T "$INSTALL_DIR/current.next" "$INSTALL_DIR/current"

# 3) Install the systemd unit (template substitutions: server URL, node binary
#    path, and install dir so non-default BLUEEYE_INSTALL_DIR works correctly).
sed \
  -e "s#https://server.example#${SERVER_URL}#g" \
  -e "s#/usr/bin/node#${NODE_BIN}#g" \
  -e "s#/opt/blueeye-agent#${INSTALL_DIR}#g" \
  "$DEST/deploy/blueeye-agent.service" > "$UNIT"

# Pin the self-update restart target to THIS unit's name (selfUpdate defaults to
# 'blueeye-agent'); only matters when SERVICE_NAME was overridden, but harmless otherwise.
mkdir -p "${UNIT}.d"
{ echo "[Service]"; echo "Environment=BLUEEYE_SERVICE_NAME=${SERVICE_NAME}"; } > "${UNIT}.d/00-service-name.conf"

# Release trust anchor. Prefer an explicitly provided key; otherwise fetch it from
# the server (public, not secret) so SIGNED self-updates verify with no manual
# provisioning. Base64-encoded in the drop-in so a multi-line PEM stays on a single
# Environment= line (the agent decodes base64-of-PEM).
RELEASE_KEY="${BLUEEYE_RELEASE_PUBLIC_KEY:-}"
[ -n "$RELEASE_KEY" ] || RELEASE_KEY="$(curl -fsSL "$SERVER_URL/enroll/agent-release-key" 2>/dev/null || true)"
if [ -n "$RELEASE_KEY" ] && command -v base64 >/dev/null 2>&1; then
  case "$RELEASE_KEY" in
    *"BEGIN PUBLIC KEY"*) RELEASE_KEY="$(printf '%s' "$RELEASE_KEY" | base64 | tr -d '\n')" ;;
  esac
  mkdir -p "${UNIT}.d"
  { echo "[Service]"; echo "Environment=BLUEEYE_RELEASE_PUBLIC_KEY=${RELEASE_KEY}"; } > "${UNIT}.d/10-release-key.conf"
  echo "Signed self-updates enabled (release key pinned)."
else
  echo "NOTE: no release public key available — signed self-updates will be refused until BLUEEYE_RELEASE_PUBLIC_KEY is set (or AGENT_RELEASE_PUBLIC_KEY is configured on the server)." >&2
fi

# Enroll on first install: the agent exchanges the one-time code for a token on
# its first boot (written to BLUEEYE_TOKEN_PATH). The code is one-time, so leaving
# it in the drop-in is harmless; remove it later if you prefer.
if [ -n "$CODE" ] && [ ! -f "$STATE_DIR/token" ]; then
  mkdir -p "${UNIT}.d"
  { echo "[Service]"; echo "Environment=BLUEEYE_ENROLLMENT_CODE=${CODE}"; } > "${UNIT}.d/20-enroll.conf"
fi

# 4) Enable + start.
systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
systemctl restart "$SERVICE_NAME"

echo "Installed $SERVICE_NAME (v$VERSION)."
echo "Follow logs:   journalctl -u $SERVICE_NAME -f"
echo "Remove later:  sudo $DEST/uninstall.sh --yes   (or Agents -> Delete in the dashboard)"
