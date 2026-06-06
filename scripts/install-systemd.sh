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
#   BLUEEYE_RELEASE_PUBLIC_KEY   base64-of-PEM — enables signed-update verification

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

# 3) Install the systemd unit (templated with the server URL).
sed "s#https://server.example#${SERVER_URL}#g" "$DEST/deploy/blueeye-agent.service" > "$UNIT"

# Embed the release trust anchor via a drop-in (keeps base64/PEM out of the unit).
if [ -n "${BLUEEYE_RELEASE_PUBLIC_KEY:-}" ]; then
  mkdir -p "${UNIT}.d"
  { echo "[Service]"; echo "Environment=BLUEEYE_RELEASE_PUBLIC_KEY=${BLUEEYE_RELEASE_PUBLIC_KEY}"; } > "${UNIT}.d/10-release-key.conf"
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
