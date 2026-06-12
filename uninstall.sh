#!/usr/bin/env bash
set -euo pipefail

# BlueEye agent uninstaller — removes the agent from THIS machine.
#
# Auto-detects how the agent was installed and removes it:
#   - systemd service (Node install): stop + disable + delete the unit + drop-ins
#   - Docker container (Docker install): stop + remove the container
#   - the install dir, the state dir (token/config) and the log dir
#
# It WARNS and asks for confirmation first (use --yes to skip the prompt).
#
# Usage:
#   sudo ./uninstall.sh            # interactive (asks y/N)
#   sudo ./uninstall.sh --yes      # no prompt
#   sudo ./uninstall.sh --purge    # also remove the Docker image + token volume
#
# Env overrides: SERVICE_NAME, BLUEEYE_INSTALL_DIR, BLUEEYE_STATE_DIR, BLUEEYE_LOG_DIR, CONTAINER, IMAGE, TOKEN_VOLUME
#
# NOTE: this removes the agent locally only. To remove it from the BlueEye
# server's list too, open the dashboard -> Agents -> Delete.

SERVICE_NAME="${SERVICE_NAME:-blueeye-agent}"
INSTALL_DIR="${BLUEEYE_INSTALL_DIR:-/opt/blueeye-agent}"
CONTAINER="${CONTAINER:-blueeye-agent}"
IMAGE="${IMAGE:-blueeye-agent}"
TOKEN_VOLUME="${TOKEN_VOLUME:-blueeye-agent-data}"
UNIT="/etc/systemd/system/${SERVICE_NAME}.service"
STATE_DIR="${BLUEEYE_STATE_DIR:-/var/lib/blueeye-agent}"
LOG_DIR="${BLUEEYE_LOG_DIR:-/var/log/blueeye-agent}"

ASSUME_YES=0
PURGE=0
for arg in "$@"; do
  case "$arg" in
    -y|--yes) ASSUME_YES=1 ;;
    --purge)  PURGE=1 ;;
    -h|--help) sed -n '3,21p' "$0"; exit 0 ;;
    *) printf 'unknown option: %s (try --help)\n' "$arg" >&2; exit 1 ;;
  esac
done

log()  { printf '[blueeye] %s\n' "$*"; }
warn() { printf '[blueeye] %s\n' "$*" >&2; }

# What's present on this host?
HAVE_SERVICE=0; [ -f "$UNIT" ] && HAVE_SERVICE=1
HAVE_CONTAINER=0
if command -v docker >/dev/null 2>&1 && docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx "$CONTAINER"; then
  HAVE_CONTAINER=1
fi
# An hsflowd exporter the AGENT provisioned (recognised by the managed marker the
# agent writes as the conf's first line). An operator's own hsflowd has no marker
# and is never touched.
HSFLOWD_CONF="/etc/hsflowd.conf"
HAVE_HSFLOWD=0
if [ -f "$HSFLOWD_CONF" ] && grep -q '^# Managed by blueeye-agent' "$HSFLOWD_CONF" 2>/dev/null; then
  HAVE_HSFLOWD=1
fi

if [ "$HAVE_SERVICE" -eq 0 ] && [ "$HAVE_CONTAINER" -eq 0 ] && [ "$HAVE_HSFLOWD" -eq 0 ] && [ ! -d "$INSTALL_DIR" ] && [ ! -d "$STATE_DIR" ]; then
  log "No BlueEye agent found on this host (no '$SERVICE_NAME' service, no '$CONTAINER' container, no $INSTALL_DIR/$STATE_DIR). Nothing to do."
  exit 0
fi

# Warn — spell out exactly what will be removed before doing anything.
warn "This will REMOVE the BlueEye agent from this machine:"
[ "$HAVE_SERVICE" -eq 1 ]   && warn "  - systemd service '$SERVICE_NAME' (stop, disable, delete $UNIT)"
[ "$HAVE_CONTAINER" -eq 1 ] && warn "  - Docker container '$CONTAINER' (stop, remove)"
[ "$HAVE_HSFLOWD" -eq 1 ]   && warn "  - agent-managed hsflowd exporter (stop, disable, delete $HSFLOWD_CONF; the hsflowd binary stays installed)"
[ -d "$INSTALL_DIR" ]       && warn "  - install directory $INSTALL_DIR (releases + current)"
[ -d "$STATE_DIR" ]         && warn "  - state directory $STATE_DIR (incl. the stored enrollment token)"
[ -d "$LOG_DIR" ]           && warn "  - log directory $LOG_DIR (local action trail)"
[ "$PURGE" -eq 1 ]          && warn "  - Docker image '$IMAGE' and token volume '$TOKEN_VOLUME' (--purge)"
warn "It does NOT remove the agent from the BlueEye server — do that in the dashboard (Agents -> Delete)."

if [ "$ASSUME_YES" -ne 1 ]; then
  printf '[blueeye] Proceed with uninstall? [y/N] ' >&2
  read -r reply </dev/tty 2>/dev/null || reply=""
  case "$reply" in
    y|Y|yes|YES) ;;
    *) log "Aborted — nothing was changed."; exit 0 ;;
  esac
fi

[ "$(id -u)" = "0" ] || { warn "uninstall needs root — re-run with sudo."; exit 1; }

if [ "$HAVE_SERVICE" -eq 1 ]; then
  log "Stopping and removing systemd service $SERVICE_NAME ..."
  systemctl stop "$SERVICE_NAME" 2>/dev/null || true
  systemctl disable "$SERVICE_NAME" 2>/dev/null || true
  rm -f "$UNIT"
  rm -rf "${UNIT}.d"
  systemctl daemon-reload 2>/dev/null || true
fi

if [ "$HAVE_HSFLOWD" -eq 1 ]; then
  log "Stopping agent-managed hsflowd exporter ..."
  systemctl disable --now hsflowd 2>/dev/null || true
  rm -f "$HSFLOWD_CONF"
fi

if [ "$HAVE_CONTAINER" -eq 1 ]; then
  log "Removing Docker container $CONTAINER ..."
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  if [ "$PURGE" -eq 1 ]; then
    log "Removing Docker image $IMAGE and volume $TOKEN_VOLUME ..."
    docker image rm -f "$IMAGE" >/dev/null 2>&1 || true
    docker volume rm "$TOKEN_VOLUME" >/dev/null 2>&1 || true
  fi
fi

if [ -d "$INSTALL_DIR" ]; then
  log "Removing $INSTALL_DIR ..."
  rm -rf "$INSTALL_DIR"
fi

if [ -d "$STATE_DIR" ]; then
  log "Removing $STATE_DIR (token + config) ..."
  rm -rf "$STATE_DIR"
fi

if [ -d "$LOG_DIR" ]; then
  log "Removing $LOG_DIR ..."
  rm -rf "$LOG_DIR"
fi

log "Done — the BlueEye agent has been removed from this machine."
log "If you haven't already, delete it in the dashboard too: Agents -> Delete."
