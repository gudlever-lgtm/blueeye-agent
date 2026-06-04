#!/usr/bin/env bash
set -euo pipefail

# BlueEye agent — Docker installer.
# Clones/updates the repo, builds the image, and runs the agent as a
# restart-on-boot Docker container. Safe to re-run (it recreates the container;
# the agent token lives on a named volume so re-runs reuse it).
#
# Usage:
#   BLUEEYE_SERVER_URL=https://server.example \
#   BLUEEYE_ENROLLMENT_CODE=<one-time-code> \
#   ./install.sh
#
# Optional env:
#   REPO_URL       (default https://github.com/gudlever-lgtm/blueeye-agent.git)
#   SRC_DIR        where to clone if not run from inside a checkout (./blueeye-agent)
#   IMAGE          image tag           (blueeye-agent)
#   CONTAINER      container name       (blueeye-agent)
#   NETWORK_MODE   host|bridge          (host — needed to measure host traffic; Linux)
#   TOKEN_VOLUME   docker volume name   (blueeye-agent-data)
#   PLATFORM       target platform      (auto-detected 64-bit: linux/amd64 or linux/arm64)

REPO_URL="${REPO_URL:-https://github.com/gudlever-lgtm/blueeye-agent.git}"
IMAGE="${IMAGE:-blueeye-agent}"
CONTAINER="${CONTAINER:-blueeye-agent}"
NETWORK_MODE="${NETWORK_MODE:-host}"
TOKEN_VOLUME="${TOKEN_VOLUME:-blueeye-agent-data}"
SERVER_URL="${BLUEEYE_SERVER_URL:-}"
ENROLL="${BLUEEYE_ENROLLMENT_CODE:-}"

# Resolve the build/run platform. The agent only supports 64-bit; default to the
# host's 64-bit architecture, but allow an explicit override (e.g. PLATFORM=linux/arm64).
if [ -z "${PLATFORM:-}" ]; then
  case "$(uname -m)" in
    x86_64|amd64)        PLATFORM="linux/amd64" ;;
    aarch64|arm64)       PLATFORM="linux/arm64" ;;
    *) echo "ERROR: unsupported architecture '$(uname -m)'. The BlueEye agent requires a 64-bit host (amd64 or arm64). Set PLATFORM to override." >&2; exit 1 ;;
  esac
fi

command -v docker >/dev/null 2>&1 || { echo "ERROR: Docker is required but not installed." >&2; exit 1; }
[ -n "$SERVER_URL" ] || { echo "ERROR: set BLUEEYE_SERVER_URL (e.g. https://server.example)." >&2; exit 1; }

# 1) Source: use the current checkout if we're inside one, otherwise clone/pull.
if [ -f "Dockerfile" ] && [ -d "src" ]; then
  SRC="$(pwd)"
  echo "Using current checkout: $SRC"
else
  SRC="${SRC_DIR:-./blueeye-agent}"
  if [ -d "$SRC/.git" ]; then
    echo "Updating existing checkout: $SRC"
    git -C "$SRC" pull --ff-only
  else
    echo "Cloning $REPO_URL -> $SRC"
    git clone "$REPO_URL" "$SRC"
  fi
fi

# 2) Build the image for the (64-bit) target platform.
echo "Building image $IMAGE for $PLATFORM ..."
docker build --platform "$PLATFORM" -t "$IMAGE" "$SRC"

# 3) (Re)create the container. The enrollment code is only needed on first start;
#    after enrollment the token on $TOKEN_VOLUME is reused automatically.
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker volume create "$TOKEN_VOLUME" >/dev/null

ARGS=(-d --name "$CONTAINER" --restart unless-stopped
  --platform "$PLATFORM"
  -e "BLUEEYE_SERVER_URL=$SERVER_URL"
  -e "BLUEEYE_TOKEN_PATH=/data/token"
  -v "$TOKEN_VOLUME:/data")
if [ "$NETWORK_MODE" = "host" ]; then ARGS+=(--network host); fi
if [ -n "$ENROLL" ]; then ARGS+=(-e "BLUEEYE_ENROLLMENT_CODE=$ENROLL"); fi

echo "Starting container $CONTAINER (network: $NETWORK_MODE, platform: $PLATFORM) ..."
docker run "${ARGS[@]}" "$IMAGE"

echo
echo "BlueEye agent is running. Recent logs:"
docker logs --tail 20 "$CONTAINER" 2>&1 || true
echo
echo "Manage it with:  docker logs -f $CONTAINER   |   docker restart $CONTAINER   |   docker rm -f $CONTAINER"
