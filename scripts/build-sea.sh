#!/usr/bin/env bash
set -euo pipefail

# Build self-contained BlueEye agent executables (Node Single Executable
# Applications) into ./dist as  blueeye-agent-<os>-<arch>  (e.g.
# blueeye-agent-linux-amd64). These are what the server serves at
# /enroll/agent/:platform and what the one-line installer downloads.
#
# The agent itself is plain Node with NO runtime build step — this script is only
# for producing distributable binaries (run in CI, see
# .github/workflows/release-agent.yml, or locally).
#
# Usage:
#   scripts/build-sea.sh                       # linux-amd64 + linux-arm64
#   scripts/build-sea.sh linux-amd64           # just one
#
# How it works:
#   1. esbuild bundles src/sea.js (+ all of src/ and the ws dependency) into one
#      CommonJS file.
#   2. `node --experimental-sea-config` turns that into a SEA blob. The blob is
#      architecture-independent (no V8 snapshot / code cache), so the SAME blob
#      is injected into the official Node binary of each target arch.
#   3. postject injects the blob into each per-arch `node`, yielding a binary that
#      runs the agent with no Node/npm install on the host.
#
# Requirements: node (20+), curl, tar (xz), and network access to nodejs.org +
# npm (for esbuild/postject via npx). Targets glibc Linux; musl/Alpine hosts must
# use the Docker install path instead.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PLATFORMS=("$@")
if [ "${#PLATFORMS[@]}" -eq 0 ]; then PLATFORMS=(linux-amd64 linux-arm64); fi

ESBUILD_VERSION="${ESBUILD_VERSION:-0.25.0}"
POSTJECT_VERSION="${POSTJECT_VERSION:-1.0.0-alpha.6}"
# Node's fixed SEA sentinel fuse (see the SEA docs). Do not change.
FUSE="NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2"

DIST="$ROOT/dist"
rm -rf "$DIST"
mkdir -p "$DIST"

NODE_VERSION="$(node -p 'process.versions.node')"
echo "[build-sea] node v$NODE_VERSION; targets: ${PLATFORMS[*]}"

# 1) Bundle to a single CommonJS file. The two optional native ws speed-ups are
#    left external — ws falls back to pure JS when they're missing, which they
#    always are inside the SEA.
echo "[build-sea] bundling with esbuild@$ESBUILD_VERSION ..."
npx --yes "esbuild@$ESBUILD_VERSION" src/sea.js \
  --bundle --platform=node --format=cjs \
  --external:bufferutil --external:utf-8-validate \
  --outfile="$DIST/blueeye-agent.cjs"

# 2) Generate the (arch-independent) SEA blob.
echo "[build-sea] generating SEA blob ..."
node --experimental-sea-config sea-config.json

# Download the official Node binary for a given dist arch (x64|arm64) and print
# the path to its `node` executable.
fetch_node() {
  local narch="$1"
  local name="node-v${NODE_VERSION}-linux-${narch}"
  local url="https://nodejs.org/dist/v${NODE_VERSION}/${name}.tar.xz"
  local out="$DIST/_node/${narch}"
  mkdir -p "$out"
  echo "[build-sea]   fetching $url" >&2
  curl -fsSL "$url" | tar -xJ -C "$out" --strip-components=1
  printf '%s' "$out/bin/node"
}

for slug in "${PLATFORMS[@]}"; do
  os="${slug%%-*}"; arch="${slug#*-}"
  [ "$os" = "linux" ] || { echo "[build-sea] only linux targets are supported (got '$slug')" >&2; exit 1; }
  case "$arch" in
    amd64) narch=x64 ;;
    arm64) narch=arm64 ;;
    *) echo "[build-sea] unsupported arch '$arch' (use amd64 or arm64)" >&2; exit 1 ;;
  esac

  bin="$DIST/blueeye-agent-$slug"
  cp "$(fetch_node "$narch")" "$bin"
  chmod u+w "$bin"
  echo "[build-sea] injecting blob -> $(basename "$bin")"
  npx --yes "postject@$POSTJECT_VERSION" "$bin" NODE_SEA_BLOB "$DIST/sea-prep.blob" \
    --sentinel-fuse "$FUSE"
  chmod 0755 "$bin"
done

# Drop intermediates; keep only the binaries + a checksum manifest.
rm -rf "$DIST/_node" "$DIST/blueeye-agent.cjs" "$DIST/sea-prep.blob"
( cd "$DIST" && sha256sum blueeye-agent-* > SHA256SUMS )

echo "[build-sea] done:"
cat "$DIST/SHA256SUMS"
