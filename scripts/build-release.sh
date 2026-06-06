#!/usr/bin/env bash
set -euo pipefail

# Build + sign an agent release tarball, ready to upload to blueeye-server.
#
#   AGENT_RELEASE_SIGNING_KEY=<base64 PKCS8 PEM> ./scripts/build-release.sh [version]
#
# Produces dist/blueeye-agent-<version>.tgz (+ .manifest.json + .sig) and prints
# the upload curl. The tarball is built REPRODUCIBLY (sorted names, fixed mtime/
# owner) and excludes dev/test/node_modules/secrets — the same shape the server
# extracts. The PRIVATE signing key never leaves this host.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
VERSION="${1:-$(node -p "require('./package.json').version")}"
OUT="$ROOT/dist"
TARBALL="$OUT/blueeye-agent-${VERSION}.tgz"
mkdir -p "$OUT"

echo "Packaging $TARBALL (reproducible) ..."
tar --sort=name --mtime='UTC 2020-01-01' --owner=0 --group=0 --numeric-owner \
    --exclude=./node_modules --exclude=./.git --exclude=./dist \
    --exclude=./test --exclude=./test-support --exclude=./.github \
    --exclude='./*.token' --exclude='./*.log' \
    --exclude=./.blueeye-agent --exclude=./blueeye-agent.config.json \
    -czf "$TARBALL" -C "$ROOT" .

echo "Signing ..."
exec node "$ROOT/scripts/sign-release.js" "$TARBALL" "$VERSION"
