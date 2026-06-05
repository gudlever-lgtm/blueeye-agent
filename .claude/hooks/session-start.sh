#!/bin/bash
# SessionStart hook (Claude Code on the web): activate the tracked git hooks so
# the package version auto-bumps on every commit (.githooks/pre-commit), and
# install dependencies so tests run in this session. Idempotent + best-effort;
# it never blocks session startup.
set -uo pipefail

root="${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"

# Make the tracked hooks active for this fresh clone (git config is not cloned).
git config core.hooksPath "$root/.githooks" 2>/dev/null || true

if [ -f "$root/package.json" ] && command -v npm >/dev/null 2>&1; then
  ( cd "$root" && npm install --no-audit --no-fund >/dev/null 2>&1 ) || echo "session-start: npm install skipped"
fi
