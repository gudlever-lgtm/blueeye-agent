#!/usr/bin/env bash
# BlueEyes pre-build test gate.
#
# Runs before a branch build is produced (git pre-push, Claude Code's git-push
# hook, and the CI workflow all call this same script) and refuses the build
# when any of the three gate categories or the full suite fails:
#
#   1. security   — test/gate/security.test.js   (auth, headers, 404/500, injection, secrets)
#   2. ui         — test/gate/ui.test.js         (dashboard/CLI wiring, i18n, static assets)
#   3. validation — test/gate/validation.test.js (input validation → 400, schema, config)
#   4. full suite — npm test
#
# Usage:  scripts/gate.sh            run the gate (cached per HEAD + worktree state)
#         scripts/gate.sh --force    ignore the cache
#         BLUEEYE_SKIP_GATE=1        skip entirely (emergency only; printed loudly)
#
# Exit code 0 = build may proceed, 1 = blocked.
set -uo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$script_dir/.." && pwd)"
cd "$repo_dir"

name="$(node -p "require('./package.json').name" 2>/dev/null || basename "$repo_dir")"
version="$(node -p "require('./package.json').version" 2>/dev/null || echo '?')"

if [ "${BLUEEYE_SKIP_GATE:-}" = "1" ]; then
  echo "[gate] !!! BLUEEYE_SKIP_GATE=1 — $name gate SKIPPED. Do not ship this build." >&2
  exit 0
fi

force=0
[ "${1:-}" = "--force" ] && force=1

# --- cache: same HEAD + same worktree contents → same result -----------------
git_dir="$(git rev-parse --git-dir 2>/dev/null || true)"
stamp=""
stamp_file=""
if [ -n "$git_dir" ]; then
  head="$(git rev-parse HEAD 2>/dev/null || echo none)"
  tree="$( { git status --porcelain --untracked-files=all; git diff HEAD; } 2>/dev/null | git hash-object --stdin 2>/dev/null || echo dirty)"
  stamp="$head:$tree"
  stamp_file="$git_dir/blueeye-gate.stamp"
  if [ "$force" = 0 ] && [ -f "$stamp_file" ] && [ "$(cat "$stamp_file")" = "$stamp" ]; then
    echo "[gate] $name v$version — already passed for this exact tree (${head:0:10}); skipping. Use --force to re-run."
    exit 0
  fi
fi

if [ ! -d node_modules ]; then
  echo "[gate] node_modules missing — installing dependencies"
  npm install --no-audit --no-fund >/dev/null 2>&1 || { echo "[gate] npm install failed" >&2; exit 1; }
fi

echo "[gate] $name v$version — security / ui / validation gate"
start=$(date +%s)
failed=()

run_phase() {
  local label="$1"; shift
  echo
  echo "[gate] ▶ $label: $*"
  if "$@"; then
    echo "[gate] ✔ $label"
  else
    echo "[gate] ✘ $label FAILED" >&2
    failed+=("$label")
  fi
}

run_phase "security"   node --test test/gate/security.test.js
run_phase "ui"         node --test test/gate/ui.test.js
run_phase "validation" node --test test/gate/validation.test.js
run_phase "full suite" npm test --silent

echo
elapsed=$(( $(date +%s) - start ))
if [ "${#failed[@]}" -gt 0 ]; then
  echo "[gate] BLOCKED — $name v$version failed: ${failed[*]} (${elapsed}s)" >&2
  echo "[gate] Fix the failures and re-run scripts/gate.sh before pushing." >&2
  [ -n "$stamp_file" ] && rm -f "$stamp_file"
  exit 1
fi

[ -n "$stamp_file" ] && printf '%s' "$stamp" > "$stamp_file"
echo "[gate] PASS — $name v$version may be built (${elapsed}s)"
exit 0
