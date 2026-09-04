#!/bin/bash
# Claude Code PreToolUse hook (matcher: Bash). Before Claude runs `git push`,
# run the pre-build gate (scripts/gate.sh: security / ui / validation tests +
# the full suite). Exit 2 blocks the push and feeds the failure back to Claude
# so it fixes the tests before a branch build is created. Anything that is not
# a git push passes straight through.
set -uo pipefail

input="$(cat)"
command="$(printf '%s' "$input" | node -e '
  let s = ""; process.stdin.on("data", d => s += d).on("end", () => {
    try { process.stdout.write(String(JSON.parse(s).tool_input?.command || "")); } catch { }
  });' 2>/dev/null)"

case "$command" in
  *git*push*) ;;
  *) exit 0 ;;
esac

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$script_dir/../.." && pwd)"

if [ ! -x "$repo_dir/scripts/gate.sh" ]; then
  exit 0
fi

echo "[claude-hook] git push detected — running the pre-build gate for $(basename "$repo_dir")" >&2
out="$(bash "$repo_dir/scripts/gate.sh" 2>&1)"
rc=$?
if [ "$rc" -ne 0 ]; then
  {
    echo "Pre-build gate FAILED for $(basename "$repo_dir") — push blocked."
    echo "Fix the failing security / ui / validation tests, then push again."
    echo "--- gate output (tail) ---"
    printf '%s\n' "$out" | tail -60
  } >&2
  exit 2
fi
printf '%s\n' "$out" | tail -3 >&2
exit 0
