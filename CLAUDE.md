# CLAUDE.md — blueeye-agent

Monitoring agent that runs on customer machines. It enrolls with **blueeye-server**
using a one‑time code, then reports traffic/system/flows/probes over `/ws/agent`
(WebSocket) and REST.

See **[codemap.md](codemap.md)** for the module map.

## Conventions (must follow)

- **CommonJS only**, plain Node.js, single runtime dependency (`ws`). **No** build
  step, **not** TypeScript, **not** ESM.
- **Dependency injection** — `createX(deps)` factories; tests wire fakes (notably
  `test-support/fakeServer.js`). Run tests: `npm test` (`node --test`).
- **Privacy by design** — metadata only (ports/ASN/timings/5‑tuple), never payload/DPI.
- **Version every change** — bump `package.json` `version` on each update (patch = fix,
  minor = feature, major = breaking). The server packages **this** agent's source +
  version and serves it; the dashboard flags deployed agents that are behind, so the
  bump is what makes "update available" appear (and what a one‑click Update upgrades
  *to*). Use `npm version <patch|minor> --no-git-tag-version`. Keep it in lockstep with
  the matching server change.
- **Keep the server backward‑compatible in mind** — agents in the field update on their
  own schedule (one‑click Update for systemd installs, or re‑running the installer).

## Server‑driven commands (over `/ws/agent`)

`src/runtime.js` handles commands the server pushes: `run-test`, `run-probe`, `ping`
(liveness ack), `update` (self‑update, systemd only), and `speedtest`. Adding one =
a recognizer in `src/command.js` + a handler in `src/runtime.js` + a `fakeServer`
endpoint (if it calls back) + tests.

## ai-codex (AI codebase index)

- [`ai-codex`](https://github.com/skibidiskib/ai-codex) generates a compact, token-cheap
  `.ai-codex/` index for AI assistants. Run it with `npm run codex` (wraps
  `npx ai-codex`); defaults come from `codex.config.json`.
- **Status: currently a no-op here.** ai-codex only reads ESM `export`/TypeScript,
  Next.js/SvelteKit routing, and Prisma/Drizzle schemas. This agent is CommonJS + plain
  Node.js (see conventions above), so every generator is skipped and `.ai-codex/` comes
  out empty. **Rely on [codemap.md](codemap.md)** for the module map. The `codex` script +
  config are kept wired up so the index starts producing output if the stack ever adopts
  TS.

## Pre-build gate (security / UI / validation tests)

No branch build exists without the gate passing. `scripts/gate.sh` runs the three
gate suites in `test/gate/` — **security**, **ui**, **validation** — and then the
full `npm test`, and refuses the build on any failure. It runs from three places
that all call the same script:

- **Claude Code** — `.claude/settings.json` has a `PreToolUse` hook on `Bash`
  (`.claude/hooks/pre-push-gate.sh`): any `git push` runs the gate first; a failing
  gate blocks the push (exit 2) and feeds the failures back to Claude to fix.
- **git** — `.githooks/pre-push` (activated by the SessionStart hook via
  `core.hooksPath`) runs it for every human push too.
- **CI** — `.github/workflows/gate.yml` runs it on every branch push and pull request.

The result is cached per `HEAD` + worktree state (`.git/blueeye-gate.stamp`), so a
push straight after a green run is instant. `scripts/gate.sh --force` re-runs;
`BLUEEYE_SKIP_GATE=1` skips (emergency only, printed loudly).

The gate suites sweep the whole surface rather than one feature at a time (every
registered route, every validator, every `data-view`/`t()` key). **When you add a
route, a validator, a nav view or an i18n key, the gate tells you what to extend**
(an allowlist entry, a PAGE_INFO entry, a catalogue key) — extend it deliberately,
never loosen the sweep.

## Sister repos

- **blueeye-server** — the on‑prem server the agent reports to and is managed from.
- **blueeye-licens** — vendor‑only license signer (no agent involvement).
