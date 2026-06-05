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

## Sister repos

- **blueeye-server** — the on‑prem server the agent reports to and is managed from.
- **blueeye-licens** — vendor‑only license signer (no agent involvement).
