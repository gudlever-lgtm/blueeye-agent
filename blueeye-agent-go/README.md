# blueeye-agent-go

A Go port of the BlueEye monitoring agent, specified by
[`../GO-REWRITE-AUDIT.md`](../GO-REWRITE-AUDIT.md). Goal: a single static binary
whose wire behaviour the Node **blueeye-server** cannot distinguish from the
Node agent — identical REST paths, WebSocket frames, headers and JSON shapes.

> **Status.** Implemented: the foundation (config, token store, REST + WebSocket
> clients), the **definition-driven collector engine**, the **persistent
> PowerShell stream** (Windows engine infrastructure), the Linux/Windows/macOS
> collector definitions, the **sFlow receive/decode/forward path**, the
> **Ed25519-verified self-update**, and **live-server data exchange** (enrollment,
> bundled default collectors, and reporting over `/agents/results`). The
> `--shadow` diffing is the remaining milestone.

## Exchanging data with a live server

The agent is a **drop-in against a stock blueeye-server** — it speaks the audited
REST/WS protocol and needs no server changes to stream data:

1. **Enroll or reuse the token** — first start exchanges the one-time code for a
   token (`POST /agents/enroll`), stored `0600`; later starts reuse it.
2. **Bundled default collectors** — the platform collector definitions are
   **embedded in the binary** (`builtins.Definitions()`), seeded as the floor of
   the store, so the agent has a working collector set immediately even though a
   stock server pushes none. Disk cache and server-pushed definitions still
   override by version.
3. **Handshake** — on every (re)connect it reports capabilities
   (`POST /agents/me/capabilities`) and fetches its config (`GET /agents/me/config`).
4. **Report** — each collection cycle is posted to `POST /agents/results`. For the
   network collectors the reporter computes the per-interface **delta + rate +
   totals**, producing the **same `traffic` snapshot shape as the Node agent**
   (a true drop-in). A 401 there is fatal.

The full loop is covered by an end-to-end test (`internal/e2e`) that drives the
real REST + WS + engine + reporter stack against a contract-faithful stub server.

## Collectors are DATA, not code

The agent ships with **no hard-coded collectors**. The server pushes collector
**definitions** (JSON) over the authenticated WebSocket channel; the engine
schedules each one, runs its `exec` sandboxed, parses stdout with a built-in
parser, and emits metrics.

Definition shape (`internal/collector/definition.go`):

```jsonc
{
  "id": "linux.net_dev", "version": 1, "platform": "linux",
  "interval_seconds": 60,
  "exec": { "command": "cat", "args": ["/proc/net/dev"] },   // no shell; args array
  "parser": { "type": "columns", "skip_line": "\\|", "columns": [ ... ] },
  "output": { "label_fields": ["iface"], "metrics": [ { "name","type","field" } ] }
}
```

Parsers: `regex_lines` (named groups), `columns` (index → field, optional
`trim`/`delimiter`/`skip_line`/`dedupe_by`, and **negative indices** that count
from the end so a variable-width middle column doesn't shift the trailing ones),
`json` (dotted/`jq`-style paths), `key_value` (`key: value`). Metric types:
`gauge` / `counter`.

### Windows: persistent PowerShell stream

On Windows the engine keeps one long-lived `powershell.exe` running a driver
loop (`internal/collector/stream.go`). Collector bodies are written to its stdin
and each run's output is framed by a per-request marker. The **stream is code;
what runs in it is data** (definition `exec.powershell` bodies). It handles
PowerShell-not-found (start fails → collector skips), the stream dying
mid-collection (restart on next use), and stalled output (a per-collect timeout
kills and restarts the session). macOS/Linux definitions use plain `exec`.

### Engine guarantees

- **WebSocket-only trust** — definitions are installed only from the
  authenticated live channel (`store.Install` rejects every other source).
- **Disk cache** — received definitions are cached under
  `<token dir>/definitions`; on restart the cache seeds memory, then the server's
  live response overrides it (server wins).
- **Versioning** — a definition is replaced only when its `version` is strictly
  higher.
- **Sandbox** — `exec.CommandContext` with an args array (no shell), a default
  10s timeout (per-definition override), stdout capped at 1 MB (oversized →
  skip), and every server string passed as an argument, never interpolated.
- **Fail-safe** — a failing/timing-out/panicking collector logs and skips its
  cycle; it never crashes the agent.
- **Two-state audit** — install/replace writes `initiated` → `completed`/`failed`
  records (`internal/audit`).

### sFlow (engine code, not a definition)

`internal/sflow` receives hsflowd sFlow v5 datagrams on `localhost:6343`, decodes
flow samples + counter samples locally into the **same shape as the Node agent's
decoder** (rate-scaled 5-tuples, `PROTO_NAMES`, uncompressed IPv6 groups), and
forwards an aggregated flow summary (`byPort`/`byProtocol`/`topTalkers`/`totals`)
over the WebSocket channel. Malformed datagrams are **counted and dropped**, never
fatal. The flow buffer is bounded (100k); when the channel is down the forwarder
**drops the snapshot with a counter** rather than buffering unbounded
(backpressure). Enable with `BLUEEYE_SFLOW=1` (monitorConfig-driven activation is
a later step).

### Self-update (Ed25519, fail-closed)

`internal/upgrade` downloads a new binary over REST, verifies the **Ed25519
signature over the canonical manifest before touching disk** (byte-for-byte
canonicalization parity with `src/release/canonicalize.js`), and only then
self-replaces: `rename`-into-place on Linux/macOS, rename-the-running-exe on
Windows. Any verification error (no key, bad manifest, bad signature, checksum or
version mismatch, download 404/500) **fails closed** — no swap, no restart. The
whole flow is wrapped in a two-state audit (`initiated` → `completed`/`failed`),
and the **collector definitions cache survives upgrades untouched**.

## Build & test

```bash
make build      # host binary
make test       # go test ./...
make vet
make all        # cross-compile linux/{amd64,arm64}, windows/amd64, darwin/{amd64,arm64}
```

## Layout

```
cmd/blueeye-agent/      entry point
internal/config         defaults < file < env loader (+ fingerprint)
internal/tokenstore     {agentId,token} JSON at 0600
internal/apiclient      REST client, explicit 400/401/404/500 handling
internal/wsclient       reconnecting /ws/agent client (leaf-cert pinning)
internal/backoff        jittered reconnect backoff
internal/protocol       wire constants + frame shapes
internal/audit          two-state audit records
internal/collector      definitions, parsers, store, engine
internal/sflow          sFlow v5 receive/decode/aggregate/forward
internal/upgrade        Ed25519-verified binary self-update
internal/report         collector Results -> /agents/results envelopes (traffic deltas)
internal/e2e            end-to-end data-exchange test vs a stub server
builtins.go             embeds the default collector definitions into the binary
collectors/{linux,windows,darwin}/*.json  collector definitions (bundled)
```
