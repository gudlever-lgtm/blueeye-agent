# blueeye-agent-go

A Go port of the BlueEye monitoring agent, specified by
[`../GO-REWRITE-AUDIT.md`](../GO-REWRITE-AUDIT.md). Goal: a single static binary
whose wire behaviour the Node **blueeye-server** cannot distinguish from the
Node agent — identical REST paths, WebSocket frames, headers and JSON shapes.

> **Status.** This milestone implements the foundation (config, token store,
> REST + WebSocket clients) and the **definition-driven collector engine** plus
> the Linux collectors. Windows/macOS collectors, sFlow, self-update and the
> shadow diffing are later milestones.

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
`trim`/`delimiter`/`skip_line`), `json` (dotted/`jq`-style paths), `key_value`
(`key: value`). Metric types: `gauge` / `counter`.

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
collectors/linux/*.json audited Linux collector definitions
```
