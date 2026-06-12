# Refactor audit — agent ↔ server protocol

Audit of blueeye-agent `v0.9.0` against blueeye-server (HEAD of both repos),
covering: protocol surface vs documentation, contract mismatches, config reads,
the upgrade/delete flows, and hsflowd/sFlow management. The full protocol as
implemented is documented in [PROTOCOL.md](PROTOCOL.md). **Audit only — no code
was changed.** Line references are to the audited revisions.

Severity: **P1** behaviour broken in a supported configuration · **P2**
correctness/robustness risk in realistic conditions · **P3** drift, dead code,
doc/test gaps.

## Fix status (updated 2026-06-12)

| finding | status |
| --- | --- |
| F-01 | **Fixed** in agent 0.9.1 — `makePinnedFetch` is binary-safe with `headers.get()`/`arrayBuffer()`; pinned-TLS regression tests cover update (signed + legacy) and speedtest |
| F-02 | **Fixed** in agent 0.9.1 — delete and the reconcile loop disable a marker-managed exporter (survives restarts); `uninstall.sh` stops it and removes the agent-authored conf |
| F-03 | **Fixed** in agent 0.9.1 — the runtime passes `config.tokenPath` to the self-deleter |
| F-04 | **Fixed** in server 0.25.0 — `bindAddress` validated + persisted for netflow/sflow, with a dashboard field so a UI edit round-trips it |
| F-05 | **Fixed** in agent 0.9.1 — interface lists capped at the 64 busiest (proc + snmp), `interfacesOmitted` marks the rest; totals still cover all |
| F-06 … F-16 | open |

The finding texts below are kept as written at audit time (line references are
to the audited revisions, before the fixes).

---

## P1 — bugs

### F-01 · Cert pinning breaks self-update and speed test (`makePinnedFetch` is not fetch-compatible)

When `serverCertFingerprint` is set and the server URL is https, the runtime
swaps in `makePinnedFetch` for **all** REST calls (`src/runtime.js:92-94`) and
passes it to the updater and speed test (`src/runtime.js:428-436`, `:536`). But the
pinned fetch (`src/httpsClient.js:91-101`) implements only `status/ok/json()/text()`:

1. **Self-update always fails when pinned.** `selfUpdate` calls
   `res.arrayBuffer()` (`src/selfUpdate.js:60`) → `TypeError: res.arrayBuffer
   is not a function`. Even if it existed, `requestJson` reads the body with
   `res.setEncoding('utf8')` (`src/httpsClient.js:69`), which would corrupt the
   binary tarball, and the signed path needs `res.headers.get(...)`
   (`src/selfUpdate.js:66-69`) which is also missing → `NO_MANIFEST`.
   Net effect: on a pinned deployment every dashboard **Update** fails with a
   `command-result`/`action-result` error, while unpinned (http/dev) agents
   work — exactly the production-hardened configuration is the broken one.
2. **Speed test fails or measures garbage when pinned.** The download path
   calls `res.arrayBuffer()` (`src/speedtest.js:38`) → caught → submitted as
   `ok:false, detail:"download: res.arrayBuffer is not a function"`. If it got
   past that, the upload would `JSON.stringify` the `Buffer` body
   (`src/httpsClient.js:52`), inflating ~3.4× and mislabelling the content.

The fake server has TLS tests (`test/certPinning.test.js`) but none that drive
`update`/`speedtest` through `makePinnedFetch`, which is why this never fails
in CI. Fix direction: give `makePinnedFetch` binary-safe bodies
(`Buffer.concat`), `arrayBuffer()` and a `headers.get()` shim — or use
`undici.Agent`/`tls.checkServerIdentity`-style pinning under the real `fetch`.

### F-02 · Self-delete and uninstall leave a self-installed hsflowd running

The agent may install and enable a systemd `hsflowd` service on the host
(`src/sflow/hsflowd.js:173-198`). Neither removal path ever stops it:

* `uninstall.sh:79-111` removes the agent service/dirs only — no
  `systemctl disable --now hsflowd`, no mention of `/etc/hsflowd.conf` or
  `/usr/local/src/host-sflow`.
* The server-commanded delete flow (`src/runtime.js handleDelete:458-485`)
  wipes the token and spawns `uninstall.sh` without calling
  `hsflowd.disable()` first.

Result: after **Delete**, an orphaned root daemon keeps sampling packets and
exporting sFlow to 127.0.0.1:6343 where nothing listens — on a customer
machine, from a product whose pitch is privacy-by-design. The disable path also
has a second hole: `hsflowdManaged` is in-memory only (`src/runtime.js:115`,
`:239-243`), so if the server flips the source away from `sflow` while the
agent is down, the restarted agent never had `hsflowdManaged=true` and never
disables the exporter.

---

## P2 — correctness / robustness risks

### F-03 · Self-delete wipes the wrong token path for file-configured `tokenPath`

`createSelfDeleter` defaults `tokenPath` to `BLUEEYE_TOKEN_PATH` env or
`<agent>/.blueeye-agent/token` (`src/selfDelete.js:28`), and the runtime
constructs it without passing the loaded config (`src/runtime.js:81`). If the
operator set `tokenPath` via the JSON config file (supported:
`src/config.js:64-67`), delete wipes/removes the **default** path: the real
token survives both the secure wipe and the `BLUEEYE_STATE_DIR` removal derived
from it (`src/selfDelete.js:50-57`). Pass `config.tokenPath` (and the config
path) into the deleter.

### F-04 · `monitorConfig.*.bindAddress` is dead config

The agent honours `netflow.bindAddress` / `sflow.bindAddress`
(`src/monitor.js:51`, `:56`), but the server's `validateMonitorConfig` strips
everything except `port` (+ `sflow.hsflowd`) (`blueeye-server/src/validation/
agentValidation.js:66-117`), so a real server can never deliver it. Either add
it to the server validator (it is useful — binding the collector to localhost
when only the local hsflowd exports) or drop it agent-side. Today it's
untestable-against-the-contract code.

### F-05 · Unbounded `interfaces` array vs the server's 64 KiB per-result cap

`sampleTraffic` reports **every** non-loopback interface
(`src/trafficMonitor.js:80-111`) with no count cap, while
`POST /agents/results` rejects any single result over 65 535 bytes
(`blueeye-server/src/validation/resultsValidation.js:4`, `:32`). A docker/k8s
host with a few hundred veth interfaces (~200 bytes each) exceeds the cap, and
then **every** continuous report 400s, forever — the agent logs and emits
`agent.error` (`traffic-report`) but never recovers, and the server stores no
traffic at all for that host. Consider capping/aggregating interfaces (e.g.
top-N by rate + a rollup entry), or filtering virtual interfaces like
`nicInfo.js` already does.

### F-06 · Update failure detail can be lost; late `command-result` is always dropped

`sendCommandAndWait`'s waiter is resolved by the **ack** and deleted
(`blueeye-server/src/ws/agentSocket.js:148-155`). The agent's later
`command-result {ok:false,error}` for a failed update (`src/runtime.js:446`)
therefore finds no waiter and is silently discarded. The failure only reaches
the server when the command carried an `auditId` (then `action-result`
completes the audit row). `recordRequested` can return null (no audit repo /
insert failure) — in that case a failed update is invisible server-side.
Minor today, but the `command-result` error path is effectively dead code on
the wire; either drop it or give it server-side handling.

### F-07 · hsflowd: non-permission `systemctl` failures are swallowed without detail

In `enable()` only permission failures of `systemctl enable` and
`systemctl start/restart` are checked (`src/sflow/hsflowd.js:241-247`); any
other failure (`ENOENT` — no systemd; unit masked; bad unit) is ignored at that
point. The subsequent `activeState()` usually lands on
`inactive`/`failed`/`unknown`, so the *state* is roughly right, but the
**stderr detail explaining why is dropped** — the dashboard shows `failed`
with no reason while e.g. `install_failed` carries `firstLine(stderr)`.
Capture `st.stderr` into the result detail for non-ok, non-permission results.

---

## P3 — drift, docs, tests, silent-error inventory

### F-08 · Command vocabulary is under-documented in both repo docs

Agent handles **eight** commands (`src/command.js`): `run-test`, `run-probe`,
`ping`, `update`, `speedtest`, `diagnose`, `delete`, `install-tool`.

* `CLAUDE.md` ("Server-driven commands") lists five — missing `diagnose`,
  `delete`, `install-tool`.
* `codemap.md` ("Server → agent commands", lines 140-147) lists three —
  missing `ping`, `update`, `speedtest`, `diagnose`, `delete`.
* `codemap.md` "At a glance" still says probes are
  `ping · tcp · dns · traceroute · http` (line 21) — `curl`, `pageload`,
  `transaction` exist (and the same table omits them while the probe table
  below documents them).

### F-09 · REST surface in `codemap.md` is incomplete

The "Server API surface (the contract)" table (codemap.md:127-138) omits five
endpoints the agent calls: `POST /speedtest/results`, `GET /speedtest/download`,
`POST /speedtest/upload` (`src/speedtest.js`, `src/apiClient.js:69`),
`GET /enroll/agent-release.tgz` / `GET /enroll/agent-source.tgz`
(`src/selfUpdate.js:55`), and `GET /enroll/config` (`src/cli.js:68`).

### F-10 · Agent→server WS frames are mostly undocumented

The agent emits six frame types (`heartbeat`, `ack`, `command-result`,
`action-result`, `sflow.status`, `agent.error`); only `agent.error` is
mentioned in `codemap.md` (error-model section). Nothing documents the two
distinct `ack` shapes (ping vs accepted/declined) or the `action-result`
contract that drives audit completion and **server-side agent-row deletion**
(`blueeye-server/src/ws/agentSocket.js:189-216`) — that last one is a
load-bearing side effect that deserves documentation. Now covered by
PROTOCOL.md §2.2; the codemap should link to it.

### F-11 · `fakeServer.js` is not contract-complete despite the "contract-faithful" claim

`test-support/fakeServer.js` lacks `POST /agents/probe-results` — the endpoint
`run-probe` and scheduled probes call back to — so `test/runtime.test.js:100`
stubs `fetch` by URL instead of exercising the stub. Also missing:
`/enroll/agent-release.tgz`, `/enroll/agent-source.tgz` (self-update tests
build their own one-off fakes). CLAUDE.md's own rule ("adding one = … a
`fakeServer` endpoint (if it calls back)") was not followed for `run-probe`.
The fake also doesn't model enrollment 410 (used/expired) — only 401.

### F-12 · Env/config reference is incomplete in `codemap.md`

The env table (codemap.md:151-163) is missing 10 variables the code reads:
`BLUEEYE_SERVER_CERT_FINGERPRINT`, `BLUEEYE_PROBE_INTERVAL_MS`,
`BLUEEYE_PROBE_COUNT`, `BLUEEYE_PROBE_GATEWAY`, `BLUEEYE_PROBE_DNS`,
`BLUEEYE_PROBE_TARGETS`, `BLUEEYE_ACTION_LOG`, `BLUEEYE_SERVICE_NAME`,
`BLUEEYE_RELEASES_DIR`/`BLUEEYE_CURRENT_LINK`, `BLUEEYE_RUNTIME`,
`BLUEEYE_RELEASE_PUBLIC_KEY` — and the file-key equivalents. Full list now in
PROTOCOL.md §3.

### F-13 · Server-side doc gap: `/speedtest` routes absent from CODEMAP.md

`blueeye-server/CODEMAP.md`'s route table has no row for the agent-facing
`/speedtest` router (`src/routes/index.js:213-215` mounts it); `grep speedtest
CODEMAP.md` finds nothing. The `/ws/agent` frame vocabulary is likewise
undocumented server-side.

### F-14 · Fields silently dropped or ignored across the boundary (informational)

Not bugs — the server normalises defensively — but the contract is implicit:

* Probe results: `attempts`, `success`, `hopCount`, `queries`, `role` are
  discarded by `validateProbeResults`; loss/jitter are recomputable, but
  `attempts/success` (sample size) are not recoverable from `lossPct` alone.
* Speedtest: `type:'speedtest'` discarded.
* `heartbeat` frames: never parsed server-side; liveness actually rides on
  WS ping/pong (30 s) + any-frame `last_seen` touches (60 s throttle). The
  app-level heartbeat is redundant by design — worth one doc sentence so
  nobody "fixes" it.
* Aliases (`self-update`, `upgrade`, `uninstall`, `doctor`, …) are accepted by
  the agent but never sent by the server — keep (back-compat) or prune.
* `agentSocket.broadcast(hostId, message)` (server) pushes e.g. `finding`
  frames to **agent** sockets; the agent silently drops unknown frame types
  (`src/agentClient.js:136-148`). Currently unused in `server.js`
  (`publishFinding` goes to the dashboard socket) — dead server code.

### F-15 · Silent-error inventory (hsflowd / sFlow path, plus runtime)

"Reported" = surfaced as a state/log/audit; "silent" = no trace anywhere.

| where | behaviour | verdict |
| --- | --- | --- |
| `src/sflow/hsflowd.js:89-91` `readFile` | conf read error → `null` → treated as "no conf" → conf rewritten + service **restarted on every reconcile** (each WS reconnect) | silent churn; an EACCES here masquerades as a clean re-enable |
| `src/sflow/hsflowd.js:241-242` `systemctl enable` | non-permission failure ignored entirely | silent (see F-07) |
| `src/sflow/hsflowd.js:246-247` `systemctl start/restart` | non-permission failure → only the *state* from `is-active`, stderr dropped | semi-silent (state without reason) |
| `src/sflow/hsflowd.js:119-127` `activeState` | `systemctl` missing (`ENOENT`) → `unknown` with no detail | semi-silent |
| `src/sflow/hsflowd.js` `status/enable/disable` outer `catch` | → `{state:'unknown', detail: err.message}` | reported (by design) |
| `src/runtime.js:252` `client.send(sflow.status)` | socket closed → frame dropped, no retry until next reconnect | semi-silent (intentional, commented; the *enable side effects already happened* with no server feedback in between) |
| `src/runtime.js:221-227` config fetch fails | `reconcileHsflowd()` not run at all → desired-state drift (e.g. a disable never applied) until the next successful config load | silent drift window |
| `src/monitor.js:14-15` collector `start()` | bind failure (EADDRINUSE etc.) → one local `logger.warn`, then the sampler **drains an empty buffer forever**: the server receives endless zero-flow summaries with no `agent.error` | semi-silent — only `diagnose` (`listening:false`) reveals it; consider an `agent.error('collector', …)` |
| `src/{netflow,sflow}/collector.js` parse errors | counted in `dropped`, debug log | reported (documented design) |
| `src/sflow/hsflowdConfig.js:42-51` sanitisation | out-of-range port/sampling/device silently replaced with defaults (e.g. unknown 33-char device → `eth0`) | silent, but server validation makes mismatches unreachable in practice |
| `src/sflow/hsflowd.js` `pickSamplingDevice` | can't enumerate interfaces → trusts configured value, no log | silent |
| `src/agentClient.js:53-56` heartbeat send | error swallowed | silent (close handler covers it) |
| `src/agentClient.js:137-141` inbound parse | bad JSON / unknown type dropped | silent (acceptable; log at debug would help) |
| `src/runtime.js:134-143` `reportError` | any throw swallowed | silent by design (error reporter must not throw) |
| `src/selfDelete.js:47-61` `remove()` | detached `uninstall.sh` outcome unobservable; if it fails after the token wipe, the host keeps a running agent whose token the server already cascaded away → 401-fatal crash-loop under systemd `Restart=on-failure` until `StartLimitBurst` | silent by construction; document as accepted risk or verify via the action log |
| `src/actionLog.js:35-39` append | write error swallowed | silent by design (documented) |

### F-16 · Minor protocol notes

* Self-update downloads send the Bearer token to endpoints that are
  deliberately unauthenticated (`src/selfUpdate.js:57`) — harmless, but worth
  knowing when reasoning about token exposure through proxies/logs.
* The unsigned (legacy) update path ignores `expectedVersion` — verification is
  sha-only (`src/selfUpdate.js:87-91`); fine, but asymmetric with the signed path.
* Enrollment: the agent collapses 401 (bad code) and 410 (used/expired) into
  one `ENROLL_FAILED`; the operator-facing message could distinguish them since
  the server already does.
* `monitor.js:45` falls back to `proc` silently when `source:'snmp'` arrives
  without an `snmp` object — unreachable via the server validator, but a log
  line would help if validation ever regresses.

---

## Suggested order of attack

1. **F-01** (pinned-fetch) — broken feature in the hardened config; add a
   pinned-TLS integration test for `update` + `speedtest` against the fake
   server while fixing it.
2. **F-02** (orphaned hsflowd) — add `hsflowd.disable()` to `handleDelete` and
   an hsflowd section to `uninstall.sh`; persist or re-derive "was managed"
   (e.g. detect the agent-authored marker comment in `/etc/hsflowd.conf`).
3. **F-03** (tokenPath plumb-through) — one-line wiring fix + test.
4. **F-05** (interface cap) — agent-side cap keeps old servers happy
   (backward-compatible by definition).
5. **F-04 / F-06 / F-07** — small contract/observability fixes.
6. Docs/tests batch: **F-08…F-13** (update codemap/CLAUDE.md, link PROTOCOL.md,
   add the missing fakeServer endpoints), then keep PROTOCOL.md as the single
   source of truth for the wire contract.

Per repo convention, each fix lands with a `package.json` version bump (agent +
server in lockstep where both sides change). F-01…F-05 shipped as agent 0.9.1 /
server 0.25.0 (see the fix-status table above); the remaining items are the
docs/tests batch.
