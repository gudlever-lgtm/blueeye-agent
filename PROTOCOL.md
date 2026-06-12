# blueeye-agent ↔ blueeye-server protocol

Complete wire contract between the agent and **blueeye-server**, as implemented
in agent `v0.9.1`. Compiled from the agent source and cross-checked against the
server's routes/validators (`blueeye-server/src/routes/agentReports.js`,
`agentEnroll.js`, `enroll.js`, `speedtest.js`, `src/ws/agentSocket.js`,
`src/validation/*`). Discrepancies found while writing this are catalogued in
[REFACTOR-AUDIT.md](REFACTOR-AUDIT.md).

Two transports, one credential:

| Transport | Where (agent) | Auth |
| --- | --- | --- |
| REST (`fetch`) | `src/apiClient.js`, `src/enroll.js`, `src/speedtest.js`, `src/selfUpdate.js`, `src/cli.js` | `Authorization: Bearer <opaque agent token>` (enrollment + `/enroll/*` are unauthenticated) |
| WebSocket `/ws/agent` | `src/agentClient.js` | Same Bearer token in the upgrade request headers |

The token is issued once at enrollment and stored at `tokenPath` (mode `0600`).
It is an opaque agent credential, never a user JWT. The server also accepts a
`?token=` query parameter on the WS upgrade (`ws/wsCommon.js`); the agent only
uses the header. With `serverCertFingerprint` configured and an `https` server
URL, both transports pin the server's exact TLS leaf certificate (SHA-256)
before sending the token (`src/httpsClient.js`, `src/agentClient.js`).

**401 anywhere is fatal**: WS handshake or any REST call answering 401 puts the
runtime into a terminal state (`TOKEN_REJECTED` / `'fatal'`); the agent stops
all timers, does not reconnect, does not re-enroll, and exits 1.

---

## 1. REST calls (agent → server)

### 1.1 `POST /agents/enroll` — one-time enrollment (unauthenticated)

`src/enroll.js`. The one-time code is the credential.

```jsonc
// request
{ "code": "<one-time code>", "hostname": "host1", "platform": "linux", "arch": "x64" }
// 201 response — the plaintext token is returned exactly once
{ "agentId": 42, "token": "<opaque token>" }
```

Server outcomes (`routes/agentEnroll.js`): `201` ok · `400` validation ·
`401` invalid code · `410` used/expired code. The agent treats any non-201 as
`ENROLL_FAILED` and does not retry (it does not distinguish 401 from 410).
On success the agent stores `{ agentId, token }` at `tokenPath` and deletes
`enrollmentCode` from its config file.

### 1.2 `GET /enroll/config` — server discovery (unauthenticated)

Used only by the `blueeye-agent enroll` CLI (`src/cli.js`) as a
trust-on-first-use fallback to discover the cert fingerprint when none was
passed/embedded. Response: `{ serverUrl, certFingerprint|null, releasePublicKey|null }`.
The agent reads only `certFingerprint`.

### 1.3 `GET /agents/me/config` — fetch the server-assigned monitor config

`src/apiClient.js getConfig()`. Called at startup and on every WS (re)connect.

```jsonc
// 200 response
{ "agentId": 42, "monitorConfig": { "source": "proc" } }
```

The agent uses `body.monitorConfig || { source: 'proc' }`. The `monitorConfig`
shape (validated server-side in `validation/agentValidation.js
validateMonitorConfig`; everything else is stripped):

```jsonc
{
  "source": "proc" | "snmp" | "netflow" | "sflow",   // required
  "intervalMs": 1000..86400000,                       // optional; overrides reportIntervalMs
  "snmp":    { "host": "...", "community"?: "...", "version"?: "1"|"2c", "port"?: 1..65535 },  // when source=snmp
  "netflow": { "port"?: 1..65535, "bindAddress"?: "<IP literal>" },   // when source=netflow ({} ⇒ agent defaults 2055)
  "sflow":   { "port"?: 1..65535, "bindAddress"?: "<IP literal>",     // when source=sflow ({} ⇒ agent defaults 6343)
               "hsflowd"?: true | {                   // self-provision a local Host sFlow exporter
                 "samplingRate"?: 1..16777216, "pollingSecs"?: 1..86400,
                 "device"?: "<iface, [A-Za-z0-9._:-]{1,32}>" } }
}
```

`bindAddress` (server ≥ 0.25.0) is the UDP address the agent's flow collector
binds — e.g. `127.0.0.1` when only the local hsflowd exports, keeping the
collector off the LAN. Unset ⇒ the agent binds `0.0.0.0`. Older servers strip
the key (the agent then uses the default).

### 1.4 `POST /agents/me/capabilities` — report capabilities + NIC inventory

`src/apiClient.js postCapabilities()`. Sent once at startup and again on every
WS (re)connect (converges the stored agent version after a self-update).

```jsonc
// request
{ "capabilities": {
    "sources": ["proc", "snmp", "netflow", "sflow"],  // required: array of strings
    "agentVersion": "0.9.0",                           // package.json version
    "managed": "systemd" | "docker" | "unmanaged",     // supervision (decides self-update/delete)
    "nic": [ {                                         // optional; omitted when empty/unreadable
      "iface": "eth0", "driver": "e1000e", "driverVersion": "...",
      "firmwareVersion": "...", "busInfo": "0000:00:1f.6", "pciId": "8086:15b8"
    } ]
} }
// 200 response
{ "agentId": 42, "capabilities": { ...echoed, nic normalised... } }
```

Server validation: `sources` must be an array of strings; `nic` (if present) is
normalised — max 64 entries, 6 known string fields, each ≤ 256 chars, malformed
entries dropped; whole object must serialise ≤ 64 KiB. Extra fields
(`agentVersion`, `managed`) pass through and are stored verbatim in
`agents.capabilities`.

### 1.5 `POST /agents/results` — traffic + system measurements

`src/apiClient.js postResults()`. Sent on the continuous-reporting interval and
for each server `run-test` command. Always a one-element batch today.

```jsonc
// request
{ "results": [ <result envelope> ] }
// 201 response
{ "inserted": 1 }
```

Result envelope (`src/testRunner.js runTest()`):

```jsonc
{
  "name": "auto-report" | "run-test" | <command name>,  // 'auto-report' ⇒ continuous reporting
  "commandId": <command.id> | null,
  "ok": true,
  "startedAt": "<ISO>", "finishedAt": "<ISO>",
  "traffic": <traffic snapshot>,   // shape depends on the active source, below
  "system": <system metrics> | null  // null when sampling failed (best-effort)
}
```

**Traffic snapshot — `proc` (default) and `snmp`** (`src/trafficMonitor.js`,
`src/snmpMonitor.js`): per-interface rates over the sampling window.

```jsonc
{
  "source": "snmp",            // only the snmp sampler sets `source`; proc has no marker
  "intervalMs": 1000, "elapsedSec": 1.002,
  "interfaces": [ {
    "iface": "eth0",
    "rxBytes": 0, "txBytes": 0, "rxPackets": 0, "txPackets": 0,   // deltas (snmp: packets always 0)
    "rxBytesPerSec": 0, "txBytesPerSec": 0,
    "rxErrors": 0, "txErrors": 0, "rxDrop": 0, "txDrop": 0,
    "operStatus": "up" | null, "speedMbps": 1000 | null
  } ],
  "interfacesOmitted": 12,     // only when the cap below kicked in
  "totals": { "rxBytes": 0, "txBytes": 0, "rxPackets": 0, "txPackets": 0,
              "rxErrors": 0, "txErrors": 0, "rxDrop": 0, "txDrop": 0,
              "rxBytesPerSec": 0, "txBytesPerSec": 0 }
}
```

The `interfaces` list is capped at the **64 busiest** interfaces (by rx+tx
bytes over the window) so a veth-farm host can't push a result over the
server's 64 KiB per-result limit; `totals` always cover every interface, and
`interfacesOmitted` says how many entries were dropped (absent when none).

**Traffic snapshot — `netflow` / `sflow`** (`src/{netflow,sflow}/collector.js
drain()` + `src/netflow/aggregate.js`): flow summary since the last drain.

```jsonc
{
  "source": "netflow" | "sflow",
  "packets": 12, "droppedPackets": 0,        // netflow naming
  "datagrams": 12, "droppedDatagrams": 0, "sampled": true,   // sflow naming
  "totals": { "bytes": 0, "packets": 0, "flows": 0 },
  "byPort":     [ { "port": 443, "bytes": 0, "packets": 0, "flows": 0 }, ... ],      // top 50 by bytes
  "byProtocol": [ { "protocol": "tcp", "bytes": 0, "packets": 0, "flows": 0 }, ... ], // top 50
  "topTalkers": [ { "pair": "10.0.0.1->93.184.216.34", "bytes": 0, "packets": 0, "flows": 0 }, ... ] // top 50
}
```

**System metrics** (`src/systemMetrics.js`):

```jsonc
{ "cpuPercent": 12.3, "cpuCount": 8, "loadavg": [0.1, 0.2, 0.3],
  "memTotalBytes": 0, "memUsedBytes": 0, "memFreeBytes": 0, "memUsedPercent": 42.1,
  "uptimeSec": 12345 }
```

Server validation (`validation/resultsValidation.js`): `results` is a
non-empty array, ≤ 1000 items, each a JSON object serialising to **≤ 65 535
bytes** (the whole payload is otherwise opaque to validation; it is stored as a
JSON blob and interpreted downstream by analysis/flow pipelines).

### 1.6 `POST /agents/probe-results` — active probe results

`src/apiClient.js postProbeResults()`. Sent after a `run-probe` command (one
result) and on the scheduled-probe interval (a batch, max 16 targets/cycle).

```jsonc
// request
{ "results": [ <probe result>, ... ] }   // server cap: 200 per POST
// 201 response
{ "inserted": N }
```

Normalized probe result (`src/probes/*`; all types):

```jsonc
{
  "ts": "<ISO>",                       // stamped by runProbe
  "type": "ping"|"tcp"|"dns"|"traceroute"|"http"|"curl"|"pageload"|"transaction",
  "target": "<host / URL>",
  "ok": true|false,
  "attempts": 4, "success": 4,         // NOT persisted by the server
  "rttMs": 1.2, "minMs": 1.0, "maxMs": 1.5, "jitterMs": 0.1, "lossPct": 0,
  "error": "<only when the probe could not RUN at all>"   // → server `execError` + `detail`
}
```

Per-type extras:

| type | extra fields sent | notes |
| --- | --- | --- |
| `ping` | — | `jitterMs` = ping's `mdev` |
| `tcp` | — | |
| `dns` | `detail` = first resolved address | |
| `traceroute` | `hops: [{hop, ip, sent, recv, lossPct, rttMs, minMs, maxMs, jitterMs}]`, `hopCount`, `queries` | `hopCount`/`queries` not persisted; `hops` capped server-side at 64 |
| `http` | `status`, `certExpiryDays` (https), `detail` (cert detail) | |
| `curl` | `status`, `bytes`, `contentType`, `detail` (assertion summary) | metadata only, never the body |
| `pageload` | `status`, `bytes` (page weight), `elements: [{url, kind, status, bytes, ms}]`, `detail` | `elements` capped server-side at 64 |
| `transaction` | `status` (last step), `bytes` (total), `elements` (`kind` = `"step N METHOD"`), `detail` | extracted variables never leave the agent |

Server persistence (`validation/probeValidation.js`): keeps `ts, type, target,
ok, rttMs, minMs, maxMs, jitterMs, lossPct, hops, status, certExpiryDays,
bytes, contentType, elements, detail, execError`; strings length-capped
(target 255, detail 255, contentType 120, hop ip 45, element url 255).
Everything else (`attempts`, `success`, `hopCount`, `queries`, `role`) is
silently discarded. `error` is mapped to `execError` (and into `detail` when no
`detail` was sent) — `execError` drives the server's `agent.probe-failed`
auditing and the traceroute auto-install trigger.

### 1.7 Speed test — `GET /speedtest/download`, `POST /speedtest/upload`, `POST /speedtest/results`

`src/speedtest.js` (triggered by the `speedtest` command):

1. `GET /speedtest/download?bytes=N` (Bearer) — server streams N zero bytes
   (default 10 MiB, hard cap 200 MiB). Agent times the full read.
2. `POST /speedtest/upload` (Bearer, `application/octet-stream`, N zero bytes)
   — server counts and discards; replies `{ bytes }`. Agent times the send.
3. `POST /speedtest/results` (Bearer):

```jsonc
// request
{ "result": {
    "type": "speedtest",            // not persisted
    "ts": "<ISO>", "target": "<server host>", "ok": true,
    "downMbps": 940.12, "upMbps": 880.0,
    "downBytes": 10485760, "upBytes": 10485760,
    "downMs": 89, "upMs": 95,
    "detail": "download: ..." }     // only on failure (ok:false)
}
// 201 response
{ "id": 7 }
```

Server validation (`validation/speedtestValidation.js`): the six numeric fields
must be finite ≥ 0 (or null); `target`/`detail` capped at 255.

### 1.8 Self-update downloads — `GET /enroll/agent-release.tgz` / `GET /enroll/agent-source.tgz`

`src/selfUpdate.js` (triggered by the `update` command). Both endpoints are
served unauthenticated; the agent sends its Bearer token anyway (harmless).

* **Signed release** (`agent-release.tgz`, chosen when the command carries a
  `signature`): response headers `X-Release-Version`, `X-Release-Signature`,
  `X-Release-Manifest` (base64 JSON `{version, sha256, ...}`),
  `X-Content-SHA256`. The agent verifies Ed25519(manifest) against its pinned
  release public key, then `manifest.sha256` against the downloaded bytes, then
  `manifest.version` against the commanded version — all before extraction.
  Fail-closed: no configured key ⇒ refuse.
* **Legacy source bundle** (`agent-source.tgz`): verified only against the
  command's `sha256`.

Related install-time endpoints (used by `install.sh` / `install-systemd.sh`,
not by the running agent): `GET /enroll/agent-release` (metadata JSON),
`GET /enroll/agent-release-key` (PEM trust anchor), `GET /enroll/:code/install.sh`,
`GET /enroll/uninstall.sh`.

---

## 2. WebSocket `/ws/agent`

Connection: `ws(s)://<server>/ws/agent` with `Authorization: Bearer <token>`.
Server rejects the upgrade with 401 (bad token → agent fatal, no reconnect) or
403 (license/agent-cap — agent retries with backoff). On any other drop the
agent reconnects with exponential backoff + jitter (50–100% of
`min(maxMs, baseMs·2^(attempt-1))`, default 1 s → 30 s cap). On every (re)open
the agent re-reports capabilities and re-fetches its monitor config (which also
re-runs the hsflowd reconcile).

Liveness is two-layered:

* **Protocol pings** — server pings every 30 s; the `ws` library auto-pongs;
  a client that missed a ping is terminated.
* **Application heartbeat** — agent sends `{type:'heartbeat'}` every
  `heartbeatMs` (default 15 s). The server never parses it; *any* inbound frame
  just refreshes `last_seen` (throttled to one DB write/minute).

Inbound frames at the server are capped at 1 MiB. Frames the agent doesn't
recognise, and frames that fail JSON.parse, are silently ignored on both sides.

### 2.1 Server → agent frames

| frame | shape | when |
| --- | --- | --- |
| `connected` | `{ type:'connected', agentId }` | immediately after the upgrade |
| `command` | `{ type:'command', command: <string or object> }` | operator/dashboard actions, test packages, auto-install |

`command` may be a bare string (`"run test"`) or an object whose verb is read
from `name` \|\| `action` \|\| `type` \|\| `command` (`src/command.js`).
Correlated commands carry an `id` (server-generated, e.g. `"s<ts36>-<seq>"`)
that the agent echoes in its `ack`/`command-result`; audited actions carry an
`auditId` echoed in `action-result`.

Command vocabulary (recognizer regexes in `src/command.js`; the server sends
the canonical names shown):

| command (canonical) | extra fields sent by server | agent behaviour | reply frames |
| --- | --- | --- | --- |
| `ping` | `id` | none (liveness) | `ack {id, ok:true, agentVersion, sources, managed}` |
| `diagnose` (aliases: diag, doctor, self-check, health-check) | `id` | snapshot flow pipeline (read-only) | `command-result {id, ok:true, diagnostic}` |
| `run-test` | `intervalMs?` (1..86400000) | measure traffic+system, POST `/agents/results` | — (REST only) |
| `run-probe` | `probe: <spec>` (required object) | run probe, POST `/agents/probe-results` | — (REST only) |
| `speedtest` (alias: speed-test) | `bytes?` | down/up transfer, POST `/speedtest/results` | — (REST only) |
| `update` (aliases: self-update, upgrade) | `id`, `auditId?`, `version?`, `sha256?`, `signature?` | systemd only: download+verify+install+restart; docker/unmanaged decline | `ack {id, accepted, runtime, reason?}`, then `action-result`; on failure also `command-result {id, ok:false, error}` |
| `delete` (aliases: self-delete, uninstall) | `id`, `auditId?` | wipe token + detached `uninstall.sh`; docker declines | `ack {id, accepted, runtime, reason?}`, then `action-result` |
| `install-tool` | `id`, `auditId?`, `tool` (required string) | install from agent's own allowlist (traceroute/mtr/tcptraceroute); docker declines | `ack {id, accepted, runtime, reason?}`, then `action-result` |

Probe `spec` (built by the server's `validateProbeSpec`): `{ type, host,
count?, port? (tcp), maxHops?/queries? (traceroute), maxElements? (pageload),
method?/expectStatus?/expectBody?/expectHeader?/minBytes?/maxBytes? (curl),
steps?/name? (transaction) }`. The agent reads the target from
`spec.host || spec.target` (http-family probes get the URL in `host`).

Anything unrecognised is logged and dropped (`command-ignored`).

### 2.2 Agent → server frames

| frame | shape | server handling (`ws/agentSocket.js`) |
| --- | --- | --- |
| `heartbeat` | `{ type:'heartbeat', ts:<ms epoch> }` | not parsed; refreshes `last_seen` like any frame |
| `ack` (ping) | `{ type:'ack', id, ok:true, agentVersion, sources, managed }` | resolves the pending waiter for `id`; `POST /agents/:id/ping` returns `agentVersion`/`sources`/`managed` |
| `ack` (update/delete/install-tool) | `{ type:'ack', id, accepted:bool, runtime:'systemd'\|'docker'\|'unmanaged', reason?:'docker-managed'\|'unmanaged' }` | resolves the waiter; `accepted:false` marks the audit row failed with `reason` |
| `command-result` | `{ type:'command-result', id, ok:true, diagnostic }` (diagnose) · `{ type:'command-result', id, ok:false, error }` (update failure) | resolves the waiter for `id` (diagnose reads `reply.diagnostic`); an update-failure result usually arrives after the waiter timed out/was resolved by the ack, so it is dropped — the failure reaches the server via `action-result` instead |
| `action-result` | `{ type:'action-result', auditId, action:'upgrade'\|'delete'\|'install-tool', ok:bool, version?, tool?, package?, manager?, detail? }` | completes the `agent_action_audit` row (`completed`/`failed`, detail ≤ 300 chars or `"version X"`); `action:'install-tool'` adds an `agent.install-tool` audit event; `action:'delete', ok:true` **deletes the agent row** (tokens cascade) and notifies the dashboard |
| `sflow.status` | `{ type:'sflow.status', state, detail\|null }` | `state` validated against `active\|inactive\|failed\|not_installed\|install_failed\|permission_denied\|unknown` (else `unknown`), `detail` ≤ 300; kept in-memory per agent (repopulated on reconnect), shown on the agents list, pushed to the dashboard |
| `agent.error` | `{ type:'agent.error', category, code\|null, message }` | recorded as a recurring `agent.error` audit event, deduped per `(agent, category, code)`; `category` ≤ 48, `code` ≤ 48, `message` → `reason` ≤ 300; pushed to the dashboard |

`agent.error` categories currently emitted (`src/runtime.js reportError`):
`traffic-report`, `probe`, `capabilities`, `config`, `probe-targets`,
`scheduled-probes`, `speedtest`. Best-effort: sent only when the socket is
open; a closed socket drops the frame (the server infers offline anyway). A 401
is never reported this way (it is fatal instead).

`diagnostic` shape (`src/runtime.js buildDiagnostic()`):

```jsonc
{ "agentVersion": "0.9.0", "managed": "systemd",
  "source": "sflow", "sources": ["proc","netflow","sflow"],
  "intervalMs": 60000, "lastReportAt": "<ISO>" | null,
  "collector": { "kind": "sflow", "listening": true, "datagrams": 0, "dropped": 0,
                 "decodedFlows": 0, "counterSamples": 0,   // sflow only
                 "bufferedFlows": 0, "lastDatagramAt": "<ISO>"|null } | null,
  "hsflowd": { "state": "active", "detail": null } | null }
```

---

## 3. Configuration the agent reads

Precedence: **built-in defaults < JSON config file < environment** (`src/config.js`).
Default config path: `BLUEEYE_AGENT_CONFIG`, else `<agent dir>/blueeye-agent.config.json`
(the systemd installer pins it to `/var/lib/blueeye-agent/config.json` so it
survives release swaps).

| env var | file key | default | used for |
| --- | --- | --- | --- |
| `BLUEEYE_AGENT_CONFIG` | — | `<agent dir>/blueeye-agent.config.json` | config file location |
| `BLUEEYE_SERVER_URL` | `serverUrl` | `http://localhost:3000` | REST + WS base URL |
| `BLUEEYE_ENROLLMENT_CODE` | `enrollmentCode` | — | first-boot enrollment (cleared from the file after success) |
| `BLUEEYE_SERVER_CERT_FINGERPRINT` | `serverCertFingerprint` | — | TLS leaf pinning (REST + WS + enroll) |
| `BLUEEYE_TOKEN_PATH` | `tokenPath` | `<agent dir>/.blueeye-agent/token` | token store (`0600`) |
| `BLUEEYE_HEARTBEAT_MS` | `heartbeatMs` | `15000` | WS app heartbeat |
| `BLUEEYE_RECONNECT_BASE_MS` / `_MAX_MS` | `reconnectBaseMs` / `reconnectMaxMs` | `1000` / `30000` | WS reconnect backoff |
| `BLUEEYE_REPORT_INTERVAL_MS` | `reportIntervalMs` | `60000` | continuous reporting cadence (0 disables; server `monitorConfig.intervalMs` overrides) |
| `BLUEEYE_REPORT_SAMPLE_MS` | `reportSampleMs` | `1000` | sampling window per measurement |
| `BLUEEYE_PROBE_INTERVAL_MS` | `probeIntervalMs` | `60000` | scheduled probes cadence (0 disables) |
| `BLUEEYE_PROBE_COUNT` | `probeCount` | `3` | attempts per scheduled probe |
| `BLUEEYE_PROBE_GATEWAY` | `probeGateway` | `true` | auto-probe the default gateway |
| `BLUEEYE_PROBE_DNS` | `probeDns` | `true` | auto-probe resolv.conf nameservers |
| `BLUEEYE_PROBE_TARGETS` | `probeTargets` | `[]` | extra targets (`"ping:1.1.1.1,tcp:host:443,dns:example.com"`) |
| `BLUEEYE_LOG_LEVEL` | — | `info` | logger (`src/index.js`) |
| `BLUEEYE_ACTION_LOG` | — | — (no-op) | local append-only action trail (`src/runtime.js`, `src/selfDelete.js`) |
| `BLUEEYE_SERVICE_NAME` | — | `blueeye-agent` | systemd unit for restart/uninstall (`src/selfUpdate.js`, `src/selfDelete.js`) |
| `BLUEEYE_RELEASES_DIR` | — | — | versioned-release layout root (`src/selfUpdate.js`) |
| `BLUEEYE_CURRENT_LINK` | — | — | `current` symlink path (`src/selfUpdate.js`, `src/selfDelete.js`) |
| `BLUEEYE_RUNTIME` | — | auto-detect | force `docker`/`systemd`/`unmanaged` (`src/capabilities.js`; else `/.dockerenv`/`$container` ⇒ docker, `$INVOCATION_ID` ⇒ systemd) |
| `BLUEEYE_RELEASE_PUBLIC_KEY` | — | embedded placeholder | release trust anchor, PEM or base64-of-PEM (`src/release/publicKey.js`); unset/placeholder ⇒ signed updates refused |

Config **writes** by the agent: token file at enrollment; `enrollmentCode`
removed from the config file after enrollment; the CLI enroll additionally
persists `serverUrl` + `serverCertFingerprint` into the config file. Other
inputs read at runtime: `/proc/net/dev`, `/sys/class/net/*` (traffic + NIC
info), `/proc/net/route` + `/etc/resolv.conf` (probe targets, hsflowd device),
`/etc/hsflowd.conf` (managed exporter config).

Server-driven config: `monitorConfig` (§1.3) selects the traffic source, the
collector port, the reporting interval, and whether to self-provision hsflowd.

---

## 4. Server-initiated flows

### 4.1 Upgrade (self-update; systemd-managed agents only)

1. Operator hits `POST /agents/:id/update` (admin). Server picks the latest
   **signed release** (version+sha256+signature) or falls back to the source
   bundle (sha256 only), records an `agent_action_audit` row (`requested`), and
   pushes `{name:'update', id, auditId, version?, sha256, signature?}`
   (8 s wait).
2. Agent (`src/runtime.js handleUpdate`):
   - non-systemd ⇒ `ack {accepted:false, runtime, reason}` +
     `action-result {ok:false, detail:reason}`; server marks the audit failed.
   - systemd ⇒ `ack {accepted:true, runtime:'systemd'}` immediately.
3. Download from `/enroll/agent-release.tgz` (signed) or
   `/enroll/agent-source.tgz` (legacy) — §1.8 verification, fail-closed.
4. `assertSafeTar` (reject absolute / `..` members), then install:
   - **Atomic layout** (`BLUEEYE_RELEASES_DIR` + `BLUEEYE_CURRENT_LINK` + known
     version): extract to `releases/<version>`, `npm ci --omit=dev` (fallback
     `npm install`), atomically repoint `current` (symlink + rename), record
     `.previous` for `rollback()`, prune to 3 releases.
   - otherwise: in-place extract over the install dir + npm install.
5. `action-result {auditId, action:'upgrade', ok:true, version}` is sent
   **before** restarting (after restart the old process can't speak), then
   `systemctl --no-block restart <service>`.
6. On failure: `command-result {id, ok:false, error}` +
   `action-result {ok:false, detail}`; the audit row completes as failed.
7. After restart the agent reconnects and re-posts capabilities, which
   converges the stored `agentVersion` (clears the dashboard "update" badge).
   Steps are also recorded locally in the action log
   (`update.start/applied/failed/declined`).

### 4.2 Delete (self-removal)

1. Operator hits `POST /agents/:id/delete` (admin). Server audits `requested`
   and pushes `{name:'delete', id, auditId}` (8 s wait).
2. Agent (`src/runtime.js handleDelete`):
   - docker ⇒ `ack {accepted:false, runtime:'docker', reason:'docker-managed'}` +
     `action-result {ok:false}` (the host removes the container).
   - else ⇒ `ack {accepted:true, runtime}`.
3. `wipeToken()` — overwrite the token file with random bytes, then unlink
   (`src/selfDelete.js`).
4. `action-result {auditId, action:'delete', ok:true}` is sent **before**
   removal (afterwards there is neither token nor process). On receiving it the
   server completes the audit row, **deletes the agent row** (tokens cascade)
   and pushes `agent-status: deleted` to the dashboard.
5. `remove()` — detached `sh -c 'sleep 2; ... uninstall.sh --yes'` (the sleep
   lets the WS frame flush). `uninstall.sh` stops+disables the systemd unit,
   deletes the unit + drop-ins, and removes the install dir, state dir
   (token/config) and log dir.
6. Failures before step 5 ⇒ `action-result {ok:false, detail}`; audit row
   `failed`; agent keeps running. Local action log records
   `delete.start/token-wiped/declined/failed`.

### 4.3 Install-tool

`POST /agents/:id/install-tool {tool}` (operator+) or the server's auto-install
trigger (on a probe `execError` like `"traceroute not installed"`, opt-in,
throttled). Push `{name:'install-tool', id, auditId, tool}` → agent ack
(docker declines) → the agent checks the tool against **its own allowlist**
(`traceroute`/`mtr`/`tcptraceroute` mapped per package manager in
`src/toolInstaller.js`; apt/dnf/yum/zypper/apk/pacman, non-interactive, retry
on dpkg lock) → `action-result {action:'install-tool', ok, tool, package?,
manager?, detail?}`. The server records the outcome as an `agent.install-tool`
audit event.

### 4.4 hsflowd reconcile (local sFlow exporter)

Runs after every successful `GET /agents/me/config` — i.e. at startup and on
each WS reconnect (`src/runtime.js reconcileHsflowd`):

* desired = `source === 'sflow' && sflow.hsflowd` ⇒
  `enable({collectorPort: sflow.port||6343, samplingRate?, pollingSecs?, device?})`;
* was managed and no longer desired ⇒ `disable()` (stop+disable, keep installed);
* result state is logged, kept for `diagnose`, and reported as a
  `sflow.status` frame (best-effort; resent on the next reconnect).

`enable()` (`src/sflow/hsflowd.js`) is idempotent: Linux-only (else `unknown`),
docker ⇒ `not_installed` + sidecar hint; installs hsflowd from source if
missing (apt build-deps → shallow clone `sflow/host-sflow` →
`make FEATURES=PCAP && make install && make schedule`); picks the sampling NIC
(configured-if-present → default-route NIC → first non-loopback); renders
`/etc/hsflowd.conf` (`collector ip/udpport`, `sampling`, `polling`,
`pcap{dev}`); rewrites it only on change; `systemctl enable` +
`restart`/`start`; reports the **observed** `systemctl is-active` state.
States: `active | inactive | failed | not_installed | install_failed |
permission_denied | unknown` (mirrored by the server's `HSFLOWD_STATES`).

---

## 5. Limits & truncation summary

| where | limit |
| --- | --- |
| `POST /agents/results` | ≤ 1000 results/POST; each result object ≤ 65 535 bytes serialized |
| `POST /agents/probe-results` | ≤ 200 results/POST; `hops`/`elements` ≤ 64 entries; target ≤ 255, detail/execError ≤ 255, contentType ≤ 120 |
| `POST /agents/me/capabilities` | object ≤ 65 535 bytes; `nic` ≤ 64 entries × 256 chars/field |
| speed test transfers | 1 KiB ≤ bytes ≤ 200 MiB per direction |
| WS inbound (server) | 1 MiB/frame |
| `agent.error` | category/code ≤ 48, message ≤ 300 (server-side) ; message ≤ 300 (agent-side slice) |
| `sflow.status.detail`, `action-result.detail` | ≤ 300 (server-side) |
| scheduled probes | ≤ 16 targets per cycle (agent-side) |
| traffic snapshots | ≤ 64 interfaces per snapshot, busiest kept (agent-side; `interfacesOmitted` counts the rest) |
| flow summaries | top 50 per byPort/byProtocol/topTalkers; collector buffer 100 000 flows |
