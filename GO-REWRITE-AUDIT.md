# GO-REWRITE-AUDIT — blueeye-agent

Audit of the Node.js **blueeye-agent** (`package.json` version **0.11.1**) as the
authoritative spec for a Go rewrite (**blueeye-agent-go**). Everything below is
compiled from the source under `src/`, cross-checked against `PROTOCOL.md`,
`codemap.md`, `REFACTOR-AUDIT.md`, the install scripts and the systemd unit.
Where the existing docs are stale or a behaviour exists **only in code**, that is
called out explicitly (§8).

Goal of the rewrite: a single static Go binary that the Node server **cannot
distinguish from the Node agent** on the wire — same endpoints, same JSON
shapes, same headers, same status-code handling, byte-for-byte.

> **Scope note for the first Go milestone.** Config loading, token storage, and
> the WebSocket + REST client are in scope. **Collectors and the sFlow path are
> NOT** (documented here for completeness / later milestones). The parenthetical
> targets in the task brief — Windows *"persistent PowerShell stream"* and macOS
> *"netstat -ib per poll"* — **do not exist in the Node agent today** (§2); they
> are design targets for the Go collectors, not audited behaviour.

---

## 1. Protocol contract

### 1.0 Transports & credential

Two transports, one credential (`src/apiClient.js`, `src/agentClient.js`):

| Transport | Modules | Auth |
| --- | --- | --- |
| REST (`fetch`) | `apiClient.js`, `enroll.js`, `speedtest.js`, `selfUpdate.js`, `cli.js` | `Authorization: Bearer <opaque token>` (enroll + `/enroll/*` are unauthenticated) |
| WebSocket `/ws/agent` | `agentClient.js` | Same Bearer token in the upgrade request headers |

The token is opaque (never a user JWT), issued once at enrollment, stored at
`tokenPath` mode `0600` (§5). Base server URL comes from config (default
`http://localhost:3000`). **TLS pinning:** when `serverCertFingerprint` is set
**and** the URL is `https:`, both transports pin the server's exact TLS **leaf**
certificate (SHA-256) on `secureConnect`, *before* the token/enrollment code is
sent (`httpsClient.js`, `agentClient.js`). Pinning uses `rejectUnauthorized:false`
+ manual leaf compare; if the pin verifier cannot be attached the agent **fails
closed** (WS) rather than run unpinned.

**Coded-error taxonomy** (thrown across modules): `TOKEN_REJECTED`, `HTTP_ERROR`,
`NO_CREDENTIALS`, `ENROLL_FAILED`, `SNMP_UNAVAILABLE`, plus updater codes
(`DOWNLOAD_FAILED`, `NO_PUBLIC_KEY`, `NO_MANIFEST`, `BAD_MANIFEST`,
`SIGNATURE_INVALID`, `CHECKSUM_MISMATCH`, `VERSION_MISMATCH`, `UNSAFE_ARCHIVE`,
`EXTRACT_FAILED`, `NPM_FAILED`).

### 1.1 The 401 rule (fatal, global)

A **401** on the WS handshake **or any REST call** is terminal: the runtime sets
`fatal`, stops all timers, `client.stop()`s, emits `'fatal'`, and `index.js`
exits **1**. The agent does **not** reconnect, does **not** re-enroll. Every
other error is non-terminal (logged, reported via `agent.error`, loop continues).
`agentClient` maps handshake 401 → fatal; `apiClient.assertOk` maps REST 401 →
`TOKEN_REJECTED` → `handleFatal()`. **403** on the WS handshake is *not* fatal —
it reconnects with backoff (server license/agent-cap).

### 1.2 Retry / timeout model (important for the Go REST client)

- **No per-call HTTP retry anywhere.** Each REST call is one-shot. On failure it
  is logged + emitted as `agent.error`, and the *next scheduled interval* is the
  only "retry". There is no exponential backoff on REST.
- **WS reconnect** is the only backoff loop: exponential with jitter,
  `delay = round(exp/2 + rand·exp/2)`, `exp = min(maxMs, baseMs·2^(attempt-1))`,
  defaults base `1000` ms → cap `30000` ms (`backoff.js`). `attempt` resets to 0
  on a successful open.
- **Timeout:** the pinned `requestJson` path uses a **15 s** request timeout
  (`httpsClient.js`); the plain global-`fetch` path has no explicit timeout
  (undici default). Go should impose an explicit timeout on all calls.
- Bodies are parsed leniently: `jsonOrEmpty` returns `{}` on non-JSON/empty.

### 1.3 REST endpoints (agent → server)

| # | Method + path | Auth | Body → success | Status handling |
| --- | --- | --- | --- | --- |
| 1 | `POST /agents/enroll` | none | `{code,hostname,platform,arch}` → **201** `{agentId,token}` | non-201 ⇒ `ENROLL_FAILED`, **no retry**; 401(bad code)/410(used/expired) collapsed into one failure |
| 2 | `GET /enroll/config` | none | → `{serverUrl,certFingerprint,releasePublicKey}` (agent reads only `certFingerprint`) | CLI enroll only; best-effort, failure ignored |
| 3 | `GET /agents/me/config` | Bearer | → `{agentId,monitorConfig}`; agent uses `monitorConfig \|\| {source:'proc'}` | 401 fatal; else keep current source |
| 4 | `POST /agents/me/capabilities` | Bearer | `{capabilities:{sources,agentVersion,managed,unavailable,nic?}}` → **200** echo | 401 fatal; else warn + `agent.error('capabilities')` |
| 5 | `POST /agents/results` | Bearer | `{results:[envelope]}` → **201** `{inserted}` | 401 fatal; else `agent.error('traffic-report')` |
| 6 | `POST /agents/probe-results` | Bearer | `{results:[…]}` → **201** `{inserted}` | 401 fatal; else `agent.error('probe'\|'scheduled-probes')` |
| 7 | `GET /speedtest/download?bytes=N` | Bearer | streams N bytes | 401 fatal; other → result `ok:false` |
| 8 | `POST /speedtest/upload` | Bearer | `application/octet-stream`, N zero bytes → `{bytes}` | 401 fatal; other → result `ok:false` |
| 9 | `POST /speedtest/results` | Bearer | `{result:{…}}` → **201** `{id}` | 401 fatal; else `agent.error('speedtest')` |
| 10 | `GET /enroll/agent-release.tgz` | Bearer* | signed release + `X-Release-*` headers | updater codes; §4 |
| 11 | `GET /enroll/agent-source.tgz` | Bearer* | legacy source bundle | updater codes; §4 |

*Endpoints 10/11 are served **unauthenticated**; the agent sends the Bearer token
anyway (harmless — note for proxy/log token-exposure reasoning).

**Content-Type:** all JSON POSTs send `Content-Type: application/json`; the
speedtest upload sends `application/octet-stream`. The pinned `requestJson`
always adds `Content-Type: application/json` + `Content-Length` when there is a
body (a Go port should not blindly copy that for the octet-stream upload — but
note the Node pinned path *does*, and the server tolerates it).

#### Envelope shapes

**Enroll request** (`enroll.js`): `{code, hostname, platform, arch}` where
`platform = process.platform` (`'linux'`/`'win32'`/`'darwin'`),
`arch = process.arch` (`'x64'`/`'arm64'`). Go must map `runtime.GOOS`/`GOARCH`
to these Node spellings (`windows`→`win32`, `amd64`→`x64`) so the server sees
identical values.

**Capabilities request** (`capabilities.js` + `runtime.reportCapabilities`):
```jsonc
{ "capabilities": {
  "sources": ["proc","snmp","netflow","sflow"],   // whichever detected
  "unavailable": { "snmp": "net-snmp not installed (npm install net-snmp)" },
  "agentVersion": "0.11.1",                        // package.json version
  "managed": "systemd" | "docker" | "unmanaged",
  "nic": [ { "iface","driver","driverVersion","firmwareVersion","busInfo","pciId" } ]  // optional; omitted when empty
} }
```
`netflow`/`sflow` are always in `sources` (always-available UDP collectors);
`proc` present iff `/proc/net/dev` readable; `snmp` present iff `net-snmp`
resolvable (else listed under `unavailable`).

**Results envelope** (`testRunner.runTest`):
```jsonc
{ "name":"auto-report"|"run-test"|<cmd>, "commandId":<id>|null, "ok":true,
  "startedAt":"<ISO>", "finishedAt":"<ISO>",
  "traffic":<snapshot>,                 // shape per active source (§2)
  "system":<metrics>|null }             // null if system sampling failed
```

**Probe result** (`probes/*`, normalized by `runProbe`): `{ts,type,target,ok,
attempts,success,rttMs,minMs,maxMs,jitterMs,lossPct,error?}` + per-type extras
(`status`, `certExpiryDays`, `bytes`, `contentType`, `hops[]`, `elements[]`,
`detail`). Server persists a subset; `attempts/success/hopCount/queries/role`
are dropped. `error` (probe couldn't run) → server `execError`.

**Speedtest result** (`speedtest.js`): `{type:'speedtest', ts, target:<host>, ok,
downMbps, upMbps, downBytes, upBytes, downMs, upMs, detail?}`. `mbps = (bytes·8 /
(ms/1000) / 1e6)` rounded to 2 dp; `null` when `ms<=0`. `detail` set only on a
leg failure. Default size 10 MiB/leg, clamped `[1 KiB, 200 MiB]`.

### 1.4 WebSocket `/ws/agent`

**Connect:** `ws(s)://host/ws/agent` (http→ws, https→wss; `search` stripped),
headers `Authorization: Bearer <token>` and `X-BlueEye-Protocol: 1`
(`protocol.js PROTOCOL_VERSION`). Server may reject with **401** (fatal) or
**403** (backoff-retry); any other close → backoff-reconnect. On every (re)open
the agent re-`reportCapabilities()` + re-`loadServerConfig()` (which re-runs the
hsflowd reconcile). Protocol-version mismatch is warn-only, never fatal.

**Liveness (two layers):**
- **Protocol ping/pong** — server pings ~30 s; the `ws` lib auto-pongs. Go must
  respond to WS control pings automatically (gorilla: default; set a read
  deadline + pong handler).
- **App heartbeat** — agent sends `{type:'heartbeat', ts:<ms epoch>}` every
  `heartbeatMs` (default 15 s). Server never parses it; any inbound frame just
  refreshes `last_seen`. Redundant by design — keep it for byte-identical
  behaviour.

Inbound frames that fail `JSON.parse` or aren't recognised are **silently
dropped** (both directions). Server caps inbound frames at 1 MiB.

#### Server → agent frames

| frame | shape | agent action |
| --- | --- | --- |
| `connected` | `{type:'connected', agentId, protocolVersion}` | emitted right after upgrade; version check (warn only) |
| `command` | `{type:'command', command:<string\|object>}` | dispatched by verb (below) |

**Command verb** is read from `name \|\| action \|\| type \|\| command` (or the
bare string). Recognizer regexes (`command.js`, case-insensitive, optional
`[\s_-]`): `run-test`, `run-probe`, `ping`, `update`(+`self-update`/`upgrade`),
`speedtest`(+`speed-test`), `diagnose`(+`diag`/`doctor`/`self-check`/`health-check`),
`delete`(+`self-delete`/`uninstall`), `install-tool`. Dispatch order in
`runtime.js`: ping → diagnose → update → delete → install-tool → speedtest →
run-probe → run-test → else `command-ignored`.

| command | extra fields | behaviour | reply frame(s) |
| --- | --- | --- | --- |
| `ping` | `id` | liveness | `ack {id,ok:true,agentVersion,sources,managed}` |
| `diagnose` | `id` | read-only pipeline snapshot | `command-result {id,ok:true,diagnostic}` |
| `run-test` | `intervalMs?` | measure + POST `/agents/results` | — (REST only) |
| `run-probe` | `probe:{…}` (required obj) | run + POST `/agents/probe-results` | — (REST only) |
| `speedtest` | `bytes?` | down/up + POST `/speedtest/results` | — (REST only) |
| `update` | `id,auditId?,version?,sha256?,signature?` | systemd only; else decline | `ack`, then `action-result`; on failure also `command-result {ok:false}` |
| `delete` | `id,auditId?` | wipe token + detached uninstall; docker declines | `ack`, then `action-result` |
| `install-tool` | `id,auditId?,tool` (required) | allowlist install; docker declines | `ack`, then `action-result` |

Probe target is read from `probe.host \|\| probe.target`.

#### Agent → server frames

| frame | shape |
| --- | --- |
| `heartbeat` | `{type:'heartbeat', ts:<ms epoch>}` |
| `ack` (ping) | `{type:'ack', id, ok:true, agentVersion, sources, managed}` |
| `ack` (update/delete/install-tool) | `{type:'ack', id, accepted:bool, runtime:'systemd'\|'docker'\|'unmanaged', reason?:'docker-managed'\|'unmanaged'}` |
| `command-result` | `{type:'command-result', id, ok:true, diagnostic}` (diagnose) · `{…, ok:false, error}` (update failure — usually dropped server-side) |
| `action-result` | `{type:'action-result', auditId, action:'upgrade'\|'delete'\|'install-tool', ok, version?, tool?, package?, manager?, detail?}` — **load-bearing**: `action:'delete', ok:true` makes the server delete the agent row |
| `sflow.status` | `{type:'sflow.status', state, detail\|null}` (`state` ∈ hsflowd states, §3) |
| `agent.error` | `{type:'agent.error', category, code\|null, message}` (message sliced to 300) |

`agent.error` categories emitted: `traffic-report`, `probe`, `capabilities`,
`config`, `probe-targets`, `scheduled-probes`, `speedtest`. Sent only when the
socket is open; a closed socket drops it (never throws). 401 is never reported
this way.

`diagnostic` payload (`buildDiagnostic`): `{agentVersion, managed, source,
sources, intervalMs, lastReportAt|null, collector:{kind,listening,datagrams,
dropped,decodedFlows,counterSamples?,bufferedFlows,lastDatagramAt}|null,
hsflowd:{state,detail}|null}`. Collector counters are read **without draining**.

### 1.5 Server limits (must respect)

Results ≤ 1000/POST, each object ≤ 65 535 bytes serialized. Probe-results ≤ 200/POST;
`hops`/`elements` ≤ 64; string caps (target 255, detail 255, contentType 120).
Capabilities object ≤ 65 535 bytes; `nic` ≤ 64 × 256-char fields. Speedtest bytes
∈ [1 KiB, 200 MiB]. Agent-side caps: traffic ≤ 64 interfaces (busiest kept,
`interfacesOmitted` counts the rest); flow summaries top-50 per list, buffer
100 000 flows; scheduled probes ≤ 16 targets/cycle.

---

## 2. Platform collectors

> **Reality check.** The Node agent's local traffic collection is **Linux-only**.
> There is no Windows and no macOS traffic collector in the codebase (verified:
> no `netstat`, `powershell`, `win32`, `darwin`, `Get-NetAdapter`, `/proc/net`
> reference outside Linux paths). On non-Linux hosts the `proc` source reads
> `/proc/net/dev`, the read throws, `snapshot()` swallows it → `{}` → an **empty
> interfaces list** every interval. The only cross-platform code is the **ping**
> and **traceroute** probes, which parse Windows/macOS CLI output. So the Go
> rewrite's Windows-PowerShell and macOS-`netstat -ib` collectors are **new
> work**, to be modelled on the Linux snapshot shape below.

The active source is chosen by the server's `monitorConfig.source`
(`monitor.createSampler`): `proc` (default) · `snmp` · `netflow` · `sflow`.
Unknown source → falls back to `proc`. A sampler is `async ({intervalMs}) =>
snapshot`; collector-backed ones also carry `.stop()`, `.stats()`, `.kind`.

### 2.1 `proc` (Linux, `trafficMonitor.js`)

Read `/proc/net/dev` twice, `intervalMs` apart; compute **non-negative deltas**
(`max(cur-prev,0)`, so counter resets/wraps don't go negative) and per-second
rates. Column map after `iface:`: rx = `bytes packets errs drop fifo frame
compressed multicast` (cols 0–7), tx = `bytes packets errs drop fifo colls
carrier compressed` (cols 8–15). Kept: `rxBytes=0, rxPackets=1, rxErrors=2,
rxDrop=3, txBytes=8, txPackets=9, txErrors=10, txDrop=11`. Lines with < 16 cols
skipped. `lo` skipped unless `includeLoopback`. Interfaces present in the second
snapshot but not the first are skipped.

Per-interface link meta from sysfs (async, best-effort → nulls):
`/sys/class/net/<if>/operstate` → `operStatus`; `/sys/class/net/<if>/speed`
(Mbps, only if finite > 0) → `speedMbps`.

**Cap:** if > `MAX_INTERFACES` (**64**), sort by `rx+tx bytes` desc, keep 64, set
`interfacesOmitted`. Totals are computed over **all** interfaces before the cap.
Snapshot:
```jsonc
{ "intervalMs":1000, "elapsedSec":1.002,
  "interfaces":[ {iface,rxBytes,txBytes,rxPackets,txPackets,rxBytesPerSec,
                  txBytesPerSec,rxErrors,txErrors,rxDrop,txDrop,operStatus,speedMbps} ],
  "interfacesOmitted":12,                // only when cap hit
  "totals":{rxBytes,txBytes,rxPackets,txPackets,rxErrors,txErrors,rxDrop,txDrop,
            rxBytesPerSec,txBytesPerSec} }
```
`elapsedSec` is measured wall-clock (`max((t1-t0)/1000, 0.001)`), not the nominal
interval. `proc` sets **no** `source` marker (only snmp does).

### 2.2 `snmp` (`snmpMonitor.js`, optional `net-snmp`)

Same output shape as proc, plus `source:'snmp'`. Polls IF-MIB HC octet counters
twice: `ifName`(1.3.6.1.2.1.31.1.1.1.1), `ifHCInOctets`(…6), `ifHCOutOctets`(…10),
best-effort health columns `ifHighSpeed`(…15, Mbps), `ifOperStatus`(2.2.1.8),
`ifIn/OutDiscards`(…13/…19), `ifIn/OutErrors`(…14/…20). Core columns (name +
octets) required; health columns tolerate a timeout. `rxPackets`/`txPackets`
always **0**. Counter64 read big-endian from the last 8 bytes. `operStatus` mapped
from the integer (1=up,2=down,3=testing,5=dormant,6=notPresent,7=lowerLayerDown).
Same 64-interface cap. If `net-snmp` missing → `SNMP_UNAVAILABLE`. **Out of scope
for the Go client milestone** — port later; needs an SNMP lib (justify the dep).

### 2.3 `netflow` (`netflow/collector.js`)

UDP collector (default `:2055`, `bindAddress` default `0.0.0.0`). Version from
first 2 bytes: 9/10 → `parseTemplated` (v9 + IPFIX, template cache persisted
across packets), else → `parseV5` (fixed 48-byte records). Malformed → `dropped++`,
debug log, never crash. Buffer capped at `maxFlows` (100 000). `drain()` →
`aggregateFlows` + `{source:'netflow', packets, droppedPackets}`.

### 2.4 `sflow` (§3)

### 2.5 Flow summary shape (`netflow/aggregate.js`, shared by sflow)

```jsonc
{ "totals":{bytes,packets,flows},
  "byPort":[{port,bytes,packets,flows}],       // top 50 by bytes
  "byProtocol":[{protocol,bytes,packets,flows}],
  "topTalkers":[{pair:"src->dst",bytes,packets,flows}] }
```
`servicePort` = lower of src/dst port (0 treated as absent). `byProtocol` key is
`protocolName || String(protocol)`. Sorted desc by bytes, sliced to `topN` (50).

### 2.6 System metrics (`systemMetrics.js`, cross-platform via `os`)

Sampled in parallel with traffic over the same window; **best-effort** (throws →
`system:null`, traffic still submitted). CPU% = busy fraction across all cores
between two `os.cpus()` tick snapshots. Fields: `{cpuPercent (1dp), cpuCount,
loadavg:[…], memTotalBytes, memUsedBytes, memFreeBytes, memUsedPercent (1dp),
uptimeSec}`. Go: `loadavg` has no stdlib equivalent on Windows — emit `[0,0,0]`
or read `/proc/loadavg` on Linux to stay faithful.

### 2.7 NIC inventory (`nicInfo.js`, Linux-only)

Best-effort, folded into capabilities. `ethtool -i <iface>` (4 s timeout) →
`driver/version/firmware-version/bus-info`; sysfs `device/{vendor,device}` →
`pciId` (`vendor:device`, `0x` stripped). Placeholders (`''`,`n/a`,`na`,`none`,
`unknown`) → null. Interfaces with no `busInfo`/`firmwareVersion`/`pciId` are
dropped (virtual). Fields clipped to 256 chars. Non-Linux → `[]`.

---

## 3. sFlow path (Option B: receive → decode locally → forward on existing channel)

Three cooperating pieces:

**(a) Receive — `sflow/collector.js`.** UDP listener (default `:6343`,
`bindAddress` default `0.0.0.0`). Each datagram: `lastAt=now`, `parseSflow`,
`decoded += flows.length`, `counterSamples += …`, push flows into a buffer capped
at `maxFlows` (100 000; excess dropped once full). Parse error → `dropped++`,
debug log. `drain()` → `aggregateFlows(buffer)` + `{source:'sflow', datagrams:
received, droppedDatagrams: dropped, sampled:true}` and clears the buffer.
`stats()` (non-draining) → `{listening, datagrams, dropped, decodedFlows,
counterSamples, bufferedFlows, lastDatagramAt}`.

**(b) Decode — `sflow/parse.js` + `sflow/decodePacket.js`.** sFlow v5 only
(datagram version field must be 5; else throw). Header: `version(4) ipVersion(4)
agentAddr(4|16) subAgentId(4) seq(4) uptime(4) numSamples(4)`. Iterate samples
(`sampleType(4) sampleLength(4) body`): types **1/3** = (expanded) flow sample →
`parseFlowSample`; types **2/4** = counter sample → `counterSamples++` only (used
by Diagnose to tell "datagrams but no packet sampling" from "no datagrams").
Flow sample body: seq, sourceId (4 or 8 if expanded), `samplingRate(4)`, pool,
drops, in/out ifIndex (8 or 16 if expanded), `numRecords(4)`; per record
(`recType(4) recLen(4) body`), **recType 1 = raw packet header** →
`header_protocol(4) frame_length(4) stripped(4) header_length(4) header[]`. The
sampled header (Ethernet II + optional one VLAN tag + IPv4/IPv6 + TCP/UDP) is
decoded to a 5-tuple by `decodeSampledHeader`; **bytes/packets are scaled by
`samplingRate`** (`rate = samplingRate>0 ? samplingRate : 1`) so a 1-in-N sample
estimates real volume. Non-IP frames → skipped. IPv6 uses next-header only (no
extension-header walking).

**(c) Forward — no new channel.** Decoded, rate-scaled flows go through the exact
same `aggregateFlows` path and are submitted under the **same `traffic` field of
the `/agents/results` envelope** as every other source (§1.3, §2.5). "Option B" =
the agent decodes sFlow locally and forwards a **flow summary over the existing
REST results channel**; it never forwards raw datagrams.

**Local exporter (hsflowd) reconcile — `sflow/hsflowd.js` + `hsflowdConfig.js`.**
Optional: only when `source==='sflow' && sflow.hsflowd` (true or options object).
Runs after every successful `GET /agents/me/config` (startup + each reconnect).
`enable(opts)` is idempotent, Linux-only (else `unknown`), docker → `not_installed`
(defer to sidecar). Steps: check installed (`command -v hsflowd` / `/usr/sbin` /
`/usr/local/sbin`); if missing, `apt-get install` build-deps (`git build-essential
clang libpcap-dev`, retry on dpkg lock) → shallow-clone `github.com/sflow/host-sflow`
into `/usr/local/src/host-sflow` → `make FEATURES=PCAP` + `install` + `schedule`;
pick sampling NIC (`opts.device` if it exists → default-route NIC → first
non-loopback); render `/etc/hsflowd.conf` (collector ip/udpport, sampling, polling,
`pcap{dev}`) with a first-line marker `# Managed by blueeye-agent`; rewrite only on
change; `systemctl enable` + (`restart` if conf changed else `start`); report the
**observed** `systemctl is-active` state. `disable()` = `systemctl disable --now`
(keep installed). `isManaged()` = conf contains the marker (survives agent
restart; lets a later delete/source-change stop an exporter a prior process
provisioned, without touching an operator-managed hsflowd).

States (must mirror server `HSFLOWD_STATES`): `active | inactive | failed |
not_installed | install_failed | permission_denied | unknown`. Permission errors
detected from `EACCES`/`EPERM` or stderr substrings; reported as their own state
rather than retried. Conf values are regex-sanitised (`SAFE_DEVICE
[A-Za-z0-9._:-]{1,32}`, `SAFE_IP [0-9a-fA-F.:]{1,45}`, bounded ints) so untrusted
input never lands verbatim in the file. **Out of scope for the Go client
milestone.**

---

## 4. Upgrade flow (`selfUpdate.js`, `release/*.js`, `runtime.handleUpdate`)

Triggered by the server `update` command; **systemd-managed agents only** —
docker/unmanaged `ack {accepted:false, reason}` + `action-result {ok:false}`.

**Two audit states on the wire** (the "two-state audit record"): the server
inserts the audit row as `requested`; the agent's terminal `action-result`
completes it as **`completed`** (`ok:true`) or **`failed`** (`ok:false`, with
`detail`). Intermediate: the immediate `ack {accepted:…}` (an `accepted:false`
marks the row failed with `reason`). So one action = `requested` → (ack) →
`completed`/`failed`. The `command-result {ok:false}` update-failure frame usually
arrives after the ack already resolved the waiter and is dropped server-side; the
failure reaches the server via `action-result` instead.

**Signature verification (Ed25519, fail-closed) — `release/verifyManifest.js`
+ `canonicalize.js`:**
1. A `signature` in the command ⇒ signed path: download `agent-release.tgz`.
2. Response headers: `X-Release-Version`, `X-Release-Signature`,
   `X-Release-Manifest` (base64 JSON `{version, sha256, …}`), `X-Content-SHA256`.
3. Verify order (any failure ⇒ refuse, nothing touches disk):
   - `publicKey` present? else `NO_PUBLIC_KEY` (**fail-closed** — no key ⇒ refuse).
   - manifest + signature headers present? else `NO_MANIFEST`.
   - `crypto.verify(null, canonicalize(manifest), publicKey, sig)` — Ed25519 over
     the **canonical** manifest bytes (keys sorted recursively, no whitespace,
     UTF-8; byte-identical to server + licens `canonicalize`). Fail ⇒
     `SIGNATURE_INVALID`.
   - `manifest.sha256 === sha256(downloaded bytes)`? else `CHECKSUM_MISMATCH`.
   - if `expectedVersion` set, `manifest.version === expectedVersion`? else
     `VERSION_MISMATCH`.
4. Legacy path (no signature): download `agent-source.tgz`, verify **sha256 only**
   against `command.sha256` (ignores `expectedVersion` — asymmetry noted).

Public key resolution (`release/publicKey.js`): `BLUEEYE_RELEASE_PUBLIC_KEY`
(PEM or base64-of-PEM) wins, else the embedded constant. The embedded value is a
`REPLACE_WITH_…` placeholder → resolves to `''` → signed updates **refused** until
a real key is provisioned. Go must implement the same canonical-JSON +
`ed25519.Verify` and the same fail-closed gate (`golang.org/x/crypto/ed25519` or
stdlib `crypto/ed25519`; parse the PEM SubjectPublicKeyInfo).

**Tar-slip guard — `assertSafeTar`:** `tar -tzf` the archive, reject any member
that is absolute or normalises to `..`/`../…` **before** extracting.

**Binary replacement per layout (there is no per-OS branch today — self-update is
Linux/systemd only):**
- **Atomic/versioned** (`BLUEEYE_RELEASES_DIR` + `BLUEEYE_CURRENT_LINK` + known
  version): extract to `releases/<version>`, `npm ci --omit=dev` (fallback
  `npm install --omit=dev`), symlink `current.next` → new dir, `rename()` over
  `current` (atomic on POSIX), write `releases/.previous` for `rollback()`,
  prune to `keepReleases` (3, keeping current+previous, oldest removed by numeric
  version compare).
- **In-place** (layout unset): `tar -xzf … -C installDir` over the tree + npm install.
- **Restart:** `action-result {ok:true, version}` is sent **before**
  `systemctl --no-block restart <service>` (after restart the old process can't
  speak). Post-restart, the new process reconnects and re-posts capabilities,
  converging the stored version and clearing the dashboard "update" badge.
- `rollback()` (operator/watchdog) repoints `current` back to `.previous`.

**For the Go rewrite:** a single static binary changes this materially — "install
deps + restart the interpreter" becomes "atomically replace the binary file
(`rename(2)`) + restart the unit". macOS/Windows self-update paths are *new
design* (out of scope for the first milestone; document the swap primitives per
OS when implemented). Local action log records
`update.start/applied/failed/declined`.

**Delete flow (`selfDelete.js`, `runtime.handleDelete`):** docker declines. Else:
disable an agent-managed hsflowd (best-effort) → `wipeToken()` (overwrite with
`randomBytes(max(size,64))` mode 0600, then unlink) → send `action-result
{action:'delete', ok:true}` **before** removal (server then deletes the agent row,
tokens cascade) → `remove()` spawns a **detached** `sh -c 'sleep 2; … uninstall.sh
--yes'` with `SERVICE_NAME`/`BLUEEYE_INSTALL_DIR`/`BLUEEYE_STATE_DIR`/
`BLUEEYE_LOG_DIR` in env. The 2 s sleep lets the WS frame flush.

**Install-tool (`toolInstaller.js`):** allowlist only — `traceroute`, `mtr`,
`tcptraceroute`, mapped per manager (`mtr`→Debian `mtr-tiny`; `tcptraceroute`
unavailable on zypper). Managers probed in order (apt/dnf/yum/zypper/apk/pacman)
via `command -v`; fixed non-interactive argv (package name is the only variable,
always from the allowlist — no shell interpolation from the wire). apt refreshes
the index first; retries on a lock; permission errors reported distinctly. Docker
declines. `action-result {ok, tool, package?, manager?, detail?}`.

---

## 5. Token handling (`tokenStore.js`, `bootstrap.js`, `config.js`)

- **Format on disk:** JSON `{ "agentId": <n|null>, "token": "<opaque>" }` +
  trailing newline. **Not** a bare token string — a Go port must read/write this
  JSON shape.
- **Location:** `config.tokenPath` — `BLUEEYE_TOKEN_PATH` env > `tokenPath` config
  key > default `<agent-dir>/.blueeye-agent/token` (relative to the module dir,
  **not** cwd). systemd installs pin it to `/var/lib/blueeye-agent/token` (outside
  the swappable release dir).
- **Permissions:** written mode `0600` with an explicit `chmod 0600` after (the
  `writeFile` mode only applies on create). Parent dir `mkdir -p`.
- **Read:** `readToken` returns `{agentId, token}` only if `token` is a non-empty
  string; any error/parse failure → `null` (treated as "not enrolled").
- **Sent as:** `Authorization: Bearer <token>` on every REST call and in the WS
  upgrade headers. Also sent (harmlessly) to the unauthenticated release
  endpoints.
- **Lifecycle:** `ensureToken` — stored token ⇒ skip enrollment; else enroll with
  `enrollmentCode`; no token and no code ⇒ throw `NO_CREDENTIALS` (no retry). On
  successful enroll: `saveToken` then `clearEnrollmentCode` (remove the code from
  the JSON config file; a code supplied purely via env cannot be unset). Wiped on
  delete (§4). Never logged (action log redacts `token`/`signature`/… keys).

---

## 6. Config (`config.js`)

Precedence: **built-in defaults < JSON config file < environment**.
Config file path: `BLUEEYE_AGENT_CONFIG` env, else `<agent-dir>/blueeye-agent.config.json`
(module-relative, not cwd — survives a deleted cwd). Bool parse: false only for
`0/false/no/off` (case-insensitive); int parse via `parseInt`, fallback on `NaN`.

| env var | file key | default | meaning |
| --- | --- | --- | --- |
| `BLUEEYE_AGENT_CONFIG` | — | `<dir>/blueeye-agent.config.json` | config file path |
| `BLUEEYE_SERVER_URL` | `serverUrl` | `http://localhost:3000` | REST + WS base |
| `BLUEEYE_ENROLLMENT_CODE` | `enrollmentCode` | `null` | first-boot code (cleared from file post-enroll) |
| `BLUEEYE_SERVER_CERT_FINGERPRINT` | `serverCertFingerprint` | `''` | TLS leaf pin (normalised; §7) |
| `BLUEEYE_TOKEN_PATH` | `tokenPath` | `<dir>/.blueeye-agent/token` | token store |
| `BLUEEYE_HEARTBEAT_MS` | `heartbeatMs` | `15000` | WS app heartbeat |
| `BLUEEYE_RECONNECT_BASE_MS` | `reconnectBaseMs` | `1000` | backoff base |
| `BLUEEYE_RECONNECT_MAX_MS` | `reconnectMaxMs` | `30000` | backoff cap (factor fixed = 2) |
| `BLUEEYE_REPORT_INTERVAL_MS` | `reportIntervalMs` | `60000` | continuous-report cadence (0 disables; server `monitorConfig.intervalMs` overrides when > 0) |
| `BLUEEYE_REPORT_SAMPLE_MS` | `reportSampleMs` | `1000` | sampling window per measurement |
| `BLUEEYE_PROBE_INTERVAL_MS` | `probeIntervalMs` | `60000` | scheduled-probe cadence (0 disables) |
| `BLUEEYE_PROBE_COUNT` | `probeCount` | `3` | attempts per scheduled probe |
| `BLUEEYE_PROBE_GATEWAY` | `probeGateway` | `true` | auto-probe default gateway (Linux only) |
| `BLUEEYE_PROBE_DNS` | `probeDns` | `true` | auto-probe resolv.conf nameservers |
| `BLUEEYE_PROBE_TARGETS` | `probeTargets` | `[]` | extra targets (`"ping:1.1.1.1,tcp:host:443,dns:example.com"`) |
| `BLUEEYE_LOG_LEVEL` | — | `info` | logger level (`index.js`) |
| `BLUEEYE_ACTION_LOG` | — | — (no-op) | local append-only action trail path |
| `BLUEEYE_SERVICE_NAME` | — | `blueeye-agent` | systemd unit for restart/uninstall |
| `BLUEEYE_RELEASES_DIR` | — | — | versioned-release root (enables atomic update) |
| `BLUEEYE_CURRENT_LINK` | — | — | `current` symlink path |
| `BLUEEYE_RUNTIME` | — | auto-detect | force `docker`/`systemd`/`unmanaged` |
| `BLUEEYE_RELEASE_PUBLIC_KEY` | — | embedded placeholder | signed-update trust anchor (PEM or base64-of-PEM) |

`monitorConfig` shape (server-driven, `GET /agents/me/config`; server strips
unknown keys): `{source:'proc'|'snmp'|'netflow'|'sflow', intervalMs?,
snmp:{host,community?,version?,port?}, netflow:{port?,bindAddress?},
sflow:{port?,bindAddress?,hsflowd?:true|{samplingRate?,pollingSecs?,device?}}}`.
Note: `bindAddress` is honoured agent-side but **stripped by older servers**
(F-04) — Go should honour it if present, default `0.0.0.0`.

`managed` runtime detection (`detectManaged`): explicit `BLUEEYE_RUNTIME` wins;
else `/.dockerenv` or `$container` ⇒ `docker`; else `$INVOCATION_ID` ⇒ `systemd`;
else `unmanaged`.

**Config writes by the agent:** token file (enroll); remove `enrollmentCode` from
the config file (enroll); CLI `enroll` additionally persists `serverUrl` +
`serverCertFingerprint` into the config file (via `writeConfigValues`, pretty
2-space JSON + trailing newline).

CLI (`cli.js`): `blueeye-agent enroll --code <C> [--server <U>] [--fingerprint
<F>] [--force]`; idempotent (existing token ⇒ no-op unless `--force`); TOFU
fingerprint discovery via `GET /enroll/config` when https + no fingerprint.

---

## 7. State persisted between restarts

| artifact | path | written by | survives update? |
| --- | --- | --- | --- |
| **Token** `{agentId,token}` | `tokenPath` (`/var/lib/blueeye-agent/token`) | enroll | yes (outside release dir) |
| **Config file** (serverUrl, cert fp, tuning; `enrollmentCode` cleared) | `BLUEEYE_AGENT_CONFIG` (`/var/lib/blueeye-agent/config.json`) | enroll / CLI | yes |
| **Action log** (append-only, redacted, 0600) | `BLUEEYE_ACTION_LOG` (`/var/log/blueeye-agent/actions.log`) | update/delete/install-tool events | yes |
| **Release dirs + `current` symlink + `.previous`** | `BLUEEYE_RELEASES_DIR` / `_CURRENT_LINK` | self-update / installer | yes (that's the point) |
| **hsflowd conf** (marker-tagged) | `/etc/hsflowd.conf` | hsflowd enable | yes (host-level; `isManaged()` re-derives ownership after restart) |
| **host-sflow build tree** | `/usr/local/src/host-sflow` | hsflowd install | yes |

**In-memory only (lost on restart, re-derived):** `hsflowdManaged` flag (re-derived
from the conf marker), `monitorConfig` (re-fetched on connect), backoff `attempts`,
`lastReportAt`, `lastHsflowdState`, netflow/sflow template cache + flow buffers.
The agent keeps **no** local traffic/probe history — everything ships to the
server. There is no PID/lock file; supervision is external (systemd/docker).

---

## 8. Undocumented / code-only behaviours (not in PROTOCOL.md/codemap/README, or doc-drifted)

1. **Windows/macOS traffic collectors — now present on `main` (updated 2026-07-04).**
   At the time this audit was written (`main` @ `57bd793`) the `proc` source was
   Linux-only and non-Linux hosts reported **no traffic** — the single biggest
   gap. That gap is now **closed on the Node side** by three PRs merged
   afterwards (#45 Windows, #46 macOS, #47 transactions):
   * **macOS** (`src/trafficMonitorDarwin.js`): `netstat -ib`, **Link-rows only**
     (`<Link#N>`), MAC-presence detection to handle the variable Address column
     (`base = col[3] has ':' ? 4 : 3`), per-interface deltas/rates in the **same
     proc snapshot shape**; `rxDrop`/`txDrop` always `0`, `operStatus`/`speedMbps`
     always `null`, `lo0` skipped, 64-interface cap.
   * **Windows** (`src/trafficMonitorWin.js`): a **persistent `powershell.exe`**
     spawned once (not per poll), ticking every 1 s and emitting one compact JSON
     line per tick `{ts, ifaces:{name:{rxBytes,rxPackets,rxErrors,rxDrop,txBytes,
     txPackets,txErrors,txDrop,operStatus,speedMbps}}}` from
     `Get-NetAdapterStatistics` (packets = Unicast+Multicast+Broadcast) +
     `Get-NetAdapter` (Status/LinkSpeed); respawn with backoff; `buildSnapshot()`
     reused for deltas/rates. This is the same "persistent PowerShell stream"
     shape the Go rewrite targets.
   * Both emit the **proc per-interface delta/rate snapshot**, so the server reads
     them uniformly.

   **Go parity implication:** the Go rewrite's Windows/macOS collectors are
   **definition-driven and emit raw cumulative counters** (server derives rates),
   whereas the Node agent now emits **agent-side deltas/rates** in the proc
   snapshot shape. These are wire-*different* traffic payloads. To keep the Node
   server from distinguishing the two, either (a) the Go engine grows a
   delta/rate stage that reshapes counter definitions into the proc snapshot, or
   (b) the shadow-diff phase accepts the counter-vs-rate difference as expected.
   Track this when reconciling the shadow output.
2. **Version drift in docs.** `PROTOCOL.md`/`REFACTOR-AUDIT.md` say `0.9.x`;
   `package.json` is **0.11.1**. Treat the code, not the docs, as truth.
3. **`X-BlueEye-Protocol: 1`** upgrade header and the whole protocol-version
   handshake (warn-only mismatch) — only in `protocol.js`/`agentClient.js`.
4. **`connected` frame carries `agentId`/`protocolVersion`** and is a distinct
   inbound type the agent emits an event for — beyond just "server sends command".
5. **App heartbeat is redundant** — server never parses it; liveness rides on WS
   ping/pong + any-frame `last_seen`. Keep it anyway for wire-identity.
6. **`action-result {action:'delete', ok:true}` deletes the server-side agent row**
   (tokens cascade) — a load-bearing side effect of a *reply frame*.
7. **Late `command-result {ok:false}` on update failure is silently dropped**
   server-side (the ack already resolved the waiter); failures propagate via
   `action-result` only (F-06).
8. **Capabilities also carries `unavailable{}`** (why a source is missing) and a
   full **NIC driver/firmware inventory** — neither in the codemap contract table.
9. **`interfacesOmitted` + 64-interface cap** (proc + snmp), busiest-kept, totals
   over all — an anti-DoS shape a naive Go port would miss.
10. **Non-negative counter deltas** (`max(cur-prev,0)`) guard against counter
    resets/wraps — silent but important for correctness.
11. **`bindAddress` for netflow/sflow is honoured agent-side but stripped by
    older servers** (dead config against those servers; F-04).
12. **`sflow.status` frame** and the seven-value hsflowd state machine — only in
    code; not in codemap.
13. **hsflowd self-provisioning from source** (apt build-deps → clone → make) and
    the **`# Managed by blueeye-agent` conf marker** used as cross-restart
    ownership — entirely code-level. Delete/uninstall historically **orphaned**
    this exporter (F-02, since fixed).
14. **Enrollment collapses 401 vs 410** into one `ENROLL_FAILED` (operator can't
    tell "bad code" from "used/expired").
15. **Config/token paths are module-relative, not cwd-relative** — deliberate, so
    a deleted cwd (post-uninstall) doesn't crash startup (`uv_cwd` ENOENT).
16. **Self-update sends the Bearer token to unauthenticated release endpoints**
    (token exposure surface through proxies/logs; F-16).
17. **Pinned `requestJson` always stamps `Content-Type: application/json`** even
    on the octet-stream speedtest upload (server tolerates it); the plain-`fetch`
    path sets the correct content type. A Go port should pick one consistently and
    verify the server accepts it.
18. **Signed-update `manifest.version` check is skipped in the legacy sha-only
    path** — asymmetric verification (F-16).
19. **`command-ignored`/unknown-frame handling is silent** on both sides (no debug
    trace by default).
20. **The agent never re-enrolls automatically** — any 401 is terminal and needs
    manual intervention.

---

## 9. Go rewrite implications (summary, first milestone)

- **In scope now:** config loader (defaults<file<env, module-relative paths, bool/int
  parsing), token store (the `{agentId,token}` JSON at 0600), REST client (all §1.3
  endpoints, one-shot, explicit timeout, 400/401/404/500 handled explicitly — 401
  fatal, others logged + `agent.error` + continue), WS client (upgrade headers,
  `connected`/`command` dispatch, all agent→server frames, heartbeat, ping/pong,
  401-fatal / 403-backoff / else-reconnect with the exact jittered backoff),
  Ed25519 canonical-manifest verification primitive, `managed`/platform detection,
  the Node-spelling `platform`/`arch` mapping.
- **Deferred:** proc/snmp/netflow/sflow collectors, hsflowd lifecycle, probes,
  speedtest transfers, self-update binary-swap, install/uninstall scripting.
- **Allowed deps:** `gorilla/websocket` (or `nhooyr.io/websocket`),
  `golang.org/x/crypto` (Ed25519 is also in stdlib `crypto/ed25519`). Everything
  else stdlib; justify any addition.
- **Build:** single static binary; Makefile cross-compile `linux/amd64`,
  `linux/arm64`, `windows/amd64`, `darwin/amd64`, `darwin/arm64`.
- **Byte-for-byte fidelity is the acceptance test:** the Node server must not be
  able to tell the Go agent apart — identical paths, headers, JSON keys/shapes,
  status handling, frame vocabulary.
</content>
</invoke>
