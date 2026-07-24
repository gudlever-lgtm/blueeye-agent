# blueeye-agent — code map

A navigation guide to the codebase. The agent runs on a customer machine,
enrolls once with a one-time code, holds a WebSocket open to **blueeye-server**
for status + commands, and submits **traffic measurements** and **probe
results** over REST. Written in Node (CommonJS, `'use strict'`), one runtime
dependency (`ws`); HTTP uses Node's built-in `fetch`.

> For the user-facing setup/install story see [`README.md`](README.md). This
> file is the developer/agent map: how the pieces fit and where to look.

## At a glance

| | |
| --- | --- |
| Entry point | [`src/index.js`](src/index.js) → `main()` (only place that calls `process.exit`) |
| Composition root | [`src/runtime.js`](src/runtime.js) → `createAgentRuntime()` ties WS + REST + commands together |
| Live channel | [`src/agentClient.js`](src/agentClient.js) — WebSocket to `/ws/agent` |
| REST | [`src/apiClient.js`](src/apiClient.js) — Bearer-authenticated calls |
| Traffic sources | proc · snmp · netflow · sflow (server picks per agent) |
| Active probes | ping · tcp · dns · traceroute · http |
| Transaction tests | [`src/transactions/`](src/transactions/) — server pushes `transaction_config` over WS; the manager schedules each http/tcp/dns/icmp test (`interval_sec` ±10% jitter), runs an executor (Node core `http`/`https`/`net`/`dns` + system `ping`), classifies the failure phase, buffers results (max 1000, oldest dropped) and flushes `transaction_result` batches on reconnect. Config persists to a local JSON file with secrets AES-256-GCM-encrypted (key derived from the token) |
| Tests | `node --test` over [`test/`](test) against [`test-support/fakeServer.js`](test-support/fakeServer.js) |

## Boot sequence

[`src/index.js`](src/index.js) `main()`:

1. `loadConfig()` — defaults < JSON file < env ([`config.js`](src/config.js)).
2. `collectSystemInfo()` — hostname / platform / arch ([`system.js`](src/system.js)).
3. `ensureToken()` ([`bootstrap.js`](src/bootstrap.js)):
   - stored token? use it, **skip enrollment**;
   - else `POST /agents/enroll` ([`enroll.js`](src/enroll.js)), save token `0600`
     ([`tokenStore.js`](src/tokenStore.js)), clear the code from the config file.
   - No token and no code → throw (no retry).
4. `createAgentRuntime({...}).start()`.
5. Signals: `SIGINT`/`SIGTERM` → `runtime.stop()` + exit 0; `'fatal'` → exit 1.

Every exit goes through `exit(code)`, which sets `process.exitCode`, drains
lingering network handles ([`shutdown.js`](src/shutdown.js) `closeNetworkHandles`
— undici's global dispatcher + the http/https global agents) and then lets the
event loop **drain naturally** (an unref'd backstop hard-exits only if a handle
unexpectedly lingers). It deliberately does *not* `process.exit()`: a forced exit
races libuv's teardown of the sockets from the last request, and on Windows that
trips a native assertion (`src\win\async.c:94`) that aborts with a non-zero code —
which made a *successful* `enroll` look like a failure to the installer
(`$LASTEXITCODE -ne 0` → "enrollment failed"). The `enroll` CLI also runs over
core http/https ([`cli.js`](src/cli.js) → `makePinnedFetch`), never undici, so no
keep-alive socket is left open to drain in the first place.

## Architecture

```
                         ┌────────────────────────────────────────────┐
                         │            runtime.js (composition)          │
   index.js  ── start ──▶│  • reportCapabilities (+NIC info) → loadCfg   │
   (boot/exit)           │  • startReporting (continuous, on interval)  │
                         │  • on command: run-test / run-probe          │
                         └───┬───────────────┬───────────────────┬──────┘
                             │               │                   │
                    agentClient.js      apiClient.js        monitor.js
                    (WebSocket)          (REST/Bearer)      createSampler()
                       /ws/agent          POST /agents/*          │
                       heartbeat          GET  /agents/me/config  │  picks one source
                       reconnect          backoff.js              ▼
                       401 = fatal                    ┌───────────┴───────────┐
                                                      │ proc   snmp  netflow  │
                                                      │ sflow                 │
                                                      └───────────────────────┘
                                                       testRunner.js wraps a
                                                       sampler + systemMetrics
```

Two security boundaries: the agent's opaque token is used **only** against
agent endpoints (WS + `/agents/*`); it is not a user JWT.

## Core abstraction: traffic sources

The server assigns each agent a `monitorConfig` (fetched from
`GET /agents/me/config`). [`monitor.js`](src/monitor.js) `createSampler(monitorConfig)`
turns it into a **sampler** — a callable `async ({ intervalMs }) => snapshot`.
Collector-backed sources also carry a `.stop()` for their background socket;
callers must `sampler.stop?.()` before replacing one.

| `source` | Module | How it measures | Snapshot shape |
| --- | --- | --- | --- |
| `proc` (default) | [`trafficMonitor.js`](src/trafficMonitor.js) (Linux) / [`trafficMonitorWin.js`](src/trafficMonitorWin.js) (Windows) | Linux: reads `/proc/net/dev` twice, `intervalMs` apart. Windows: one persistent `powershell.exe` (spawned once, not per poll) ticks `Get-NetAdapterStatistics`/`Get-NetAdapter` and streams a JSON line per tick over stdout; both feed the same `buildSnapshot()` delta/rate computation | per-interface rx/tx bytes·packets·errors·drops + rates, `operStatus`/`speedMbps`, `totals` |
| `snmp` | [`snmpMonitor.js`](src/snmpMonitor.js) | polls IF-MIB HC octet counters (+ health columns) twice over SNMP | same per-interface shape as proc (`source:'snmp'`) |
| `netflow` | [`netflow/collector.js`](src/netflow/collector.js) | UDP :2055 collector, `drain()` per interval | flow summary: `byPort` / `byProtocol` / `topTalkers` / `totals` |
| `sflow` | [`sflow/collector.js`](src/sflow/collector.js) | UDP :6343 collector, rate-scaled samples | same flow-summary shape (`sampled:true`) |

proc/snmp give a per-interface **rate** snapshot; netflow/sflow give a **flow
summary**. Both land under the same `traffic` field in the result, so
server/dashboard treat them uniformly. Unknown source → falls back to `proc`.

### NetFlow / sFlow parsing pipeline

```
UDP packet ─▶ collector.js ─▶ parse ─▶ flow records ─▶ aggregate.js ─▶ {byPort, byProtocol, topTalkers, totals}
                              │
   NetFlow v5  ──────────────┤  parseV5.js          (fixed 48-byte records)
   NetFlow v9 / IPFIX ───────┤  parseTemplated.js   (template-cached; fields.js decodes IEs)
   sFlow v5  ────────────────┘  parse.js → decodePacket.js (decodes sampled Ethernet/IP/L4 header)
```

| File | Responsibility |
| --- | --- |
| [`netflow/parseV5.js`](src/netflow/parseV5.js) | Pure parser for NetFlow v5 packets → `{ header, flows }`. |
| [`netflow/parseTemplated.js`](src/netflow/parseTemplated.js) | NetFlow v9 + IPFIX; learns Template FlowSets, caches them across packets. |
| [`netflow/fields.js`](src/netflow/fields.js) | IE field decoders + `applyField`/`finaliseFlow`; `PROTO_NAMES`. |
| [`netflow/aggregate.js`](src/netflow/aggregate.js) | Folds flow records into per-port/proto/talker summaries + a capped per-5-tuple `flows` list (proto+ports, feeds the server's service dependency graph). Shared by sflow. |
| [`localIps.js`](src/localIps.js) | This host's own non-loopback IPs (`os.networkInterfaces()`), reported as `capabilities.ips` so the server can resolve a flow IP back to the host. |
| [`sflow/parse.js`](src/sflow/parse.js) | Parses sFlow v5 datagrams; scales sampled bytes by sampling rate. |
| [`sflow/decodePacket.js`](src/sflow/decodePacket.js) | Decodes the sampled raw frame (Eth+IPv4/IPv6+TCP/UDP) to a 5-tuple. |
| [`sflow/hsflowd.js`](src/sflow/hsflowd.js) | Self-managed hsflowd lifecycle (install/configure/start/stop + state machine) so a host exports sFlow to its own collector. Docker agents defer to the [hsflowd sidecar](docker/hsflowd). |
| [`sflow/hsflowdConfig.js`](src/sflow/hsflowdConfig.js) | Renders `/etc/hsflowd.conf` (collector, sampling, polling, pcap device). |

## Active probes

[`probes/index.js`](src/probes/index.js) `runProbe(spec)` dispatches by
`spec.type` through a `RUNNERS` lookup and **never throws** — an unknown type or
a runner error resolves to an `ok:false` result stamped with `ts`.

| Type | Module | Method |
| --- | --- | --- |
| `ping` | [`probes/ping.js`](src/probes/ping.js) | system `ping`, parses loss% + min/avg/max/mdev (Linux/macOS/Windows). |
| `tcp` | [`probes/tcp.js`](src/probes/tcp.js) | times N connect-and-close attempts. |
| `dns` | [`probes/dns.js`](src/probes/dns.js) | times N resolver lookups. |
| `traceroute` | [`probes/traceroute.js`](src/probes/traceroute.js) | system `traceroute`/`tracert`, MTR-style multi-probe (`-q queries`); per-hop `{ ip, sent, recv, lossPct, rttMs, minMs, maxMs, jitterMs }` for the server's path map. |
| `http` | [`probes/http.js`](src/probes/http.js) | `fetch`es a URL (metadata only); reports HTTP `status` + (https) TLS `certExpiryDays`. |
| `curl` | [`probes/curl.js`](src/probes/curl.js) | system `curl` content check — verifies received traffic beyond mere connectivity: HTTP `status`, response body (substring or `/regex/`), `bytes`, and a response header. Fetches the body locally to check it but reports **metadata only** (pass/fail, `bytes`, `contentType`, `status`) — never the body. |
| `pageload` | [`probes/pageload.js`](src/probes/pageload.js) | browser-free page-load test — `curl`s a page, parses its sub-resources (script/css/img), times a fetch of each → per-element waterfall (`elements: [{url,kind,status,bytes,ms}]`) + totals (`rttMs` = total load time, `bytes` = page weight, `status` = doc status). Bodies discarded/parsed locally; metadata only. |
| `transaction` | [`probes/transaction.js`](src/probes/transaction.js) | browser-free multi-step journey / scripted API call — ordered `curl` steps with status/body assertions; a step can `extract` a regex capture into a variable later steps reference as `{{name}}` in URL/header/body (e.g. login → token → authed call). Stops at the first failure. Per-step waterfall in `elements` (`kind` = `step N METHOD`); `rttMs` = total time. Extracted values stay local — never reported. |
| — | [`probes/stats.js`](src/probes/stats.js) | shared `clampInt`/`round`/`summarize`/`fail` helpers. |

All probes return a normalized record: `{ type, target, ok, attempts, success,
rttMs, minMs, maxMs, jitterMs, lossPct, ... }` (http adds `status` +
`certExpiryDays`; curl adds `status` + `bytes` + `contentType`; pageload +
transaction add `status` + `bytes` + `elements`).

## Server API surface (the contract)

What the agent calls on **blueeye-server** (mirrored by the fake server):

| Call | Where | Notes |
| --- | --- | --- |
| `POST /agents/enroll` | [`enroll.js`](src/enroll.js) | `{ code, hostname, platform, arch }` → `201 { agentId, token }`, else `{ ok:false }`. |
| `WS /ws/agent` | [`agentClient.js`](src/agentClient.js) | `Authorization: Bearer`; server sends `{type:'connected'}` then `{type:'command', command}`. |
| `POST /agents/results` | [`apiClient.js`](src/apiClient.js) | traffic results. |
| `POST /agents/probe-results` | [`apiClient.js`](src/apiClient.js) | probe results. |
| `GET /agents/me/config` | [`apiClient.js`](src/apiClient.js) | returns `{ monitorConfig }` (which source to use). |
| `POST /agents/me/capabilities` | [`apiClient.js`](src/apiClient.js) | reports `{ sources, agentVersion, managed, nic }` — sources/version/runtime ([`capabilities.js`](src/capabilities.js)) plus the per-interface NIC driver/firmware inventory ([`nicInfo.js`](src/nicInfo.js), `ethtool -i` + sysfs; for fleet firmware-drift detection). |

Server → agent commands ([`command.js`](src/command.js)):
- **run-test** (`run[\s_-]?test`) → measure traffic + system, `POST /agents/results`.
- **run-probe** (`run[\s_-]?probe` + a `probe` object) → run it, `POST /agents/probe-results`.
- **install-tool** (`install[\s_-]?tool` + a `tool` string, carries `auditId`) → install a
  missing diagnostic tool (traceroute/mtr/tcptraceroute) from the host package manager and
  report back via `action-result`. The tool is checked against the agent's OWN allowlist in
  [`toolInstaller.js`](src/toolInstaller.js) (apt/dnf/yum/zypper/apk/pacman) — the agent never
  installs an arbitrary package the server names. Docker-managed agents decline.
- **evidence** (`evidence(?:[\s_-]?snapshot)?` + `snapshotId`/`clusterId`/`commandSetVersion`/
  `items`/optional `signature`) → collect a READ-ONLY diagnostic snapshot and reply
  `command-result` with per-item results. The agent enforces its OWN read-only allowlist in
  [`evidenceCollector.js`](src/evidenceCollector.js) (`iface.counters`/`arp.table`/`snmp.reads`/
  `agent.state`) and **hard-refuses** anything else **without invoking a collector** — the
  server's allowlist is not trusted (defense in depth). When a release public key is
  configured, a signed command with a bad signature is refused (reuses
  [`verifyManifest.js`](src/release/verifyManifest.js)). Never a write action.

## Configuration & environment

Loaded by [`config.js`](src/config.js); precedence **defaults < JSON file < env**.

| Env var | Default | Meaning |
| --- | --- | --- |
| `BLUEEYE_AGENT_CONFIG` | `<install-dir>/blueeye-agent.config.json` | config file path |
| `BLUEEYE_SERVER_URL` | `http://localhost:3000` | server base URL |
| `BLUEEYE_ENROLLMENT_CODE` | — | one-time code (first start only) |
| `BLUEEYE_TOKEN_PATH` | `<cfgdir>/.blueeye-agent/token` | token file (`0600`) |
| `BLUEEYE_HEARTBEAT_MS` | `15000` | WS heartbeat interval |
| `BLUEEYE_RECONNECT_BASE_MS` / `_MAX_MS` | `1000` / `30000` | reconnect backoff ([`backoff.js`](src/backoff.js)) |
| `BLUEEYE_REPORT_INTERVAL_MS` | `60000` | continuous-report cadence (`0` disables) |
| `BLUEEYE_REPORT_SAMPLE_MS` | `1000` | sampling window per measurement |
| `BLUEEYE_LOG_LEVEL` | `info` | `debug`/`info`/`warn`/`error` ([`logger.js`](src/logger.js)) |

## Error & fatal model

- **401 anywhere is fatal.** A rejected token over WS (handshake) or REST is
  surfaced as `code: 'TOKEN_REJECTED'` / a `'fatal'` event; the runtime stops
  all timers, does **not** reconnect, does **not** re-enroll, and the process
  exits 1. Manual intervention required.
- **Everything else is non-terminal.** Transient REST/WS errors are logged and
  the loop continues; WS reconnects with exponential backoff + jitter. Each such
  error is also reported to the server over the live channel as an `agent.error`
  frame (`reportError` in [`runtime.js`](src/runtime.js)) — best-effort + metadata
  only, so it surfaces in the server's audit trail (Reporting → Audit) instead of
  hiding in the host's local log. A closed socket simply drops it.
- **Collectors swallow malformed packets** (counted as `dropped`), never crash.
- **Probes never throw** (bad probe → `ok:false`).
- System metrics are **best-effort** — a failure there must not lose the
  traffic report ([`testRunner.js`](src/testRunner.js)).

## Result shapes

`runTest()` ([`testRunner.js`](src/testRunner.js)) envelope submitted to
`/agents/results`:

```js
{ name, commandId, ok: true, startedAt, finishedAt,
  traffic,   // sampler snapshot (proc/snmp per-interface OR netflow/sflow flow summary)
  system }   // CPU%/mem/load/uptime (systemMetrics.js) — null if sampling failed
```

## Module reference

| Concern | Files |
| --- | --- |
| Lifecycle / wiring | [`index.js`](src/index.js), [`runtime.js`](src/runtime.js), [`bootstrap.js`](src/bootstrap.js), [`shutdown.js`](src/shutdown.js) |
| Connection self-test | [`doctor.js`](src/doctor.js) — `blueeye-agent doctor`: config→token→DNS→TCP→HTTP→auth→WebSocket, each failure with a fix suggestion (run post-install / on an offline agent) |
| Scheme self-heal | [`serverUrl.js`](src/serverUrl.js) — `resolveEffectiveServerUrl`: if an http:// server redirects to https on the same host, adopt it at boot so WS uses wss:// and REST keeps its auth header (index.js, before the runtime) |
| Identity / config | [`config.js`](src/config.js), [`system.js`](src/system.js), [`tokenStore.js`](src/tokenStore.js), [`enroll.js`](src/enroll.js), [`capabilities.js`](src/capabilities.js), [`nicInfo.js`](src/nicInfo.js) |
| Transport | [`agentClient.js`](src/agentClient.js), [`apiClient.js`](src/apiClient.js), [`backoff.js`](src/backoff.js) |
| Commands | [`command.js`](src/command.js) |
| Measurement orchestration | [`testRunner.js`](src/testRunner.js), [`monitor.js`](src/monitor.js), [`systemMetrics.js`](src/systemMetrics.js) |
| Traffic sources | [`trafficMonitor.js`](src/trafficMonitor.js), [`trafficMonitorWin.js`](src/trafficMonitorWin.js), [`snmpMonitor.js`](src/snmpMonitor.js), [`netflow/`](src/netflow), [`sflow/`](src/sflow) |
| Active probes | [`probes/`](src/probes) |
| Logging | [`logger.js`](src/logger.js) |

## Conventions

- **Injectable dependencies for tests.** Almost every module takes its side
  effects as params with real defaults — `fetchImpl = fetch`, `WebSocketImpl`,
  `readProc`/`readCounters`, `createSocket`, `exec`/`connect`/`resolver`,
  `sleepFn`/`now`. Tests pass fakes; production uses the defaults. Follow this
  pattern when adding code.
- **Pure parsers, side-effecting collectors.** `parseV5`/`parseTemplated`/
  `parseSflow`/`decodeSampledHeader` are pure functions over a `Buffer`; sockets
  live only in the `collector.js` wrappers.
- **Coded errors.** Thrown errors carry a `.code` (`TOKEN_REJECTED`,
  `HTTP_ERROR`, `NO_CREDENTIALS`, `ENROLL_FAILED`, `SNMP_UNAVAILABLE`).
- **No `process.exit` outside `index.js`.** Logic modules emit events / throw so
  they stay testable.

## Testing

`npm install` then `npm test` (`node --test`). Integration tests run the runtime
against [`test-support/fakeServer.js`](test-support/fakeServer.js) — a
contract-faithful stub of the real server (same endpoints), so tests are
self-contained and need no MySQL.

| Area | Test |
| --- | --- |
| Config merge / code clearing | [`test/config.test.js`](test/config.test.js) |
| Token store (`0600`) | [`test/tokenStore.test.js`](test/tokenStore.test.js) |
| Enroll + bootstrap | [`test/enroll.test.js`](test/enroll.test.js) |
| Command recognition | [`test/command.test.js`](test/command.test.js) |
| Backoff | [`test/backoff.test.js`](test/backoff.test.js) |
| Runtime: connect / 401 / reconnect / run-test | [`test/runtime.test.js`](test/runtime.test.js) |
| Continuous reporting | [`test/reporting.test.js`](test/reporting.test.js) |
| Capabilities + monitor config | [`test/capabilities.test.js`](test/capabilities.test.js), [`test/monitorConfig.test.js`](test/monitorConfig.test.js) |
| Traffic / SNMP / system metrics | [`test/trafficMonitor.test.js`](test/trafficMonitor.test.js), [`test/trafficMonitorWin.test.js`](test/trafficMonitorWin.test.js), [`test/monitor.test.js`](test/monitor.test.js), [`test/snmpMonitor.test.js`](test/snmpMonitor.test.js), [`test/systemMetrics.test.js`](test/systemMetrics.test.js) |
| NetFlow / sFlow | [`test/netflow.test.js`](test/netflow.test.js), [`test/netflowTemplated.test.js`](test/netflowTemplated.test.js), [`test/sflow.test.js`](test/sflow.test.js) |
| Probes | [`test/probes.test.js`](test/probes.test.js) |
| Test runner envelope | [`test/testRunner.test.js`](test/testRunner.test.js) |
