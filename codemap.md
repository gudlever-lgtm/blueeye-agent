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
| Active probes | ping · tcp · dns · rdns · traceroute · tcptraceroute · http · tls · dhcp |
| Transaction tests | [`src/transactions/`](src/transactions/) — server pushes `transaction_config` over WS; the manager schedules each http/tcp/dns/icmp test (`interval_sec` ±10% jitter), runs an executor (Node core `http`/`https`/`net`/`dns` + system `ping`), classifies the failure phase, buffers results (max 1000, oldest dropped) and flushes `transaction_result` batches on reconnect. Config persists to a local JSON file with secrets AES-256-GCM-encrypted (key derived from the token) |
| SNMP topology | [`snmpTopology.js`](src/snmpTopology.js) + [`snmpPoller.js`](src/snmpPoller.js) — the agent polls the **switches the server assigns to it** (`snmpTargets` in the agent config) for the forwarding table, LLDP and CDP neighbours, VLAN names, the router ARP table (IP-MIB `ipNetToPhysicalTable`, falling back to `ipNetToMediaTable`; ≤ 8 192 rows, walk bounded) and the ENTITY-MIB inventory (chassis + modules: model, serial, firmware) — the last three opt-in per device via `collect` (`cdp`/`arp`/`entity`), walked AFTER the core tables in what is left of the device's 30 s timeout, so a slow one is reported in the device's `partial` list instead of costing its forwarding table — plus `sysName`/`sysDescr`/`sysUpTimeTicks`/`sysLocation`/`sysContact`/`sysObjectID` per device, ALONGSIDE its own traffic sampling. Breaks the old 1:1 binding where `monitorConfig.source='snmp'` made a whole agent poll one device. **Bridge port is not ifIndex** — `dot1dBasePortIfIndex` is walked and resolved before anything is reported. **Catalyst IOS** (no Q-BRIDGE): VLAN names fall back to CISCO-VTP-MIB `vtpVlanName` (1002-1005 skipped), and the per-VLAN forwarding tables are walked under `community@<vlan>` (v3: context `vlan-<vlan>`) — ≤ 64 VLANs, inside the optional-phase budget, each resolved through its own bridge-port map and tagged with its VLAN. The poller's scheduled ticks run the RUNTIME's cycle wrapper (`start({ cycle })`), the same one `poll-snmp` uses: interface names feed the trap resolver, the diagnose timestamps move, and a 401 on the submit is fatal. `poll-snmp` re-reads the config first (≤ 5 s), so a switch assigned a moment ago is polled, and replies with how many devices it polled |
| Device events | [`src/syslog/`](src/syslog/) — the agent is the **syslog collector**: devices on the customer's own network point their logging at it (udp+tcp **1514**, off by default), it parses RFC 3164/5424 per line, classifies the fault, masks credentials and batches to `POST /agents/me/device-events`. Bounded buffer + per-sender token bucket, so a switch in an STP loop cannot make the agent the outage. Optional sender allowlist, checked before the rate limiter: `syslogAllowedSenders` (CIDRs/addresses, `BLUEEYE_SYSLOG_ALLOWED_SENDERS`; fails CLOSED on a bad entry) and/or `syslogOnlyPolled` (the switches this agent polls, same resolved addresses as the trap allowlist) — a sender either vouches for is accepted, refusals counted as `refused`; neither set = accept all. ONE flush timer (`syslogFlushIntervalMs`) serves syslog and traps and starts when EITHER binds |
| SNMP traps | [`src/traps/`](src/traps/) — udp **1162**, off by default. Same start/drain/stats/stop contract as the syslog receiver, so both drain into ONE device-event batch. A trap is accepted only from an address this agent actually polls — v2c is unauthenticated and the source address is the strongest check it permits — and that is checked BEFORE any decoding. A target configured by **hostname** is resolved (`dns.lookup`, all addresses; injectable `lookupHost`) whenever the targets are applied, so its traps match; a failed lookup keeps the last known address. A v1/v2c **community** that differs from the one the agent polls that device with is counted as `communityMismatch`; it is only refused when `trapsCheckCommunity` is on (default **off** — a separate trap community is a normal setup, and refusing it would drop that switch's traps silently; refusals counted as `badCommunity`). Decoded by the pure BER decoder [`traps/decode.js`](src/traps/decode.js) (v1 converted to the v2 varbind shape, RFC 3584) — no net-snmp needed; SNMPv3 traps are out of scope and counted as `v3` |
| Burst mode | [`burst.js`](src/burst.js) — one target, **once a second** for up to two minutes, on demand. Streams every sample as it is taken so the dashboard draws the chart live. Length and rate are clamped HERE as well as validated on the server: a burst is a packet generator, and the thing emitting the packets must not depend on the thing that asked having validated correctly. One at a time |
| Result size guard | [`resultBudget.js`](src/resultBudget.js) — the server 400s any single result over 65 535 bytes, losing the whole traffic report, so `runAndSubmit` trims one over 60 000 bytes first: `traffic.sflowCounters` tail (handed back to the collector via `sampler.requeueCounters`), then the smallest `flows`, then `topTalkers` (…then byPort/byProtocol/interfaces, then totals only). `result.truncated` names what went; totals are never cut; a result that cannot fit is not sent |
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
| `proc` (default) | [`trafficMonitor.js`](src/trafficMonitor.js) (Linux) / [`trafficMonitorWin.js`](src/trafficMonitorWin.js) (Windows) | Linux: reads `/proc/net/dev` twice, `intervalMs` apart (including the rx `fifo`/`frame` and tx `colls`/`carrier` columns, reported as per-interval `rxFifoErrors`/`rxFrameErrors`/`txCollisions`/`txCarrierErrors`), plus `/sys/class/net/<if>/duplex` as `duplex` — all null, never 0, where they cannot be read (Windows/macOS, down or virtual links). Windows: one persistent `powershell.exe` (spawned once, not per poll) ticks `Get-NetAdapterStatistics`/`Get-NetAdapter` and streams a JSON line per tick over stdout; both feed the same `buildSnapshot()` delta/rate computation | per-interface rx/tx bytes·packets·errors·drops + rates, `operStatus`/`speedMbps`, `totals` |
| `snmp` | [`snmpMonitor.js`](src/snmpMonitor.js) | polls IF-MIB HC octet counters (+ health columns) twice over SNMP, plus `dot3StatsLateCollisions` from the EtherLike-MIB — the counter that names a duplex mismatch, and the one whose ABSENCE is reported as `null` rather than 0, because a device that cannot report it must not look like one with a clean link | same per-interface shape as proc (`source:'snmp'`) |
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
| [`sflow/parse.js`](src/sflow/parse.js) | Parses sFlow v5 datagrams; scales sampled bytes by sampling rate. Flow samples keep the in/out ifIndex (and the extended-switch VLAN); **counter samples** are decoded (generic format 1 + Ethernet format 2) and the collector forwards the latest per (exporter, ifIndex) as `sflowCounters` — bounded and rotated to fit the 64 KB result (PROTOCOL.md). |
| [`sflow/decodePacket.js`](src/sflow/decodePacket.js) | Decodes the sampled raw frame (Eth+802.1Q/QinQ+IPv4/IPv6+TCP/UDP) to a 5-tuple plus VLAN id and src/dst MAC. |
| [`sflow/hsflowd.js`](src/sflow/hsflowd.js) | Self-managed hsflowd lifecycle (install/configure/start/stop + state machine) so a host exports sFlow to its own collector. Docker agents defer to the [hsflowd sidecar](docker/hsflowd). |
| [`sflow/hsflowdConfig.js`](src/sflow/hsflowdConfig.js) | Renders `/etc/hsflowd.conf` (collector, sampling, polling, pcap device). |

## Active probes

[`probes/index.js`](src/probes/index.js) `runProbe(spec)` dispatches by
`spec.type` through a `RUNNERS` lookup and **never throws** — an unknown type or
a runner error resolves to an `ok:false` result stamped with `ts`.

| Type | Module | Method |
| --- | --- | --- |
| `ping` | [`probes/ping.js`](src/probes/ping.js) | system `ping`, parses loss% + min/avg/max/mdev (Linux/macOS/Windows). `sizes: [64, 1472]` + `df: true` sweeps several payload sizes with don't-fragment set — the probe that tells an MTU blackhole from a lossy link — reporting each size in `sizes[]` and the router's `mtuHint` when an ICMP frag-needed comes back. The TOP-LEVEL metrics always describe the SMALLEST size, so a blocked 1472-byte packet never reads as an outage on the reachability screens. |
| `tcp` | [`probes/tcp.js`](src/probes/tcp.js) | times N connect-and-close attempts. Adds `failure` (`refused`/`timeout`/`unreachable`/`error`) + `errorCode` of the last failing attempt (both null when none failed) — a closed port is not a dead host. |
| `dns` | [`probes/dns.js`](src/probes/dns.js) | times N resolver lookups. Adds `errorCode` (`ENOTFOUND`/`ETIMEOUT`/`ESERVFAIL`/… of the last failing attempt; null when none failed). |
| `traceroute` | [`probes/traceroute.js`](src/probes/traceroute.js) | system `traceroute`/`traceroute6`/`tracert`, MTR-style multi-probe (`-q queries`); IPv4 + IPv6 (an IPv6 literal selects the family on its own; both IPv6 binaries are tried, since distributions disagree on which exists); per-hop `{ ip, ips, sent, recv, lossPct, rttMs, minMs, maxMs, jitterMs }` for the server's path map — `ip` is the first responder, `ips` every distinct one on that hop line (ECMP), also in the live `trace_hop` frames. |
| `tcptraceroute` | [`probes/tcptraceroute.js`](src/probes/tcptraceroute.js) | the SAME path, traced with TCP SYNs to `host:port` — the one that still works where ICMP/UDP is filtered. Tries `tcptraceroute`, falls back to `traceroute -T -p <port>` (already installed for the ICMP probe), and when neither exists names `tcptraceroute` so the server's auto-install can fix it; a raw-socket permission failure gets its own reason. Reuses `parseTraceroute`; `target` is `host:port` so a TCP trace stays a separate series from an ICMP one. |
| `http` | [`probes/http.js`](src/probes/http.js) | `fetch`es a URL (metadata only); reports HTTP `status` + (https) TLS `certExpiryDays`. |
| `curl` | [`probes/curl.js`](src/probes/curl.js) | system `curl` content check — verifies received traffic beyond mere connectivity: HTTP `status`, response body (substring or `/regex/`), `bytes`, and a response header. Fetches the body locally to check it but reports **metadata only** (pass/fail, `bytes`, `contentType`, `status`) — never the body. |
| `pageload` | [`probes/pageload.js`](src/probes/pageload.js) | browser-free page-load test — `curl`s a page, parses its sub-resources (script/css/img), times a fetch of each → per-element waterfall (`elements: [{url,kind,status,bytes,ms}]`) + totals (`rttMs` = total load time, `bytes` = page weight, `status` = doc status). Bodies discarded/parsed locally; metadata only. |
| `transaction` | [`probes/transaction.js`](src/probes/transaction.js) | browser-free multi-step journey / scripted API call — ordered `curl` steps with status/body assertions; a step can `extract` a regex capture into a variable later steps reference as `{{name}}` in URL/header/body (e.g. login → token → authed call). Stops at the first failure. Per-step waterfall in `elements` (`kind` = `step N METHOD`); `rttMs` = total time. Extracted values stay local — never reported. |
| `path_mtu` | [`probes/pathmtu.js`](src/probes/pathmtu.js) | largest packet the path carries, per hop — binary search on packet size with the DF bit set. Separates a normal MTU reduction (ICMP frag-needed received) from a **PMTUD blackhole** (large packets vanish silently, so no sender ever learns), and both from a hop that simply doesn't answer ICMP. A hop is measured by pinging the TARGET with the TTL limited to it, so the measured MTU is monotonic along the path and `mtu_drop_at_hop` names the router that narrows it. The path is listed by a 2-query traceroute; hop numbers are its TTLs, a silent hop stays in the list (measured, `ip` null unless the ping names it), and the first TTL whose ping the TARGET answers ends the path — a rate-limited trace otherwise put a 2-hop target at hop 18. IPv4 and IPv6 alike, per hop. Optional Linux-only MSS check via `ss -tin`. Reports `ok: true` even on a blackhole — the finding is about the path, not the agent. |
| `tls` | [`probes/tls.js`](src/probes/tls.js) | the certificate a PORT presents — not only a web server's. Opens a TLS handshake (nothing sent, nothing read) and reports the four faults APART: `expiryDays`, chain trust (`chainTrusted`; `authorized` + node's own `authorizationError` code kept verbatim — node checks the chain before the name, so `ERR_TLS_CERT_ALTNAME_INVALID` is a trusted chain with `hostnameMatches: false`), hostname match (RFC 6125 — SAN decides, one wildcard label, subject CN only when there is no SAN), and the negotiated protocol/cipher. `rejectUnauthorized: false` is deliberate: a refused handshake cannot say WHICH fault it was, and reporting that is the job. An explicit `servername` checks the certificate a particular virtual host serves (point it at an IP and name the host), and when it differs from the host it is part of the `target` (`name@host:port`) so each name is its own series; an IP with no servername reports `hostnameMatches: null` rather than a verdict it never reached. `lossPct` stays 0 — a certificate fault is not packet loss, and must not land in the outage numbers. |
| `rdns` | [`probes/rdns.js`](src/probes/rdns.js) | the other direction from `dns`: what does the ADDRESS say it is called. Resolves a name to an address first, so it can be pointed at either. Reports `ptrNames` and, separately, **`forwardConfirmed`** — does the PTR name resolve back to the same address (RFC 1912 §2.1, and what receiving mail servers check). A PTR pointing at somebody else's name is worse than none, because it looks fine until it is checked, so it is its own state rather than folded into `ok`. No PTR at all is an `ok:false` RESULT with the reason, not a broken probe. |
| `dhcp` | [`probes/dhcp.js`](src/probes/dhcp.js) | is there a DHCP server on this segment, and only ONE? Broadcasts an RFC 2131 DHCPDISCOVER from `0.0.0.0:68` (broadcast flag, random xid, `chaddr` = the MAC of `spec.iface` or the default-route interface, options 53/55/61) and collects EVERY DHCPOFFER for that xid until the timeout (3 s default, 1–10 s). **Never sends a DHCPREQUEST**, so no lease is taken. Reports `offers[]` (≤ 8: serverId, offeredIp, leaseSec, router, dns, subnetMask, relay = giaddr) and `serverCount` (distinct option-54 identifiers — more than one is a rogue/misconfigured server). No offer is an `ok:false` measurement, not an `error`; port 68 needs root or `CAP_NET_BIND_SERVICE`, and a port held by the host's own DHCP client is retried with `reuseAddr` before it is named. Pure codec (`buildDiscover`/`parseDhcpPacket`/`offerFromPacket`, option-52 overload honoured) + a runner with injectable dgram/interfaces/clock/timer. Schedulable as a configured target `dhcp` / `dhcp:<iface>` (off by default). The DISCOVER leaves by the route the kernel picks for 255.255.255.255 (the default-route NIC); `iface` names whose hardware address is asked about. |
| — | [`probes/ipFamily.js`](src/probes/ipFamily.js) | **the IPv4/IPv6 seam** — header sizes, RFC minimum packet sizes, MSS overhead, address extraction (`net.isIP`-validated, reads both families out of any tool layout) and the per-platform argv for `ping`/`ping6`/`traceroute`/`traceroute6`/`tracert`. IPv6 has no don't-fragment bit (routers may not fragment it at all), so the "too big" answer is ICMPv6 Packet Too Big rather than "fragmentation needed and DF set" — same event, two names. Pure: command builders return `{ bin, args }`. |
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
| `GET /agents/me/config` | [`apiClient.js`](src/apiClient.js) | returns `{ monitorConfig, snmpTargets? }`. Read at start, on reconnect, every `configRefreshIntervalMs` (300 s) and before `poll-snmp`; the last two apply only what changed. |
| `POST /agents/me/capabilities` | [`apiClient.js`](src/apiClient.js) | sent at start, on every WS (re)connect and every `capabilitiesIntervalMs` (default 300 s, skipped while disconnected). Reports `{ sources, unavailable, agentVersion, managed, nic, ips, connections, arp, lldp, lldpChassisId }` — the host's own **LLDP neighbours** ([`lldp.js`](src/lldp.js): `lldpctl -f json` + `lldpcli show chassis`, optional — no lldpd ⇒ `lldp` omitted, never `[]`, and `unavailable.lldp` says why) as `[{ localPort, remoteChassisId, remotePort, linkState }]` for the server's `lldp_neighbors` + topology-change detection; sources/version/runtime ([`capabilities.js`](src/capabilities.js)), the per-interface NIC driver/firmware inventory ([`nicInfo.js`](src/nicInfo.js), `ethtool -i` + sysfs; for fleet firmware-drift detection), own IPs ([`localIps.js`](src/localIps.js)), and the established-TCP **connection table** folded into directed service-dependency edges ([`connTable.js`](src/connTable.js), `ss`/`netstat`/Get-NetTCPConnection — metadata only) so a `proc`/`snmp` host with no flow exporter still feeds the server's service dependency graph. Also the **ARP/neighbour table** ([`arpTable.js`](src/arpTable.js) — `/proc/net/arp` + `ip neigh` on Linux, `arp -an`/`arp -a` elsewhere; metadata only, incomplete/broadcast/multicast dropped, capped at 2000 entries), which backs the server's IP↔MAC identity source and its universal search field. The same data was already reachable via the read-only evidence path (`arp.table`), but only when an incident cluster opened — reporting it here makes it continuous. Best-effort: a missing tool or unreadable `/proc` yields `[]` and never costs the capabilities report. |

### Command authenticity ([`commandAuth.js`](src/commandAuth.js))

A command is normally trusted because it arrived on the authenticated WebSocket.
For the **privileged** ones — `update`, `delete`, `install-tool`, `rekey` — that
puts the whole host on the server never being wrong, so they may carry a
`commandSignature`: an Ed25519 signature (over `agentId` + `issuedAt` + every
other field except the transport `id`) made with the same release key the agent
already pins. Verification is fail-closed — a signature that does not check out,
names another agent, or is older than ±5 min is refused without running the
action. `BLUEEYE_REQUIRE_SIGNED_COMMANDS=1` additionally refuses UNSIGNED
privileged commands. Note `update.signature` is a different thing: it signs the
release manifest (the payload), not the instruction.

The agent also reports the **fingerprint** of the release key it pins, in its
capabilities (`releaseKeyFingerprint`, a SHA-256 of the public PEM). That is
what lets a dashboard say "this agent trusts ab12…, this server signs with
cd34… — re-pin it" instead of relaying `refused: command signature verification
failed`, which is true, unactionable, and indistinguishable from a corrupt
signature. It is a digest of a public key: nothing secret leaves the host.

**`rekey` does not follow that lenient default.** The other three are bounded —
a `delete` is visible in the fleet list, an `update` still verifies the release
manifest separately — but a rekey replaces the anchor every LATER signature is
checked against, so an unsigned one turns one moment of socket access into
permanent, silent code execution. When this agent already holds a key, an
unsigned rekey is refused; a legitimate rotation is signed with the key being
replaced. `BLUEEYE_ALLOW_UNSIGNED_REKEY=1` is the break-glass for a fleet whose
server lost its signing key, and setting it needs access to the host.

Server → agent commands ([`command.js`](src/command.js)):
- **run-test** (`run[\s_-]?test`) → measure traffic + system, `POST /agents/results`.
- **run-probe** (`run[\s_-]?probe` + a `probe` object) → run it, `POST /agents/probe-results`.
- **install-tool** (`install[\s_-]?tool` + a `tool` string, carries `auditId`; PRIVILEGED — see
  Command authenticity above) → install a
  missing diagnostic tool (traceroute/mtr/tcptraceroute) from the host package manager and
  report back via `action-result`. The tool is checked against the agent's OWN allowlist in
  [`toolInstaller.js`](src/toolInstaller.js) (apt/dnf/yum/zypper/apk/pacman) — the agent never
  installs an arbitrary package the server names. Docker-managed agents decline.
- **update** (PRIVILEGED) → download the release the server named
  ([`selfUpdate.js`](src/selfUpdate.js)): a SIGNED one is verified against the pinned
  release key (Ed25519 over the manifest + sha256 + version, fail-closed), a legacy
  source bundle against its sha256 only; then extract (tar-slip + link members refused),
  `npm ci --omit=dev`, atomically repoint `current`, and ask systemd to restart. **The
  restart is checked**: when it fails the new code is on disk but this old process is
  still the one running, so the agent reports the action FAILED with
  `run: systemctl restart …` rather than a success whose version never changes. systemd
  only — docker/unmanaged decline.
- **rekey** (`rekey|re-key|rotate-key|re-pin` + a `publicKey` string, plus a `vendorProof`
  where the trust chain is in force; PRIVILEGED) → replace the
  release trust anchor this host pins ([`release/keyStore.js`](src/release/keyStore.js)).
  The anchor is baked in at install time, so an agent whose server changed its signing
  key refuses every update it can produce — and there is no shell on these hosts, they
  are managed from the server. The new key is validated as Ed25519, stored beside the
  token (`release-key.pem`, which outranks `BLUEEYE_RELEASE_PUBLIC_KEY` at startup),
  mirrored into the systemd drop-in best-effort, and applied **in memory** so the update
  that follows needs no restart. When the server can still sign, the command carries a
  `commandSignature` made with the key being replaced — a proper rotation, and the only
  form `BLUEEYE_REQUIRE_SIGNED_COMMANDS=1` accepts.
- A release the agent cannot start is rolled back ([`release/releaseGuard.js`](src/release/releaseGuard.js)).
  `atomicInstall` marks the new release unproven (`releases/.pending`) while the OLD,
  known-good process is still running; the new agent deletes the marker only after it has
  HELD a server connection for a minute — "the process started" is not proof. A plain `sh`
  guard living outside the swappable tree (`bin/release-guard.sh`, run by systemd as
  `ExecStartPre`, installed by the agent itself on startup) counts the starts and repoints
  `current` at the previous release when they run out. It is not Node on purpose: the
  failure it recovers from is a release Node cannot even parse.
- **Who decides which key this agent trusts** ([`license/trustProof.js`](src/license/trustProof.js)).
  Not the server. The vendor's public key is embedded here
  ([`license/vendorRoot.js`](src/license/vendorRoot.js), the same key blueeye-server embeds),
  and a rekey is accepted when the vendor-signed licence proof the server relays names the
  fingerprint of the key being offered. Every step fails closed: signature, customer/licence
  binding, `valid_until`, monotonic `sequence` (anti-rollback), then
  `fingerprint(offered) == fingerprint(authorised)`. A server that has been taken over can
  send anything; it cannot produce that signature. Accepting one LATCHES this host
  (`release-trust.json`): from then on nothing but a vendor authorisation is accepted, and
  no server can clear the latch. Until the first one arrives, a rekey signed with the key
  being replaced still works — that is the migration path, not a fallback.
- **run-discovery** (`run[\s_-]?discovery|discovery[\s_-]?sweep|sweep` + a `discovery` object
  `{ cidrs?, ports?, rateLimit?, addressCap?, requestId? }`) → sweep the CIDR scope from THIS
  agent's vantage (empty `cidrs` ⇒ the agent's own subnet via `localIps.collectLocalCidrs`),
  probes ([`discovery/`](src/discovery): one ICMP echo via the system `ping` — run alongside
  the TCP sweep, `null` when ping is missing — TCP-connect on the server's `ports` or the
  default IT + OT/ICS list (22, 80, 161, 443, 3389, 102 S7, 502 Modbus, 2404 IEC-104,
  20000 DNP3, 44818 EtherNet/IP, 4840 OPC UA) — one address's ports four at a time
  (`portConcurrency`, so a silent address costs ~3 connect timeouts, not 11), each
  connect still taking its own grant from the rate limiter in order — rDNS;
  rate-limited, scope-capped), and
  `POST /agents/discovery-results` with the candidates. A scope refusal
  (empty/over-cap) is reported as `{ refused, reason }`, never a crash. Never a write action.
- **evidence** (`evidence(?:[\s_-]?snapshot)?` + `snapshotId`/`clusterId`/`commandSetVersion`/
  `items`/optional `signature`) → collect a READ-ONLY diagnostic snapshot and reply
  `command-result` with per-item results. The agent enforces its OWN read-only allowlist in
  [`evidenceCollector.js`](src/evidenceCollector.js) (`iface.counters`/`arp.table`/`snmp.reads`/
  `agent.state`) and **hard-refuses** anything else **without invoking a collector** — the
  server's allowlist is not trusted (defense in depth). When a release public key is
  configured, a signed command with a bad signature is refused (reuses
  [`verifyManifest.js`](src/release/verifyManifest.js)). Never a write action.
- **poll-snmp** (`poll[\s_-]?snmp`) → re-read the assignment (`GET /agents/me/config`,
  bounded to 5 s, errors tolerated), then run an SNMP topology cycle NOW rather than waiting
  out the per-device interval: each assigned switch's forwarding table, LLDP neighbours
  and VLAN names ([`snmpPoller.js`](src/snmpPoller.js)), then
  `POST /agents/me/snmp-topology`. Read-only on the device — it walks tables, it never
  sets an OID — and one bad device costs itself, not the cycle.
- **burst** (`burst` + a `target`) → measure that one target once a second for up to two
  minutes ([`burst.js`](src/burst.js)), streaming a `burst_sample` frame per tick and
  replying `command-result` with the whole series. The caps are enforced here, not only in
  the server's validation — a caller that asks for an hour at 50 Hz gets two minutes at
  2 Hz, and the reply says what was clamped, because the technician is mid-fault and a
  rejection helps nobody. Refused, not queued, while one is already running.
- **stop-burst** (`stop[\s_-]?burst`) → end the running burst at its next tick and report
  the partial run. Whoever is watching the chart saw what they needed.

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
| `BLUEEYE_CAPABILITIES_INTERVAL_MS` | `300000` | periodic capabilities re-report (ARP/conn table/NIC/LLDP); `0` disables |
| `BLUEEYE_CONFIG_REFRESH_MS` | `300000` | periodic config re-read (new SNMP targets, a changed source) without a reconnect; unchanged = no-op; `0` disables |
| `BLUEEYE_LOG_LEVEL` | `info` | `debug`/`info`/`warn`/`error` ([`logger.js`](src/logger.js)) |
| `BLUEEYE_REQUIRE_SIGNED_COMMANDS` | **on once the server has signed one** | refuse an unsigned `update`/`delete`/`install-tool`. A RATCHET: the first command whose signature verifies latches it on for good (recorded in `release-trust.json`). Deriving it from "a key is pinned" instead bricked every privileged command on a fleet whose server had lost its signing key — pinning says the agent can CHECK a signature, not that its server can MAKE one. `=0` opts out ([`commandAuth.js`](src/commandAuth.js)) |
| `BLUEEYE_VENDOR_ROOT_PUBLIC_KEY` | (embedded) | the vendor trust anchor. Dev/test override only — production ignores it without `BLUEEYE_TRUST_ANCHOR_OVERRIDE_ACK` ([`license/vendorRoot.js`](src/license/vendorRoot.js)) |
| `BLUEEYE_REQUIRE_SIGNED_UPDATES` | off | refuse an unsigned release ([`selfUpdate.js`](src/selfUpdate.js)) |
| `BLUEEYE_ALLOW_UNSIGNED_REKEY` | off | break-glass: let an UNSIGNED `rekey` replace an anchor this host already holds. Needed only to recover a fleet whose server lost its signing key ([`commandAuth.js`](src/commandAuth.js)) |
| `BLUEEYE_RELEASE_PUBLIC_KEY` | (installer) | the pinned release anchor. A `rekey` accepted from the server stores one in `release-key.pem` beside the token, and THAT wins ([`release/keyStore.js`](src/release/keyStore.js)) |

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
| Lifecycle / wiring | [`index.js`](src/index.js), [`runtime.js`](src/runtime.js), [`bootstrap.js`](src/bootstrap.js), [`shutdown.js`](src/shutdown.js), [`lib/crashGuard.js`](src/lib/crashGuard.js) — the last-resort process guards: an unhandled rejection is logged and survived (this agent is full of deliberately best-effort collectors, and dying on one stops reporting from a host nobody is watching), an uncaught exception stops the runtime and exits non-zero so systemd restarts clean |
| Connection self-test | [`doctor.js`](src/doctor.js) — `blueeye-agent doctor`: config→token→DNS→TCP→HTTP→auth→WebSocket, each failure with a fix suggestion (run post-install / on an offline agent) |
| Scheme self-heal | [`serverUrl.js`](src/serverUrl.js) — `resolveEffectiveServerUrl`: if an http:// server redirects to https on the same host, adopt it at boot so WS uses wss:// and REST keeps its auth header (index.js, before the runtime) |
| Identity / config | [`config.js`](src/config.js), [`system.js`](src/system.js), [`tokenStore.js`](src/tokenStore.js), [`enroll.js`](src/enroll.js), [`capabilities.js`](src/capabilities.js), [`nicInfo.js`](src/nicInfo.js), [`lldp.js`](src/lldp.js) |
| Transport | [`agentClient.js`](src/agentClient.js), [`apiClient.js`](src/apiClient.js), [`backoff.js`](src/backoff.js) |
| Commands | [`command.js`](src/command.js), [`commandAuth.js`](src/commandAuth.js) |
| Measurement orchestration | [`testRunner.js`](src/testRunner.js), [`monitor.js`](src/monitor.js), [`systemMetrics.js`](src/systemMetrics.js) |
| Traffic sources | [`trafficMonitor.js`](src/trafficMonitor.js), [`trafficMonitorWin.js`](src/trafficMonitorWin.js), [`snmpMonitor.js`](src/snmpMonitor.js), [`netflow/`](src/netflow), [`sflow/`](src/sflow) |
| SNMP topology | [`snmpTopology.js`](src/snmpTopology.js) reads FDB/LLDP/CDP/VLAN/ARP/ENTITY (pure `buildTopology`, injectable reader and session — no device and no `net-snmp` needed to test it; the IP-MIB and CDP index/address decoding is tested on real byte layouts), [`snmpPoller.js`](src/snmpPoller.js) schedules per device with a 60 s floor, a 30 s per-device timeout and per-device error isolation, and splits a cycle too big for the server's 1 MiB body limit into several POSTs by device (`splitSubmission`) |
| SNMP client (shared) | [`snmp/session.js`](src/snmp/session.js) opens/walks/closes — one `net-snmp` guard, v1/v2c/v3 (the security level DERIVED from which keys are set, never stated), **no credential is a refusal and never a walk with `public`** (the server resolves one community per device and an agent walks only with a community assigned to it; `snmpPoller.js` refuses the target before a session is opened and reports which of the two reasons it is), one GETBULK walk (`maxRepetitions`, which is the biggest lever on how long a poll takes), one set of value coercions where **an absent value is `null` and never `0`**; [`snmp/oids.js`](src/snmp/oids.js) is every OID this agent reads, grouped by RFC. The counters, the topology poller and the trap receiver all go through them |
| Interface counters | [`snmp/counters.js`](src/snmp/counters.js) — ONE read per cycle of the raw counters (not two, and not a rate): without the raw value the server can never recompute a rate, recognise a counter reset after the fact, or tell a missing cycle from a cycle that measured zero. sysUpTime rides along, because a device that rebooted between two polls has counters that restarted at zero. Scheduled by `snmpPoller.runCounterCycle` on its OWN interval, FOUR devices at a time — sequential cannot fit twenty switches into a minute, and all at once is the burst that looks like a scan |
| Device events | [`syslog/receiver.js`](src/syslog/receiver.js) binds + buffers, [`syslog/parse.js`](src/syslog/parse.js) is the pure per-line parser (four dialects), [`syslog/classify.js`](src/syslog/classify.js) maps a line onto an `event_type` (unknown stays `syslog.raw`, never guessed; a Cisco `%FAC-SEV-MNEMONIC` opening the MESSAGE — RFC 5424, `logging origin-id hostname`, a blank tag — is classified as if it were the tag), [`syslog/mask.js`](src/syslog/mask.js) redacts credentials BEFORE the line leaves the host |
| SNMP traps | [`traps/translate.js`](src/traps/translate.js) is a TABLE of ~40 well-known trap OIDs, not a MIB compiler; an unknown trap keeps its OID and is never mapped to a neighbour. [`traps/receiver.js`](src/traps/receiver.js) binds + allowlists + folds. The interface is named from what the stage-02 poll already read, so “ifIndex 1” shows as “GigabitEthernet0/1” |
| Burst mode | [`burst.js`](src/burst.js) — `planBurst()` is pure (the clamps), `createBurstRunner()` runs the ticks and subtracts the probe's own time so the cadence stays 1 Hz rather than drifting |
| Connection table | [`connTable.js`](src/connTable.js) — established-TCP edges from `ss`/`netstat`/Get-NetTCPConnection (pure per-platform parsers + orientation + aggregation; injectable exec), reported in `capabilities.connections`. `ss -Htan state established` prints NO State column (one state filtered); `parseSs` reads both shapes — fixture captured from the real command in `test/fixtures/` |
| Active probes | [`probes/`](src/probes); [`probes/curlArgs.js`](src/probes/curlArgs.js) keeps a server-supplied header/body from becoming a curl `@file` read, [`probes/safeRegex.js`](src/probes/safeRegex.js) bounds a server-supplied pattern in time + input so it can't wedge the event loop |
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
| Traffic / SNMP / system metrics | [`test/trafficMonitor.test.js`](test/trafficMonitor.test.js), [`test/trafficMonitorWin.test.js`](test/trafficMonitorWin.test.js), [`test/monitor.test.js`](test/monitor.test.js), [`test/snmpMonitor.test.js`](test/snmpMonitor.test.js), [`test/snmpLateCollisions.test.js`](test/snmpLateCollisions.test.js), [`test/systemMetrics.test.js`](test/systemMetrics.test.js) |
| NetFlow / sFlow | [`test/netflow.test.js`](test/netflow.test.js), [`test/netflowTemplated.test.js`](test/netflowTemplated.test.js), [`test/sflow.test.js`](test/sflow.test.js) |
| Probes | [`test/probes.test.js`](test/probes.test.js) |
| Test runner envelope | [`test/testRunner.test.js`](test/testRunner.test.js) |

### Realistic fixtures

The tests above mostly build their input by hand. These run data that was NOT
written for this codebase through the same code paths; each fixture directory
has a README naming the source, version, capture date and licence.

| Area | Test | Fixture |
| --- | --- | --- |
| sFlow | [`test/sflowRealCapture.test.js`](test/sflowRealCapture.test.js) (+ `blueeye-agent-go/internal/sflow/realcapture_test.go`, same bytes, Go/Node parity) | [`test/fixtures/sflow/`](test/fixtures/sflow) — 28 raw datagrams from **hsflowd 2.1.26** built from source, sampling a veth pair 1-in-8: expanded flow + counter samples, parser checked against an independent XDR walk, then aggregate + the collector over a real UDP socket |
| SNMP traps | [`test/trapsRealCapture.test.js`](test/trapsRealCapture.test.js) | [`test/fixtures/traps/`](test/fixtures/traps) — v1/v2c linkDown (admin + fault), linkUp, coldStart, Cisco ciscoConfigManEvent and a v3 trap, sent by **Net-SNMP 5.9.4 `snmptrap`**; decode → translate, the receiver over UDP, and a cross-check against the `net-snmp` module's own decode |
| Syslog | [`test/syslogRealLines.test.js`](test/syslogRealLines.test.js) | [`test/fixtures/syslog/`](test/fixtures/syslog) — lines captured from util-linux `logger` and **rsyslog 8.2312** (all three forward templates), plus Cisco IOS / Junos text cited line-by-line from vendor-published sources, plus the Cisco shapes (RFC 5424, `logging origin-id hostname`, blank tag) the end-to-end run found unclassified (`cisco-shapes.txt`); parse → classify → mask against a `# expect:` annotation per line |
| Path MTU | [`test/pathMtuRateLimited.test.js`](test/pathMtuRateLimited.test.js) | [`test/fixtures/traceroute/`](test/fixtures/traceroute) — rate-limited `traceroute` output (a 2-hop target at hop 18/10/7 for `-q 1/2/3`) and TTL-limited `ping` replies from the end-to-end rig |
| SNMP walks | [`test/snmpRealWalks.test.js`](test/snmpRealWalks.test.js) via [`test-support/snmprec.js`](test-support/snmprec.js) | [`test/fixtures/snmprec/`](test/fixtures/snmprec) — snmpsim-data recordings (BSD-2) of an HPE ProCurve 6120XG and a Cisco Catalyst 3750, trimmed to the columns the agent reads (the 3750's CISCO-VTP-MIB VLAN rows included); `defaultReadTables` → `buildTopology` and `defaultReadCounters`. [`test/snmpCiscoVlans.test.js`](test/snmpCiscoVlans.test.js) adds the per-VLAN (`community@vlan`) forwarding walk over a fake session keyed by community. `BLUEEYE_SNMPSIM_ENDPOINT=host:port` additionally walks them through real snmpsim + `net-snmp` and asserts identical output |

`test-support/snmprec.js` is the reusable piece: it serves a `.snmprec` file as
a net-snmp-shaped session (`get`/`subtree`/`close`) or module
(`createSession`), with values in the shapes net-snmp really returns — including
Counter64's BER sign pad, which is how the 7-byte Counter64 bug in
`snmp/session.js` `toNumber` was found. Keep helpers in `test-support/`: every
`.js` under `test/` is run by `node --test`.
