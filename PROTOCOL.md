# blueeye-agent ↔ blueeye-server protocol

Complete wire contract between the agent and **blueeye-server**. Compiled from
the agent source and cross-checked against the server's routes/validators
(`blueeye-server/src/routes/agents/`, `agentReports.js`, `agentEnroll.js`,
`enroll.js`, `speedtest.js`, `src/ws/agentSocket.js`, `src/validation/*`).
Discrepancies found while writing this are catalogued in
[REFACTOR-AUDIT.md](REFACTOR-AUDIT.md).

> **This document is pinned to the code.** It used to carry an "as implemented
> in agent vX" line, which went twenty-three releases out of date without
> anything noticing — and it is the only written definition of the contract, so
> a stale one is worse than none. `test/gate/protocolDoc.test.js` now asserts
> that the command table below lists exactly the commands `src/command.js`
> recognises. Add a command without documenting it and the gate says so.

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

`src/apiClient.js getFullConfig()`. Called at startup, on every WS (re)connect,
every `configRefreshIntervalMs` (default 300 s, `BLUEEYE_CONFIG_REFRESH_MS`;
skipped while the WebSocket is down; `0` disables) and before every
`poll-snmp` (bounded to 5 s — on a timeout or an error the poll runs with the
assignment already held). The same body carries `snmpTargets`, so a switch
assigned to a running agent, or a changed source, applies without a reconnect.
The startup and reconnect loads always rebuild the sampler and reconcile
hsflowd; the periodic and `poll-snmp` loads apply only what CHANGED (compared
key-order-independently) — an unchanged config restarts nothing.

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

`src/apiClient.js postCapabilities()`. Sent once at startup, again on every
WS (re)connect (converges the stored agent version after a self-update), and
every `capabilitiesIntervalMs` (default 300 s; skipped while the WebSocket is
down; `0` disables) so the ARP/connection/NIC/LLDP data does not freeze at the
moment the agent connected. A repeat is safe on the server: the agent row is
UPDATEd, the connection table REPLACEd, ARP rows UPSERTed, and the LLDP set is
diffed against the previous snapshot — only a real change writes a
`topology_changes` row / audit entry.

```jsonc
// request
{ "capabilities": {
    "sources": ["proc", "snmp", "netflow", "sflow"],  // required: array of strings
    "agentVersion": "0.9.0",                           // package.json version
    "managed": "systemd" | "docker" | "unmanaged",     // supervision (decides self-update/delete)
    "nic": [ {                                         // optional; omitted when empty/unreadable
      "iface": "eth0", "driver": "e1000e", "driverVersion": "...",
      "firmwareVersion": "...", "busInfo": "0000:00:1f.6", "pciId": "8086:15b8"
    } ],
    "ips": ["10.0.0.5", "2001:db8::1"],                // optional; this host's own non-loopback IPs
                                                        //   (src/localIps.js) — lets the server resolve a
                                                        //   flow IP back to the host for the service
                                                        //   dependency graph. Additive + metadata only.
    "unavailable": { "snmp": "...", "lldp": "..." },   // why an optional capability is absent
    "lldp": [ {                                        // optional (src/lldp.js, lldpd's `lldpctl -f json`);
      "localPort": "eth0",                             //   OMITTED when lldpd is missing / not running
      "remoteChassisId": "00:1b:44:11:3a:b7",          //   (see unavailable.lldp) — never [] then, because
      "remotePort": "Gi1/0/24",                        //   [] is a snapshot the server diffs into
      "linkState": "up" | null                         //   "every neighbour removed". ≤ 64 entries,
    } ],                                               //   fields ≤ 190 chars; MACs lowercased.
    "lldpChassisId": "52:54:00:ab:cd:ef"               // optional; this host's own chassis id (lldpcli)
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
    "operStatus": "up" | null, "speedMbps": 1000 | null,
    // proc (Linux) only; null on every other source and when unreadable:
    "duplex": "full" | "half" | "unknown" | null,          // /sys/class/net/<if>/duplex
    "rxFrameErrors": 0 | null, "rxFifoErrors": 0 | null,   // /proc/net/dev rx frame, rx fifo (deltas)
    "txCollisions": 0 | null, "txCarrierErrors": 0 | null  // /proc/net/dev tx colls, tx carrier (deltas)
  } ],
  "interfacesOmitted": 12,     // only when the cap below kicked in
  "totals": { "rxBytes": 0, "txBytes": 0, "rxPackets": 0, "txPackets": 0,
              "rxErrors": 0, "txErrors": 0, "rxDrop": 0, "txDrop": 0,
              "rxBytesPerSec": 0, "txBytesPerSec": 0 }
}
```

`duplex` and the four error-detail counters are what let the server tell a
duplex mismatch (half duplex + collisions, or frame errors on the full-duplex
end) from a cabling fault (frame/CRC errors on a full-duplex link) from a host
that is simply too slow (rx fifo overruns). They are **null, never 0**, when the
source cannot read them (Windows/macOS sources, a down link, most virtual
interfaces), because a measured zero is what rules those faults out. Additive:
an older server ignores them.

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
  "topTalkers": [ { "pair": "10.0.0.1->93.184.216.34", "bytes": 0, "packets": 0, "flows": 0 }, ... ], // top 50
  "flows": [ { "srcIp": "10.0.0.1", "dstIp": "10.0.0.9", "proto": "tcp",  // top 200 by bytes; per-5-tuple + VLAN
              "srcPort": 51000, "dstPort": 443, "bytes": 0, "packets": 0, "flows": 0,
              "vlan"?: 120, "inIf"?: 3, "outIf"?: 49 }, ... ],        // present only when the exporter reported them
  "sflowCounters"?: [ {                          // sflow only; counter samples, see below
      "agent": "10.14.0.2", "ifIndex": 7, "at": 1790000000000, "uptimeMs": 123456,
      "ifType": 6, "speed": 1000000000, "direction": 1, "status": 3,
      "if":  [ /* 13 counters, IF_COUNTER_FIELDS order */ ],
      "eth"?: [ /* 13 counters, ETHERNET_FIELDS order */ ] }, ... ],
  "sflowCountersPending"?: 12,                   // readings that did not fit, sent next time
  "sflowExporters"?: ["10.14.0.2", "2001:db8::1"], // sflow only; every exporter heard from this interval
  "truncated"?: { "budgetBytes": 49088, "originalBytes": 66077,     // sflow only; the collector made
                  "removed": { "flows": 71 } }                       // room for the counters' floor
}
```

`sflowExporters`: the distinct exporter addresses (the sFlow agent address in
the datagram header, IPv6 compressed as in `sflowCounters[].agent`) heard from
since the last snapshot, in **any** sample — flow or counter — in first-seen
order, ≤ 256. Flow records are aggregated without the exporter, so without this
an exporter that sends only flow samples (counter polling off) was named
nowhere. Absent when nothing was heard. Additive: an older server ignores it.

`vlan` / `inIf` / `outIf`: the 802.1Q VLAN id (1..4094) and the
exporter's ingress/egress ifIndex. sFlow: the tag in the sampled frame (outer
tag of QinQ), else the extended-switch record (1001); the flow-sample header's
input/output interface (format 0 only). NetFlow v9/IPFIX: IE 243 (else 58) and
IE 10/14. Absent keys mean "not reported". The VLAN is part of the aggregation
key; the interfaces are not (the first seen is kept). The sampled frame's MACs
are decoded but not sent.

`sflowCounters`: the latest sFlow **counter sample** per
(exporter, ifIndex) — generic interface counters (enterprise 0, format 1) and
Ethernet counters (format 2). Arrays, not named keys, to fit the 64 KB result
limit (~200 bytes an interface instead of ~500):

- `if` = `ifInOctets, ifInUcastPkts, ifInMulticastPkts, ifInBroadcastPkts,
  ifInDiscards, ifInErrors, ifInUnknownProtos, ifOutOctets, ifOutUcastPkts,
  ifOutMulticastPkts, ifOutBroadcastPkts, ifOutDiscards, ifOutErrors`
  (`src/sflow/collector.js IF_COUNTER_FIELDS`);
- `eth` = `dot3StatsAlignmentErrors, FCSErrors, SingleCollisionFrames,
  MultipleCollisionFrames, SQETestErrors, DeferredTransmissions, LateCollisions,
  ExcessiveCollisions, InternalMacTransmitErrors, CarrierSenseErrors,
  FrameTooLongs, InternalMacReceiveErrors, SymbolErrors`
  (`src/sflow/parse.js ETHERNET_FIELDS`);
- a counter the exporter marks unavailable (all ones) is `null`, never 0;
- `agent` is the exporter's address from the datagram header (IPv6 compressed);
  `at` is when the agent received it (ms epoch); `uptimeMs` the exporter's own
  uptime; `speed` bits/s; `direction` 0 unknown, 1 full, 2 half duplex, 3 in,
  4 out; `status` bit 0 = admin up, bit 1 = oper up.

Bounded: ≤ 1024 entries and ≤ 24 KB per snapshot, and never more than keeps the
whole snapshot ≤ 56 KB. What does not fit stays pending (replaced by a newer
reading, dropped after 10 min) and goes first next time, so a large switch is
rotated through rather than starved. When readings are pending the counters get
**at least 8 KB** even if the flow summary alone would fill the 56 KB: the
smallest `flows` (then `topTalkers`) make way, and the snapshot's `truncated`
says how many — the totals are summed before any cut and stay whole. (Before
this, 200 IPv6 flows left the counters no room at all, every interval.) The server
(`src/devices/sflowCounterIngest.js`) stores them as device counter samples for
exporters that are registered SNMP devices, and ignores the key when older.

`flows` is the full-5-tuple form the server prefers (populates `flow_records.proto` /
`dst_port`, and feeds the **service dependency graph**); `byPort`/`byProtocol`/
`topTalkers` are unchanged. All additive — an older server ignores `flows` and keeps
using `topTalkers`; a newer server falls back to `topTalkers` when `flows` is absent
(e.g. a `proc`/`snmp` source, which produces interface counters, not per-flow rows).

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

A result over that is a 400 for the **whole** report, so the agent never sends
one (`src/resultBudget.js`, applied in `runtime.js` before the POST). A result
over **60 000 bytes** is trimmed from the tails of, in this order,
`traffic.sflowCounters` (handed back to the collector, sent next interval),
`traffic.flows` (smallest first), `traffic.topTalkers`, then — never reached in
practice — `byPort`, `byProtocol`, `interfaces`; as a last resort the traffic
keeps only its scalars and `totals`. What was cut is named on the result:

```jsonc
"truncated"?: { "budgetBytes": 60000, "originalBytes": 81234,
                "removed": { "traffic.sflowCounters": 60, "traffic.flows": 12 } }
```

and logged. A result that still cannot fit is not sent (logged as
`RESULT_TOO_LARGE`). The totals are never trimmed.

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
  "type": "ping"|"tcp"|"dns"|"traceroute"|"tcptraceroute"|"http"|"curl"|"pageload"|"transaction"|"path_mtu"|"tls"|"rdns"|"dhcp",
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
| `tcp` | `failure`: `"refused"`\|`"timeout"`\|`"unreachable"`\|`"error"`\|`null`, `errorCode` (e.g. `ECONNREFUSED`, `ETIMEDOUT`, `EHOSTUNREACH`) \| `null` | the LAST failing attempt; both `null` when no attempt failed. `refused` = RST (host up, port closed), `timeout` = nothing came back |
| `dns` | `detail` = first resolved address, `errorCode` (e.g. `ENOTFOUND`, `ETIMEOUT`, `ESERVFAIL`, `ECONNREFUSED`, `EAI_AGAIN`) \| `null` | `errorCode` is the LAST failing lookup's code; `null` when none failed |
| `traceroute` | `hops: [{hop, ip, ips, sent, recv, lossPct, rttMs, minMs, maxMs, jitterMs}]`, `hopCount`, `queries` | `ip` = first responder (unchanged); `ips: string[]` = every DISTINCT responder on that hop line, in order (ECMP), `[]` for a silent hop. The live `trace_hop` frame's `hop` carries the same record. `hopCount`/`queries` not persisted; `hops` capped server-side at 64 |
| `tcptraceroute` | the same `hops`/`hopCount`/`queries`, plus `port` | identical hop record — the path is traced with TCP SYNs instead of ICMP/UDP. `target` is `host:port`, which is what keeps a TCP trace and an ICMP trace to the same host as separate series. `port` is not persisted (it is already in `target`) |
| `http` | `status`, `certExpiryDays` (https), `detail` (cert detail) | |
| `tls` | `certExpiryDays`, `detail`, `tls: {protocol, cipher, authorized, authorizationError, chainTrusted, hostnameMatches, servername, expiryDays, expired, notYetValid, validFrom, validTo, subject, issuer, altNames, serialNumber, fingerprint256, chainLength, selfSigned}` (only when a certificate was received; a failed handshake is `ok:false` + `error`, no `tls`) | `target` is `host:port`, or `servername@host:port` when an explicit `servername` differs from `host` (agent 0.40+), so two names on one address are two series. `authorized`/`authorizationError` are node's verdict verbatim; `chainTrusted` (0.40+) separates the chain from the name — node checks the chain first, so `ERR_TLS_CERT_ALTNAME_INVALID` is `chainTrusted:true` + `hostnameMatches:false`. `hostnameMatches` is `null` for an IP probed without a name. `servername` = the SNI sent, `null` for none |
| `curl` | `status`, `bytes`, `contentType`, `detail` (assertion summary) | metadata only, never the body |
| `pageload` | `status`, `bytes` (page weight), `elements: [{url, kind, status, bytes, ms}]`, `detail` | `elements` capped server-side at 64 |
| `transaction` | `status` (last step), `bytes` (total), `elements` (`kind` = `"step N METHOD"`), `detail` | extracted variables never leave the agent |
| `dhcp` | `iface`, `timeoutMs`, `offers: [{serverId, offeredIp, leaseSec, router, dns[], subnetMask, relay}]` (≤ 8), `serverCount`, `detail` | a broadcast DHCPDISCOVER from `0.0.0.0:68` (broadcast flag, random xid, `chaddr` = the interface MAC); every DHCPOFFER for that xid is collected until `timeoutMs` (default 3000, clamped 1000–10000). **No DHCPREQUEST is ever sent**, so no lease is taken. `target` = the interface. `ok` = at least one offer; `rttMs` = first offer. `serverCount` = distinct server identifiers (option 54) — more than one is the rogue-server signal. No answer is `ok:false` + `offers: []` + `detail`, NOT `error`; `error` means it could not run (`"dhcp probe needs root or CAP_NET_BIND_SERVICE (port 68)"`, port 68 held by the host's own DHCP client, no IPv4 interface). `relay` = giaddr when the offer came through a relay agent |

Server persistence (`validation/probeValidation.js`): keeps `ts, type, target,
ok, rttMs, minMs, maxMs, jitterMs, lossPct, hops, status, certExpiryDays,
bytes, contentType, elements, detail, execError`; strings length-capped
(target 255, detail 255, contentType 120, hop ip 45, element url 255).
From server 0.188.0 it also keeps why a probe failed: `errorCode` (dns + tcp,
errno-shaped `[A-Z0-9_]{1,32}`, else dropped), `failure` (tcp only: `refused`,
`timeout`, `unreachable`, `error`) and `resolver` (dns only, the first system
nameserver), plus each hop's `ips` (deduplicated, at most 8, first == `ip`)
inside the hops JSON — the ECMP members the path graph and diagnose count.
Everything else (`attempts`, `success`, `hopCount`, `queries`, `role`) is
silently discarded. `error` is mapped to `execError` (and into `detail` when no
`detail` was sent) — `execError` drives the server's `agent.probe-failed`
auditing and the traceroute auto-install trigger. A `tcptraceroute` reports
`"tcptraceroute not installed"` only when BOTH it and the `traceroute -T`
fallback are missing, so the name in the reason is always one the install-tool
allowlist can act on; a raw-socket permission failure reads
`"<bin> needs root (raw socket)"` instead and correctly triggers nothing.

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

### 1.9 `POST /agents/me/snmp-topology` — one SNMP topology cycle

Sent by `src/snmpPoller.js` after polling the switches in `snmpTargets`
(`src/snmpTopology.js` builds each device's entry). Body
`{ devices: [ … ], errors: [{ deviceId, error, code }] }`. A cycle that would
exceed ~900 KiB is sent as **several POSTs**, split by device (never within
one); the per-device `errors` travel in the first. A device too big on its own
has its `arp` list trimmed and `arpTruncated: true`.

**Core first, optional in what is left.** Each device gets one timeout (30 s).
The core tables (`if`, `fdb`, `lldp`, `vlan`) are walked first; the optional
ones (`cdp`, `arp`, `entity`) are walked afterwards in the remaining time, less
a 2 s reserve. An optional walk that runs out of time or fails is abandoned and
the device is still submitted with its core tables — named in the device's own
`partial` list, **not** in `errors` (which would record the whole poll as
failed):

```jsonc
"partial"?: [ { "kind": "arp" | "cdp" | "entity",
                "reason": "timeout" | "error" | "no-time",   // no-time: never started
                "rows"?: 3120,                               // arp: rows kept
                "error"?: "Request timed out" } ]
```

A cut `arp` keeps the rows read so far (`arpTruncated: true`; the server
upserts them). So does the per-VLAN forwarding walk below (`kind: 'fdb'`,
with `vlans`/`of` counts; reason `rotating` when the device has more than 64
VLANs — the default VLAN is read every poll and the others rotate, 63 a poll,
so every VLAN is covered within ⌈(VLANs−1)/63⌉ polls; `no-time` when the
budget ran out). A cut `cdp` or `entity` reports none of its rows — the server
diffs neighbours and replaces the inventory, so half a table would read as
removals. `supported` keeps a kind the device answered on its previous poll
when this poll cut it short. `partial` is absent on a complete poll; a server
that does not know it ignores it.

Each device entry — every field after `deviceId` is optional to the server,
and everything below the `vlans` line is newer than the server's first
version of this endpoint, so an older server ignores it:

**Catalyst IOS (no Q-BRIDGE-MIB).** VLAN names fall back to CISCO-VTP-MIB
`vtpVlanName` (operational VLANs only, 1002-1005 left out) when
`dot1qVlanStaticName` is empty. The forwarding table: IOS keeps one BRIDGE-MIB
instance per VLAN and the default community reads only VLAN 1's, so when the
Q-BRIDGE FDB is empty and VTP lists VLANs, each VLAN's `dot1dTpFdbPort/Status`
+ `dot1dBasePortIfIndex` are walked under `community@<vlan>` (SNMPv3: context
`vlan-<vlan>`), at most 64 VLANs, 4 at a time, inside the optional-phase time
budget, stopping after 3 VLANs fail in a row. Those rows carry their `vlan`
and resolve through THAT VLAN's bridge-port map; a MAC the untagged default
walk also saw is reported once, tagged.

```jsonc
{
  "deviceId": 7,
  "sysUpTimeTicks": 123456, "sysName": "sw-core-1", "sysDescr": "Cisco IOS …",
  "interfaces": [ … ], "fdb": [ … ], "fdbTruncated": false, "fdbTotal": 812,
  "vlans": [ { "vlan": 20, "name": "Kontor" } ],
  "supported": ["if", "fdb", "lldp", "vlan", "cdp", "arp", "entity"],
  // SNMPv2-MIB system group (second GET, so a v1 noSuchName never costs the uptime)
  "sysLocation": "Bygning 3, rum 2.14, rack B", "sysContact": "…", "sysObjectId": "1.3.6.1.4.1.9.1.1745",
  // LLDP and CDP in one list (≤ 512 together, LLDP first); `protocol` says which
  "neighbours": [
    { "protocol": "lldp", "localPort": 3, "localIfIndex": 10003, "localIfName": "Gi0/24",
      "remoteChassisId": "aa:bb:cc:11:22:33", "remotePortId": "Gi1/0/5", "remotePortDesc": "…", "remoteSysName": "sw-acc-2" },
    { "protocol": "cdp", "localPort": 10102, "localIfIndex": 10102, "localIfName": "Gi1/0/2",
      "remoteChassisId": "sw-dist-1", "remotePortId": "Gi1/0/48", "remotePortDesc": null, "remoteSysName": "sw-dist-1",
      "remoteAddress": "10.14.0.11", "remotePlatform": "cisco WS-C3850-48P" }
  ],
  // IP-MIB ARP table (collect 'arp'): ipNetToPhysicalTable, else ipNetToMediaTable
  "arp": [ { "ip": "10.20.0.84", "mac": "00:1b:44:11:3a:b7", "ifIndex": 20, "ifName": "Vlan20" } ],
  "arpSource": "ipNetToPhysical" | "ipNetToMedia" | null, "arpTruncated": false, "arpTotal": 1,
  // ENTITY-MIB (collect 'entity'): every chassis (≤ 16) + modules with a model or serial (≤ 32)
  "inventory": [ { "entIndex": 1, "class": "chassis" | "module", "name": "Switch 1", "descr": "…",
                   "model": "WS-C3850-48P", "serial": "FOC1234X0AB", "vendor": "Cisco Systems, Inc.",
                   "hardwareRev": "V07", "firmwareRev": "…", "softwareRev": "16.12.04" } ]
}
```

What is walked follows the device's `collect` from `snmpTargets`: `cdp`, `arp`
and `entity` are opt-in kinds, so an agent polling for a server that never sends
them reads exactly what it read before. A device that does not implement a MIB
answers with an empty walk, which is an empty list and never an error.

## 2. WebSocket `/ws/agent`

Connection: `ws(s)://<server>/ws/agent` with `Authorization: Bearer <token>` and
`X-BlueEye-Protocol: <n>` (the agent's wire-contract version from
`src/protocol.js`; absent on a pre-versioning agent → the server treats it as 1).
The server echoes its own version in the `connected` frame. A version mismatch is
logged on both sides but is **never** fatal — the server stays backward-compatible
so fielded agents update on their own schedule.
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
| `connected` | `{ type:'connected', agentId, protocolVersion }` | immediately after the upgrade |
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
| `rekey` (aliases: re-key, rotate-key, repin, re-pin) | `id`, `auditId?`, `publicKey` (required PEM) | replace the pinned release trust anchor, in memory and on disk. **Strict by default** — see §2.3 | `ack {id, accepted, runtime}`, `command-result {id, ok, fingerprint?}`, `action-result` |
| `evidence` (alias: evidence-snapshot) | `id`, `snapshotId`, `clusterId`, `commandSetVersion`, `items[]`, `signature?` | collect READ-ONLY items from the agent's own allowlist (`iface.counters`, `arp.table`, `snmp.reads`, `agent.state`); anything else is refused per item | `command-result {id, ok:true, evidence:{commandSetVersion, items[]}}` |
| `run-discovery` (aliases: discovery-sweep, sweep) | `discovery: { cidrs?, ports?, rateLimit?, addressCap?, requestId? }` (required object) | sweep the scope from THIS agent's vantage (empty scope ⇒ its own subnets), POST `/agents/discovery-results` | — (REST only); a scope refusal posts `refused:true` with a reason |
| `poll-snmp` | `deviceId?` | re-read `GET /agents/me/config` (≤ 5 s, errors tolerated), then run an SNMP topology + counter cycle now instead of waiting out the per-device interval (a cycle already in flight is waited for, then this one runs — never a silent "0 polled"); read-only on the device | `command-result {id, ok:true, devices, polled, failed, configRefreshed, deviceAssigned?, detail?, snmp, counters}` — `devices` = switches assigned to this agent; `detail` says so when that is 0 or when `deviceId` is not one of them |
| `burst` (alias: burst-mode) | `id`, `target` (required), `seconds?`, `hz?`, `probe?`, `size?`, `df?` | measure ONE target up to once a second for at most two minutes, streaming every sample | `command-result` per sample + a final one |
| `stop-burst` (alias: burst-stop) | `id` | cancel a running burst at the next tick | `command-result {id, ok:true, stopped:bool}` |

Probe `spec` (built by the server's `validateProbeSpec`): `{ type, host,
count?, port? (tcp, tcptraceroute — the latter defaults to 443),
maxHops?/queries? (traceroute, tcptraceroute), maxElements? (pageload),
method?/expectStatus?/expectBody?/expectHeader?/minBytes?/maxBytes? (curl),
steps?/name? (transaction), iface?/timeoutMs? (dhcp — no host; `iface`
defaults to the default-route interface) }`. The agent reads the target from
`spec.host || spec.target` (http-family probes get the URL in `host`).

Anything unrecognised is logged and dropped (`command-ignored`). A handler that
THROWS is caught by the dispatcher: the agent replies `command-result
{ok:false, error:'handler failed: …'}` (and `action-result` when an `auditId`
was given) and keeps running — an async handler's rejection must never be able
to take a monitoring agent off a host nobody is watching.

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
`capabilities`, `config`, `device-events`, `discovery`, `probe`,
`probe-targets`, `scheduled-probes`, `snmp-counters`, `snmp-topology`,
`speedtest`, `syslog-bind`, `traffic-report`, `trap-bind`. Best-effort: sent only when the
socket is open; a closed socket drops the frame (the server infers offline
anyway). A 401 is never reported this way (it is fatal instead).

The list above is pinned to `reportError()` by
`test/gate/protocolDoc.test.js` — the server dedupes audit rows per
`(agent, category, code)`, so the vocabulary is part of the contract.

### 2.3 Command authenticity

By default a command is trusted because it arrived on the authenticated
WebSocket. For the commands that change the HOST rather than measure it
(`update`, `delete`, `install-tool`, `rekey`) the server also signs, when it
can, and the agent verifies (`src/commandAuth.js`).

| field | meaning |
| --- | --- |
| `commandSignature` | base64 Ed25519 over `canonicalize(command minus commandSignature and id)`, made with the **release key** the agent already pins for signed updates. Not `signature`, which on an `update` signs the release manifest — the payload to install, not the instruction to install it. |
| `agentId` | binds the signature to one agent, so a captured command cannot be replayed across the fleet. Required on any signed command. |
| `issuedAt` | ISO timestamp; the agent accepts ±5 minutes. Required on any signed command. |

Policy:

| situation | outcome |
| --- | --- |
| signed, verifies against the pinned key | accepted |
| signed, does not verify (or no key pinned) | **refused** — a signature that cannot be checked is worse than none |
| unsigned, `BLUEEYE_REQUIRE_SIGNED_COMMANDS=1` | refused |
| unsigned, default, `update`/`delete`/`install-tool` | accepted (backward compatible with a server that cannot sign) |
| unsigned `rekey`, agent already holds a key | **refused by default.** `rekey` replaces the anchor every later signature is checked against, so accepting an unsigned one turns one moment of socket access into permanent, silent code execution. A legitimate rotation is signed with the key being replaced. |
| unsigned `rekey`, no key pinned yet | accepted — nothing to downgrade (the anchor arrived by trust-on-first-use anyway) |
| unsigned `rekey`, `BLUEEYE_ALLOW_UNSIGNED_REKEY=1` | accepted — break-glass for a fleet whose server lost its signing key; setting it needs access to the host, which is the authority re-anchoring trust deserves |

A refusal is reported on every channel the handler would have used (`ack`
`accepted:false`, `command-result` `ok:false`, and `action-result` when an
`auditId` was given), so the operator sees a declined action rather than
silence.

`diagnostic` shape (`src/runtime.js buildDiagnostic()`):

```jsonc
{ "agentVersion": "0.9.0", "managed": "systemd",
  "source": "sflow", "sources": ["proc","netflow","sflow"],
  "intervalMs": 60000, "lastReportAt": "<ISO>" | null,
  "collector": { "kind": "sflow", "listening": true, "datagrams": 0, "dropped": 0,
                 "decodedFlows": 0, "counterSamples": 0,   // sflow only
                 "counterInterfaces": 0, "counterOverflow": 0, // sflow only: pending counter readings
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
| `BLUEEYE_PROBE_TARGETS` | `probeTargets` | `[]` | extra targets (`"ping:1.1.1.1,tcp:host:443,dns:example.com"`; `"dhcp"` / `"dhcp:eth0"` schedules the DHCP test — never on by default) |
| `BLUEEYE_CAPABILITIES_INTERVAL_MS` | `capabilitiesIntervalMs` | `300000` | periodic capabilities re-report (§1.4); `0` disables |
| `BLUEEYE_CONFIG_REFRESH_MS` | `configRefreshIntervalMs` | `300000` | periodic `GET /agents/me/config` (§1.3); an unchanged config is a no-op; `0` disables |
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

Runs after every successful `GET /agents/me/config` at startup and on each WS
reconnect, and after a periodic/`poll-snmp` re-read only when `monitorConfig`
changed (`src/runtime.js reconcileHsflowd`):

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
| `sflowCounters` | ≤ 1024 entries, ≤ 24 KB, ≥ 8 KB floor when pending, whole snapshot ≤ 56 KB; ≤ 4096 interfaces pending, stale after 10 min |
| `sflowExporters` | ≤ 256 addresses per snapshot |
| traffic result (agent-side) | trimmed to ≤ 60 000 bytes before the POST (`truncated` names what went); never sent over 65 535 |
| `POST /agents/me/snmp-topology` | ≤ ~900 KiB per POST (split by device); per device: fdb ≤ 5 000, neighbours (LLDP+CDP) ≤ 512, arp ≤ 8 192 (walk bounded at 16 384 rows), inventory ≤ 16 chassis + 32 modules (agent-side) |
