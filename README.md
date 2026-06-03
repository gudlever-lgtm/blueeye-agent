# blueeye-agent

The BlueEye agent runs on customer machines and connects to **blueeye-server**.
It enrolls once with a one-time code, stores an **opaque token** locally,
keeps a **WebSocket** open to the server (status + commands), and submits
**test results** via REST.

Written in Node.

## Dependencies

Open-source / permissive licences only — **no US-cloud SDKs**, no telemetry:

| Component        | Licence | Role                                    |
| ---------------- | ------- | ---------------------------------------- |
| ws               | MIT     | WebSocket client (agent live channel)    |
| Node `fetch`     | —       | HTTP (built-in undici — Node.js project) |
| Node `node:test` | —       | Test runner (development only)           |

`ws` is the only external runtime dependency. HTTP is handled by Node's
built-in `fetch`, so there is no external HTTP SDK.

## Requirements

- Node.js >= 18 (developed and tested on Node 22)
- Access to a running `blueeye-server`

## Getting started

```bash
npm install

# 1) Create a config (see config.example.json) with serverUrl + one-time code
cp config.example.json blueeye-agent.config.json
#    Obtain the one-time code from the server:  POST /enrollment-codes (operator/admin)

# 2) Start the agent
npm start
```

On first start the agent enrolls, stores its token, and removes the
one-time code from the config file. Subsequent starts use the stored token and
**skip enrollment**.

### Easiest: one-liner from the server

In the server UI (**Enrollment → Add agent**) a ready-made command is generated
with the code, server address, and checksum already filled in. Run it on the
machine:

```bash
curl -sSL https://<server>/enroll/<CODE>/install.sh | sh
```

The script fetches the agent binary **from the server itself** (works in
air-gapped networks too), verifies its SHA-256, runs `blueeye-agent enroll`,
and installs a systemd service. You never type the server address yourself.

### Manual: the `enroll` command

```bash
blueeye-agent enroll --code <CODE> [--server <URL>] [--fingerprint <SHA256>]
```

Exchanges the code for a token and stores it (0600). `--server`/`--fingerprint`
are saved in the config file so the service started afterwards reaches the right
server with **certificate pinning**. If `--server` is omitted, the embedded or
configured URL is used (or `GET /enroll/config`). The command is idempotent:
if a token already exists it does nothing (unless `--force`).

## Install as a Docker container

`install.sh` clones/updates the repo, builds the image, and runs the agent as a
restart-on-boot container. The token lives on a named volume so it is reused
across restarts and upgrades (the one-time code is only used on first start).

```bash
# Clone the repo
git clone https://github.com/gudlever-lgtm/blueeye-agent.git
cd blueeye-agent

# Install + start as a Docker container (Linux: --network host measures host traffic)
BLUEEYE_SERVER_URL=https://server.example \
BLUEEYE_ENROLLMENT_CODE=<one-time-code> \
./install.sh
```

Update later with `git pull` and re-run `./install.sh` (or run the script from
anywhere — without a checkout it will clone the repo itself). Optional env:
`NETWORK_MODE=bridge`, `CONTAINER`, `IMAGE`, `TOKEN_VOLUME`. Manage the
container with `docker logs -f blueeye-agent` / `docker restart blueeye-agent`.

## Configuration (file + env)

Configuration is read from a JSON file and can be overridden by environment
variables (precedence: built-in defaults → config file → env). See
[`config.example.json`](config.example.json) and [`.env.example`](.env.example).

| Field (file)      | Env variable                 | Default                        | Description                              |
| ----------------- | ---------------------------- | ------------------------------ | ---------------------------------------- |
| (file path)       | `BLUEEYE_AGENT_CONFIG`       | `./blueeye-agent.config.json`  | Path to the JSON config file             |
| `serverUrl`       | `BLUEEYE_SERVER_URL`         | `http://localhost:3000`        | blueeye-server URL                       |
| `enrollmentCode`  | `BLUEEYE_ENROLLMENT_CODE`    | (none)                         | One-time code — first start only         |
| `serverCertFingerprint` | `BLUEEYE_SERVER_CERT_FINGERPRINT` | (none)              | SHA-256 of the server's TLS cert — pinned when https |
| `tokenPath`       | `BLUEEYE_TOKEN_PATH`         | `./.blueeye-agent/token`       | Where the token is stored (0600)         |
| `heartbeatMs`     | `BLUEEYE_HEARTBEAT_MS`       | `15000`                        | Heartbeat message interval               |
| `reconnectBaseMs` | `BLUEEYE_RECONNECT_BASE_MS`  | `1000`                         | Reconnect backoff base                   |
| `reconnectMaxMs`  | `BLUEEYE_RECONNECT_MAX_MS`   | `30000`                        | Reconnect backoff ceiling                |
| `probeIntervalMs` | `BLUEEYE_PROBE_INTERVAL_MS`  | `60000`                        | Scheduled probes — `0` disables          |
| `probeCount`      | `BLUEEYE_PROBE_COUNT`        | `3`                            | Attempts per scheduled probe             |
| `probeGateway`    | `BLUEEYE_PROBE_GATEWAY`      | `true`                         | Auto-ping default gateway                |
| `probeDns`        | `BLUEEYE_PROBE_DNS`          | `true`                         | Auto-ping DNS servers (resolv.conf)      |
| `probeTargets`    | `BLUEEYE_PROBE_TARGETS`      | (none)                         | Extra targets, e.g. `ping:1.1.1.1,tcp:host:443` |

> **Scheduled probes:** by default the agent runs a small set of reachability
> probes every 60 seconds — the auto-discovered default gateway + DNS servers
> (`/etc/resolv.conf`) plus any `probeTargets` — and submits them to the server
> so fleet health is populated without manual intervention. Metadata only
> (targets + timings), never packet content. Set `BLUEEYE_PROBE_INTERVAL_MS=0`
> to disable.

> If the one-time code is supplied via an env variable, the agent cannot remove
> it from there — remove it yourself after the first start. (The agent will not
> re-enroll as long as a stored token exists.)

## Enrollment (first start)

1. The agent collects `hostname`, `platform`, `arch`.
2. `POST /agents/enroll { code, hostname, platform, arch }`.
3. The returned token is stored locally in a file with **restrictive permissions
   (0600)**, and `enrollmentCode` is removed from the config file.
4. If the code is rejected (invalid/used/expired → `401`/`410`), the agent fails
   **hard** and does **not** retry automatically.

## Operation

- Opens a WebSocket to `/ws/agent` with the token in the `Authorization: Bearer` header.
- Sends a periodic heartbeat so the server keeps `last_seen` fresh.
- Listens for server commands. A **run-test** command (e.g.
  `{ type: "command", command: { name: "run-test", intervalMs: 1000 } }`) causes
  the agent to **measure network traffic** and submit the result.
- **Traffic sources** — the agent can measure traffic in two ways, and **the
  server selects which one per agent** (matched by agent ID via the token):
  - `proc` ([`src/trafficMonitor.js`](src/trafficMonitor.js)): reads
    `/proc/net/dev` twice `intervalMs` apart, computing per-interface rx/tx bytes
    and rates. Run the container with `network_mode: host` to measure the host's
    full traffic (otherwise only the container's own interfaces are measured).
  - `snmp` ([`src/snmpMonitor.js`](src/snmpMonitor.js)): polls a Cisco device's
    IF-MIB high-capacity octet counters (ifHCInOctets/ifHCOutOctets) over SNMP —
    useful when the agent runs alongside the device, or on IOS without `/proc`.
- **Capabilities + config:** on start the agent reports its capabilities
  (`{ sources: [...] }`) to `POST /agents/me/capabilities` and fetches its
  assigned source from `GET /agents/me/config`. It re-fetches the config on every
  (re)connection so dashboard changes take effect immediately. Both sources
  produce the same result format, so the server/dashboard treats them uniformly.
- **Continuous reporting:** independently of server commands, the agent measures
  traffic and submits the result on a fixed interval
  (`BLUEEYE_REPORT_INTERVAL_MS`, default 60s; `0` disables it). This is how the
  server receives continuous data without anyone pressing "Run test".
- Submits results via `POST /agents/results { results: [...] }` with a
  Bearer token.
- **Reconnects** on a lost connection with exponential backoff (+ jitter).
- **Hard failure** if the token is rejected (`401` at WS handshake or on
  results-POST): the agent logs the error and stops — it does **not** re-enroll
  automatically.

Two separate security boundaries: the agent's token is used **only** against
agent endpoints (WS + `/agents/results`). It is not a user JWT.

## Project structure

See [`codemap.md`](codemap.md) for an up-to-date map of the source code —
architecture, modules, data flow, traffic sources (proc/snmp/netflow/sflow),
probes, server API, and test structure.

## Tests

```bash
npm test
```

Tests cover: config merging and one-time code clearing, token storage with
`0600` permissions, command recognition, backoff, and **integration tests against
a running server**: enroll flow, WS connect (valid/invalid token), result
submission, and reconnect.

> The integration tests run against a contract-faithful stub server
> ([`test-support/fakeServer.js`](test-support/fakeServer.js)) with exactly the
> same endpoints as `blueeye-server` (`/agents/enroll`, `/ws/agent`,
> `/agents/results`). The real server requires MySQL; the stub makes the tests
> self-contained and fast without deviating from the contract.
