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

- Node.js >= 18 (udviklet og testet på Node 22)
- 64-bit host (`linux/amd64` eller `linux/arm64`)
- Adgang til en kørende `blueeye-server`

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

Opdatér senere med `git pull` og kør `./install.sh` igen (eller kør scriptet et
vilkårligt sted — uden et checkout kloner det selv repoet). Valgfrie env:
`NETWORK_MODE=bridge`, `CONTAINER`, `IMAGE`, `TOKEN_VOLUME`. Styr containeren med
`docker logs -f blueeye-agent` / `docker restart blueeye-agent`.

Imaget bygges til en **64-bit** platform. `install.sh` detekterer host-arkitekturen
automatisk (`linux/amd64` eller `linux/arm64`); overstyr med `PLATFORM`, fx
`PLATFORM=linux/arm64 ./install.sh`. 32-bit hosts understøttes ikke.

## Uninstalling

Easiest — a one-liner from the server (mirrors install):

```bash
curl -sSL https://<server>/enroll/uninstall.sh | sudo sh            # warns, then asks y/N
curl -sSL https://<server>/enroll/uninstall.sh | sudo sh -s -- --purge   # pass flags after --
```

`uninstall.sh` is also shipped **with the agent** — the installer drops it in the
install directory, so it's already on the machine:

```bash
sudo sh /opt/blueeye-agent/uninstall.sh            # warns, then asks y/N
sudo sh /opt/blueeye-agent/uninstall.sh --yes      # no prompt
sudo sh /opt/blueeye-agent/uninstall.sh --purge    # also remove the Docker image + token volume
```

It auto-detects how the agent was installed and removes it accordingly:

- **Node install** — stops + disables the `blueeye-agent` systemd service and deletes the unit.
- **Docker install** — stops + removes the `blueeye-agent` container (`--purge` also drops the image and the `blueeye-agent-data` volume).
- Removes the install directory `/opt/blueeye-agent` (including the stored token).

It **warns and asks for confirmation first** (skip with `--yes`) and needs `sudo`.
Env overrides: `SERVICE_NAME`, `BLUEEYE_INSTALL_DIR`, `CONTAINER`, `IMAGE`,
`TOKEN_VOLUME`.

> This removes the agent **locally only**. To also remove it from the BlueEye
> server's list, open the dashboard → **Agents → Delete**.

(If you installed from a checkout with the Docker `install.sh`, you can run
`sudo ./uninstall.sh` from that checkout instead.)

## Konfiguration (fil + env)

Konfiguration læses fra en JSON-fil og kan overstyres af miljøvariabler
(rækkefølge: indbyggede defaults → config-fil → env). Se
[`config.example.json`](config.example.json) og [`.env.example`](.env.example).

| Felt (fil)        | Env-variabel                 | Standard                       | Beskrivelse                         |
| ----------------- | ---------------------------- | ------------------------------ | ----------------------------------- |
| (fil-sti)         | `BLUEEYE_AGENT_CONFIG`       | `./blueeye-agent.config.json`  | Sti til JSON-config                 |
| `serverUrl`       | `BLUEEYE_SERVER_URL`         | `http://localhost:3000`        | blueeye-server URL                  |
| `enrollmentCode`  | `BLUEEYE_ENROLLMENT_CODE`    | (ingen)                        | Engangskode — kun ved første start  |
| `serverCertFingerprint` | `BLUEEYE_SERVER_CERT_FINGERPRINT` | (ingen)             | SHA-256 af serverens TLS-cert — pinnes ved https |
| `tokenPath`       | `BLUEEYE_TOKEN_PATH`         | `<agent-dir>/.blueeye-agent/token` | Hvor tokenet gemmes (0600) — relativt til agentens egen mappe, ikke cwd |
| `heartbeatMs`     | `BLUEEYE_HEARTBEAT_MS`       | `15000`                        | Interval for heartbeat-besked       |
| `reconnectBaseMs` | `BLUEEYE_RECONNECT_BASE_MS`  | `1000`                         | Backoff-basis ved reconnect         |
| `reconnectMaxMs`  | `BLUEEYE_RECONNECT_MAX_MS`   | `30000`                        | Backoff-loft                        |
| `probeIntervalMs` | `BLUEEYE_PROBE_INTERVAL_MS`  | `60000`                        | Planlagte probes — `0` slår fra     |
| `probeCount`      | `BLUEEYE_PROBE_COUNT`        | `3`                            | Antal forsøg pr. planlagt probe     |
| `probeGateway`    | `BLUEEYE_PROBE_GATEWAY`      | `true`                         | Auto-ping default gateway           |
| `probeDns`        | `BLUEEYE_PROBE_DNS`          | `true`                         | Auto-ping DNS-servere (resolv.conf) |
| `probeTargets`    | `BLUEEYE_PROBE_TARGETS`      | (ingen)                        | Ekstra mål, fx `ping:1.1.1.1,tcp:host:443` |

> **Planlagte probes:** agenten kører som standard hvert 60. sekund et lille sæt
> reachability-probes — den auto-opdagede default gateway + DNS-servere
> (`/etc/resolv.conf`) plus evt. `probeTargets` — og indsender dem til serveren, så
> flåde-sundheden er udfyldt uden manuel kørsel. Kun metadata (mål + timings),
> aldrig pakke-indhold. Sæt `BLUEEYE_PROBE_INTERVAL_MS=0` for at slå det fra.

> Hvis engangskoden gives via env, kan agenten ikke fjerne den derfra — fjern
> den selv efter første start. (Agenten enroller alligevel ikke igen, så længe
> der findes et gemt token.)

## Enrollment (første opstart)

1. Agenten samler `hostname`, `platform`, `arch`.
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
