# blueeye-agent

BlueEye-agenten kører på kundens maskiner og forbinder til **blueeye-server**.
Den enroller sig én gang med en engangskode, gemmer et **opaque token** lokalt,
holder en **WebSocket** åben til serveren (status + kommandoer) og indsender
**testresultater** via REST.

Skrevet i Node.

## Afhængigheder

Kun open source/tilladende licenser — **ingen US-cloud-SDK'er**, ingen telemetri:

| Komponent        | Licens | Rolle                                    |
| ---------------- | ------ | ---------------------------------------- |
| ws               | MIT    | WebSocket-klient (agent live-kanal)      |
| Node `fetch`     | —      | HTTP (indbygget undici — Node.js-projektet) |
| Node `node:test` | —      | Test runner (kun udvikling)              |

`ws` er den eneste eksterne runtime-afhængighed. HTTP klares af Node's
indbyggede `fetch`, så der er ingen ekstern HTTP-SDK.

## Krav

- Node.js >= 18 (udviklet og testet på Node 22)
- 64-bit host (`linux/amd64` eller `linux/arm64`)
- Adgang til en kørende `blueeye-server`

## Kom i gang

```bash
npm install

# 1) Lav en config (se config.example.json) med serverUrl + engangskode
cp config.example.json blueeye-agent.config.json
#    Hent engangskoden fra serveren:  POST /enrollment-codes (operator/admin)

# 2) Start agenten
npm start
```

Ved første opstart enroller agenten sig, gemmer sit token og fjerner
engangskoden fra config-filen. Efterfølgende opstart bruger det gemte token og
**springer enrollment over**.

### Nemmest: one-liner fra serveren

I serverens UI (**Enrollment → Tilføj agent**) genereres en færdig kommando med
koden, server-adressen og checksum allerede sat. Kør den på maskinen:

```bash
curl -sSL https://<server>/enroll/<CODE>/install.sh | sh
```

Scriptet henter agent-binæren **fra serveren selv** (virker også i luftgappede
net), verificerer dens SHA-256, kører `blueeye-agent enroll` og installerer en
systemd-service. Du indtaster aldrig selv server-adressen.

### Manuelt: `enroll`-kommandoen

```bash
blueeye-agent enroll --code <CODE> [--server <URL>] [--fingerprint <SHA256>]
```

Veksler koden til et token og gemmer det (0600). `--server`/`--fingerprint` huskes
i config-filen, så servicen bagefter rammer den rigtige server med
**certifikat-pinning**. Mangler `--server`, bruges den indlejrede/konfigurerede
URL (eller `GET /enroll/config`). Kommandoen er idempotent: findes der allerede et
token, springes den over (medmindre `--force`).

## Installér som Docker-container

`install.sh` henter/opdaterer koden, bygger image'et og kører agenten som en
restart-on-boot container. Tokenet ligger på en navngivet volume, så det
genbruges ved genstart/opgradering (engangskoden bruges kun ved første start).

```bash
# Hent koden
git clone https://github.com/gudlever-lgtm/blueeye-agent.git
cd blueeye-agent

# Installér + start som Docker-container (Linux: --network host måler host-trafik)
BLUEEYE_SERVER_URL=https://server.example \
BLUEEYE_ENROLLMENT_CODE=<engangskode> \
./install.sh
```

Opdatér senere med `git pull` og kør `./install.sh` igen (eller kør scriptet et
vilkårligt sted — uden et checkout kloner det selv repoet). Valgfrie env:
`NETWORK_MODE=bridge`, `CONTAINER`, `IMAGE`, `TOKEN_VOLUME`. Styr containeren med
`docker logs -f blueeye-agent` / `docker restart blueeye-agent`.

Imaget bygges til en **64-bit** platform. `install.sh` detekterer host-arkitekturen
automatisk (`linux/amd64` eller `linux/arm64`); overstyr med `PLATFORM`, fx
`PLATFORM=linux/arm64 ./install.sh`. 32-bit hosts understøttes ikke.

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
| `tokenPath`       | `BLUEEYE_TOKEN_PATH`         | `./.blueeye-agent/token`       | Hvor tokenet gemmes (0600)          |
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
3. Det returnerede token gemmes lokalt i en fil med **restriktive rettigheder
   (0600)**, og `enrollmentCode` fjernes fra config-filen.
4. Afvises koden (ugyldig/brugt/udløbet → `401`/`410`), fejler agenten **hårdt**
   og prøver **ikke** igen automatisk.

## Kørsel

- Åbner en WebSocket til `/ws/agent` med tokenet i `Authorization: Bearer`-headeren.
- Sender periodisk heartbeat, så serveren holder `last_seen` frisk.
- Lytter efter server-kommandoer. En **run-test**-kommando (fx
  `{ type: "command", command: { name: "run-test", intervalMs: 1000 } }`) får
  agenten til at **måle netværkstrafik** og indsende resultatet.
- **Trafik-kilder** — agenten kan måle trafik på to måder, og **serveren vælger
  hvilken pr. agent** (matchet på agent-id via tokenet):
  - `proc` ([`src/trafficMonitor.js`](src/trafficMonitor.js)): læser
    `/proc/net/dev` to gange `intervalMs` fra hinanden, pr. interface rx/tx-bytes
    og rater. Kør containeren med `network_mode: host` for at måle hele værtens
    trafik (ellers måles containerens egne interfaces).
  - `snmp` ([`src/snmpMonitor.js`](src/snmpMonitor.js)): poller en Cisco-enheds
    IF-MIB high-capacity octet-tællere (ifHCInOctets/ifHCOutOctets) over SNMP —
    nyttigt når agenten kører ved siden af enheden, eller på IOS uden `/proc`.
- **Capabilities + config:** ved opstart sender agenten sine muligheder
  (`{ sources: [...] }`) til `POST /agents/me/capabilities` og henter sin
  tildelte kilde fra `GET /agents/me/config`. Den genhenter config ved hver
  (gen)tilslutning, så ændringer i dashboardet slår igennem. Begge kilder giver
  samme resultat-format, så server/dashboard behandler dem ens.
- **Løbende rapportering:** uafhængigt af server-kommandoer måler agenten
  trafik og indsender resultatet på et fast interval
  (`BLUEEYE_REPORT_INTERVAL_MS`, default 60s; `0` slår det fra). Det er sådan
  serveren får kontinuerlige data uden at nogen trykker "Kør test".
- Indsender resultater via `POST /agents/results { results: [...] }` med
  Bearer-token.
- **Reconnect** ved tabt forbindelse med eksponentiel backoff (+ jitter).
- **Hård fejl** hvis tokenet afvises (`401` ved WS-handshake eller på results-POST):
  agenten logger og stopper — den enroller **ikke** automatisk igen.

To adskilte sikkerhedsgrænser: agentens token bruges **kun** mod agent-endpoints
(WS + `/agents/results`). Det er ikke et bruger-JWT.

## Projektstruktur

Se [`codemap.md`](codemap.md) for et aktuelt kort over kildekoden — arkitektur,
moduler, dataflow, trafik-kilder (proc/snmp/netflow/sflow), probes, server-API
og teststruktur.

## Test

```bash
npm test
```

Tests dækker: config-fletning og rydning af engangskode, token-lagring med
`0600`-rettigheder, kommando-genkendelse, backoff, samt **integrationstests mod
en kørende server**: enroll-flow, WS-connect (gyldigt/ugyldigt token),
afsendelse af resultat og reconnect.

> Integrationstestene kører mod en kontrakt-tro stub-server
> ([`test-support/fakeServer.js`](test-support/fakeServer.js)) med præcis de
> samme endpoints som `blueeye-server` (`/agents/enroll`, `/ws/agent`,
> `/agents/results`). Den rigtige server kræver MySQL; stubben gør testene
> selvstændige og hurtige uden at afvige fra kontrakten.
