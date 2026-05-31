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

## Konfiguration (fil + env)

Konfiguration læses fra en JSON-fil og kan overstyres af miljøvariabler
(rækkefølge: indbyggede defaults → config-fil → env). Se
[`config.example.json`](config.example.json) og [`.env.example`](.env.example).

| Felt (fil)        | Env-variabel                 | Standard                       | Beskrivelse                         |
| ----------------- | ---------------------------- | ------------------------------ | ----------------------------------- |
| (fil-sti)         | `BLUEEYE_AGENT_CONFIG`       | `./blueeye-agent.config.json`  | Sti til JSON-config                 |
| `serverUrl`       | `BLUEEYE_SERVER_URL`         | `http://localhost:3000`        | blueeye-server URL                  |
| `enrollmentCode`  | `BLUEEYE_ENROLLMENT_CODE`    | (ingen)                        | Engangskode — kun ved første start  |
| `tokenPath`       | `BLUEEYE_TOKEN_PATH`         | `./.blueeye-agent/token`       | Hvor tokenet gemmes (0600)          |
| `heartbeatMs`     | `BLUEEYE_HEARTBEAT_MS`       | `15000`                        | Interval for heartbeat-besked       |
| `reconnectBaseMs` | `BLUEEYE_RECONNECT_BASE_MS`  | `1000`                         | Backoff-basis ved reconnect         |
| `reconnectMaxMs`  | `BLUEEYE_RECONNECT_MAX_MS`   | `30000`                        | Backoff-loft                        |

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
- **Trafik-måling** ([`src/trafficMonitor.js`](src/trafficMonitor.js)): læser
  `/proc/net/dev` to gange `intervalMs` fra hinanden og rapporterer pr.
  interface rx/tx-bytes, pakker og rater. Kør containeren med
  `network_mode: host` for at måle hele værtens trafik (ellers måles containerens
  egne interfaces).
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

```
blueeye-agent/
├── config.example.json        # Eksempel-config
├── src/
│   ├── index.js               # CLI-entrypoint (enroll-or-load -> kør)
│   ├── config.js              # Indlæs/flet/ryd config (fil + env)
│   ├── logger.js              # Simpel niveau-logger
│   ├── system.js              # hostname/platform/arch
│   ├── tokenStore.js          # Læs/skriv token-fil (0600)
│   ├── enroll.js              # POST /agents/enroll
│   ├── bootstrap.js           # ensureToken: skip enroll hvis token findes
│   ├── apiClient.js           # REST (postResults) med Bearer
│   ├── agentClient.js         # WebSocket: connect, heartbeat, reconnect, hård fejl
│   ├── command.js             # Genkend "run test"-kommandoer
│   ├── trafficMonitor.js      # Måler netværkstrafik via /proc/net/dev
│   ├── testRunner.js          # Kør en test (trafik-måling), producér resultat
│   └── runtime.js             # Binder WS + REST + kommando-håndtering sammen
├── test/                      # Tests (node --test)
└── test-support/              # fakeServer (kontrakt-tro blueeye-server-stub)
```

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
