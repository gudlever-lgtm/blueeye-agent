# BlueEye Agent

En netværksdiagnostik-agent der modtager test-kommandoer fra BlueEye Server via
WebSocket, kører dem lokalt og sender resultaterne tilbage i JSON.

## Installation

```bash
npm install
```

Opret en env-fil ud fra `.env.example`:

```bash
cp .env.example .env
# rediger .env og sæt mindst SERVER_URL
```

Start agenten direkte:

```bash
SERVER_URL=ws://server-ip:4000 node index.js
```

### Som systemd-service (Linux)

```bash
sudo useradd --system blueeye
sudo mkdir -p /opt/blueeye-agent /etc/blueeye-agent
sudo cp -r . /opt/blueeye-agent
# læg miljøvariable i /etc/blueeye-agent/env (se .env.example)
sudo cp install/blueeye-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now blueeye-agent
```

### Docker (inkl. Raspberry Pi 4/5)

Image'et er baseret på `node:20-slim` og virker både på almindelige x86-64-værter
og på Raspberry Pi 4/5 med 64-bit OS (arm64).

Opret først en `.env` (se `.env.example`). Sæt **altid** `AGENT_ID` eksplicit —
ellers bliver det containerens tilfældige hostname, som ændrer sig ved hver
genstart.

Med docker compose:

```bash
docker compose up -d --build
```

Eller rå `docker run`:

```bash
docker build -t blueeye-agent .
docker run -d --restart unless-stopped \
  --cap-add=NET_RAW \
  -e SERVER_URL=ws://server-ip:4000 \
  -e AGENT_ID=min-unikke-agent-id \
  blueeye-agent
```

`--cap-add=NET_RAW` (i compose: `cap_add: [NET_RAW]`) er nødvendig for at ICMP
(`ping`) og `traceroute` kan sende rå pakker.

For mere præcise latency-målinger kan `network_mode: host` aktiveres i
`docker-compose.yml` — så deler agenten vært-netværket direkte i stedet for
Dockers bridge-netværk.

## Test-typer

| Type         | Værktøj            | Beskrivelse                    |
|--------------|--------------------|--------------------------------|
| `latency`    | ping               | ICMP latency (min/avg/max)     |
| `loss`       | ping               | Packet loss                    |
| `jitter`     | iperf3             | UDP jitter + tab               |
| `http`       | curl               | HTTP status og svartider       |
| `traceroute` | traceroute/tracert | Hop-for-hop rute               |
| `dns`        | dig/nslookup       | DNS-opslag og query-tid        |
| `bandwidth`  | iperf3             | TCP send/receive bandwidth     |

## Miljøvariable

| Variabel                | Påkrævet | Default          | Beskrivelse                  |
|-------------------------|----------|------------------|------------------------------|
| `SERVER_URL`            | ja       | —                | WebSocket-adresse til server |
| `AGENT_ID`              | nej      | `os.hostname()`  | Unikt agent-id               |
| `RECONNECT_INTERVAL_MS` | nej      | `5000`           | Reconnect-interval           |
| `TEST_TIMEOUT_MS`       | nej      | `30000`          | Timeout for systemkommandoer |

## Udvikling

```bash
npm test        # kører node --test
```
