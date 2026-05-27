# BlueEye Agent

The probe that runs on a customer site, polls the BlueEye server for its
assigned tests (HTTP, ICMP ping, DNS), executes them, and submits batched
results.

## How it works

Every poll cycle (default 60s) the agent:

1. `POST /api/agent/checkin` with its bearer token — server returns the agent's
   current `test_configs`.
2. For each test whose interval has elapsed, runs the matching probe.
3. Batches the results and `POST /api/agent/results`.

If the server is unreachable the agent logs and keeps trying — it never exits
on transient failures.

## Probes

| Type | Library                                          | Fails when                                |
| ---- | ------------------------------------------------ | ----------------------------------------- |
| http | `requests`                                       | non-2xx/3xx response or connection error  |
| ping | `icmplib` (preferred), falls back to `/bin/ping` | host unreachable or 100% loss             |
| dns  | `dnspython`                                      | NXDOMAIN, no answer, or DNS exception     |

Each runner returns `{status, latency_ms, detail}`. `status` is one of
`ok`, `warn`, `fail`.

## Configuration

The agent reads `/etc/blueeye/agent.conf` by default. Override the path with
`BLUEEYE_CONFIG=/path/to/agent.conf`.

```ini
[agent]
server_url = https://blueeye.example.com
token      = <paste from UI>
poll_interval = 60
```

These environment variables override the file:

| Variable                | Default                   |
| ----------------------- | ------------------------- |
| `BLUEEYE_SERVER_URL`    | (required)                |
| `BLUEEYE_AGENT_TOKEN`   | (required)                |
| `BLUEEYE_POLL_INTERVAL` | `60`                      |
| `BLUEEYE_LOG_LEVEL`     | `INFO`                    |
| `BLUEEYE_CONFIG`        | `/etc/blueeye/agent.conf` |

## Run locally

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
export BLUEEYE_SERVER_URL=http://localhost:8000
export BLUEEYE_AGENT_TOKEN=<from server UI>
python blueeye_agent.py
```

## Run in Docker

```bash
docker build -t blueeye-agent .
docker run --rm \
  -e BLUEEYE_SERVER_URL=http://host.docker.internal:8000 \
  -e BLUEEYE_AGENT_TOKEN=<from server UI> \
  blueeye-agent
```

The server repo's `docker-compose.yml` also ships a sample agent service under
the `agent` profile — set `BLUEEYE_AGENT_TOKEN` and run
`docker compose --profile agent up agent`.

## Run as a systemd service

```bash
sudo useradd --system --home /opt/blueeye --shell /usr/sbin/nologin blueeye
sudo mkdir -p /opt/blueeye /etc/blueeye /var/log/blueeye
sudo cp -r blueeye_agent.py tests /opt/blueeye/
sudo chown -R blueeye:blueeye /opt/blueeye /var/log/blueeye
sudo cp agent.conf.example /etc/blueeye/agent.conf      # then edit it
sudo cp install/blueeye-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now blueeye-agent
journalctl -u blueeye-agent -f
```
