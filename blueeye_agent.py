"""BlueEye Agent — polls server for test config, runs probes, submits results."""
import configparser
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

from tests.dns_test import run as run_dns
from tests.http_test import run as run_http
from tests.ping_test import run as run_ping

DEFAULT_CONFIG_PATH = "/etc/blueeye/agent.conf"

log = logging.getLogger("blueeye.agent")

RUNNERS = {
    "http": run_http,
    "ping": run_ping,
    "dns": run_dns,
}


def load_config(path: str) -> dict:
    parser = configparser.ConfigParser()
    if Path(path).exists():
        parser.read(path)
    server_url = os.environ.get("BLUEEYE_SERVER_URL") or parser.get("agent", "server_url", fallback="")
    token = os.environ.get("BLUEEYE_AGENT_TOKEN") or parser.get("agent", "token", fallback="")
    interval_raw = (
        os.environ.get("BLUEEYE_POLL_INTERVAL")
        or parser.get("agent", "poll_interval", fallback="60")
    )
    if not server_url or not token:
        raise SystemExit(
            "BlueEye agent: server_url and token must be configured "
            "(set them in /etc/blueeye/agent.conf or via the BLUEEYE_SERVER_URL "
            "and BLUEEYE_AGENT_TOKEN env vars)"
        )
    return {
        "server_url": server_url.rstrip("/"),
        "token": token,
        "poll_interval": max(5, int(interval_raw)),
    }


class AgentClient:
    def __init__(self, server_url: str, token: str):
        self.base = server_url
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"Bearer {token}"
        self.session.headers["User-Agent"] = "blueeye-agent/1.0"

    def checkin(self) -> dict:
        r = self.session.post(f"{self.base}/api/agent/checkin", timeout=30)
        r.raise_for_status()
        return r.json()

    def submit(self, results: list[dict]) -> None:
        r = self.session.post(
            f"{self.base}/api/agent/results",
            json={"results": results},
            timeout=30,
        )
        r.raise_for_status()


def execute_test(tc: dict) -> dict:
    runner = RUNNERS.get(tc["test_type"])
    if runner is None:
        return {
            "status": "fail",
            "latency_ms": None,
            "detail": {"error": f"unknown test type {tc['test_type']}"},
        }
    try:
        out = runner(tc["target"])
    except Exception as exc:
        log.exception("test %s on %s raised", tc["test_type"], tc["target"])
        return {"status": "fail", "latency_ms": None, "detail": {"error": str(exc)}}
    out.setdefault("status", "ok")
    out.setdefault("latency_ms", None)
    out.setdefault("detail", {})
    return out


def run_cycle(client: AgentClient, due: dict[int, float]) -> int:
    cfg = client.checkin()
    now = time.monotonic()
    results = []
    active_ids = set()
    for tc in cfg["tests"]:
        tc_id = tc["id"]
        active_ids.add(tc_id)
        interval = max(10, int(tc.get("interval_seconds", 60)))
        next_run = due.setdefault(tc_id, now)
        if now < next_run:
            continue
        outcome = execute_test(tc)
        results.append({
            "test_config_id": tc_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": outcome["status"],
            "latency_ms": outcome["latency_ms"],
            "detail": outcome["detail"],
        })
        due[tc_id] = now + interval
    # Forget timers for tests that were disabled or deleted server-side.
    for stale in [k for k in due if k not in active_ids]:
        due.pop(stale, None)
    if results:
        client.submit(results)
    return len(results)


def main(argv: Optional[list[str]] = None) -> int:
    logging.basicConfig(
        level=os.environ.get("BLUEEYE_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    config_path = os.environ.get("BLUEEYE_CONFIG", DEFAULT_CONFIG_PATH)
    cfg = load_config(config_path)
    client = AgentClient(cfg["server_url"], cfg["token"])
    log.info(
        "BlueEye agent starting against %s (poll every %ss)",
        cfg["server_url"], cfg["poll_interval"],
    )

    stop = {"now": False}

    def _stop(*_):
        log.info("Shutdown requested")
        stop["now"] = True

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    due: dict[int, float] = {}
    while not stop["now"]:
        try:
            count = run_cycle(client, due)
            if count:
                log.info("Reported %d result(s)", count)
        except requests.RequestException as exc:
            log.error("Cycle failed (server unreachable): %s", exc)
        except Exception:
            log.exception("Unexpected error in cycle")

        for _ in range(cfg["poll_interval"]):
            if stop["now"]:
                break
            time.sleep(1)

    log.info("Agent stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
