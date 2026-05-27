"""HTTP probe: GET target, record status code + latency."""
import time

import requests


def run(target: str) -> dict:
    url = target if target.startswith(("http://", "https://")) else f"http://{target}"
    started = time.perf_counter()
    try:
        r = requests.get(url, timeout=10, allow_redirects=True)
    except requests.RequestException as exc:
        return {
            "status": "fail",
            "latency_ms": (time.perf_counter() - started) * 1000.0,
            "detail": {"error": str(exc), "url": url},
        }
    latency_ms = (time.perf_counter() - started) * 1000.0
    status = "ok" if 200 <= r.status_code < 400 else "fail"
    return {
        "status": status,
        "latency_ms": latency_ms,
        "detail": {
            "status_code": r.status_code,
            "url": r.url,
            "size_bytes": len(r.content),
        },
    }
