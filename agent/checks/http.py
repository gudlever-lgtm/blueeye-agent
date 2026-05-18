"""HTTP(S) endpoint check."""
import time

import requests


def run(target, params):
    if not target:
        raise ValueError("http check requires a target URL")
    method = params.get("method", "GET").upper()
    timeout = float(params.get("timeout", 10))
    expect_status = params.get("expect_status")

    start = time.perf_counter()
    resp = requests.request(method, target, timeout=timeout, allow_redirects=True)
    elapsed_ms = (time.perf_counter() - start) * 1000

    result = {
        "target": target,
        "method": method,
        "status_code": resp.status_code,
        "ok": resp.ok,
        "response_ms": round(elapsed_ms, 2),
        "bytes": len(resp.content),
    }
    if expect_status is not None and resp.status_code != int(expect_status):
        raise ValueError(
            f"expected HTTP {expect_status} but got {resp.status_code} from {target}"
        )
    return result
