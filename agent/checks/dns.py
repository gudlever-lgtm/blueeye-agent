"""DNS resolution check."""
import time

import dns.resolver


def run(target, params):
    if not target:
        raise ValueError("dns check requires a target hostname")
    record_type = params.get("record", "A")
    nameserver = params.get("nameserver")

    resolver = dns.resolver.Resolver()
    if nameserver:
        resolver.nameservers = [nameserver]

    start = time.perf_counter()
    answer = resolver.resolve(target, record_type, lifetime=10)
    elapsed_ms = (time.perf_counter() - start) * 1000

    return {
        "target": target,
        "record_type": record_type,
        "nameserver": nameserver or "system",
        "resolved": sorted(r.to_text() for r in answer),
        "resolve_ms": round(elapsed_ms, 2),
    }
