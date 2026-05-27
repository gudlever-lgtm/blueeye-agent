"""DNS probe: resolve A records, record latency + answer count."""
import time

import dns.exception
import dns.resolver


def run(target: str) -> dict:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    started = time.perf_counter()
    try:
        answer = resolver.resolve(target, "A")
    except dns.resolver.NXDOMAIN:
        return {
            "status": "fail",
            "latency_ms": (time.perf_counter() - started) * 1000.0,
            "detail": {"error": "NXDOMAIN"},
        }
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers) as exc:
        return {
            "status": "fail",
            "latency_ms": (time.perf_counter() - started) * 1000.0,
            "detail": {"error": str(exc)},
        }
    except dns.exception.DNSException as exc:
        return {
            "status": "fail",
            "latency_ms": (time.perf_counter() - started) * 1000.0,
            "detail": {"error": str(exc)},
        }
    latency_ms = (time.perf_counter() - started) * 1000.0
    addrs = [r.to_text() for r in answer]
    return {
        "status": "ok",
        "latency_ms": latency_ms,
        "detail": {"answers": addrs, "count": len(addrs)},
    }
