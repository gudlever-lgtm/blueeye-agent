"""Registry of built-in network checks."""
from . import dns, http, ping

CHECKS = {
    "ping": ping.run,
    "dns": dns.run,
    "http": http.run,
}


def run_check(job):
    """Execute the check named by job['type']. Raises on unknown type or failure."""
    fn = CHECKS.get(job.get("type"))
    if fn is None:
        raise ValueError(f"unknown check type: {job.get('type')}")
    return fn(job.get("target") or "", job.get("params") or {})
