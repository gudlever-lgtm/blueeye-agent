"""ICMP ping probe (icmplib preferred, falls back to /bin/ping)."""
import re
import shutil
import subprocess

try:
    from icmplib import ping as _icmplib_ping  # type: ignore
    _HAVE_ICMPLIB = True
except ImportError:
    _HAVE_ICMPLIB = False


def run(target: str) -> dict:
    if _HAVE_ICMPLIB:
        return _ping_icmplib(target)
    return _ping_subprocess(target)


def _ping_icmplib(target: str) -> dict:
    result = _icmplib_ping(target, count=4, interval=0.2, timeout=2, privileged=False)
    if result.is_alive and result.packet_loss == 0:
        status = "ok"
    elif result.is_alive:
        status = "warn"
    else:
        status = "fail"
    return {
        "status": status,
        "latency_ms": result.avg_rtt if result.is_alive else None,
        "detail": {
            "host": result.address,
            "packets_sent": result.packets_sent,
            "packets_received": result.packets_received,
            "packet_loss": result.packet_loss,
            "min_rtt": result.min_rtt,
            "max_rtt": result.max_rtt,
        },
    }


def _ping_subprocess(target: str) -> dict:
    if shutil.which("ping") is None:
        return {
            "status": "fail",
            "latency_ms": None,
            "detail": {"error": "ping binary not available"},
        }
    try:
        proc = subprocess.run(
            ["ping", "-c", "4", "-W", "2", target],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"status": "fail", "latency_ms": None, "detail": {"error": "ping timed out"}}

    avg_rtt = None
    m = re.search(r"=\s*[\d.]+/([\d.]+)/", proc.stdout)
    if m:
        avg_rtt = float(m.group(1))
    loss = 100.0
    m = re.search(r"(\d+(?:\.\d+)?)%\s*packet loss", proc.stdout)
    if m:
        loss = float(m.group(1))
    if proc.returncode == 0 and loss == 0:
        status = "ok"
    elif proc.returncode == 0:
        status = "warn"
    else:
        status = "fail"
    return {
        "status": status,
        "latency_ms": avg_rtt,
        "detail": {"packet_loss": loss, "stdout": proc.stdout.strip()[-512:]},
    }
