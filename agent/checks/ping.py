"""ICMP reachability / latency / packet-loss check."""
import platform
import re
import subprocess

_LOSS_RE = re.compile(r"(\d+(?:\.\d+)?)%\s*packet loss")
_RTT_RE = re.compile(r"=\s*[\d.]+/([\d.]+)/")


def run(target, params):
    if not target:
        raise ValueError("ping check requires a target host")
    count = int(params.get("count", 4))

    if platform.system().lower() == "windows":
        cmd = ["ping", "-n", str(count), target]
    else:
        cmd = ["ping", "-c", str(count), "-w", "15", target]

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    out = proc.stdout or ""

    loss_match = _LOSS_RE.search(out)
    rtt_match = _RTT_RE.search(out)

    return {
        "target": target,
        "reachable": proc.returncode == 0,
        "packet_loss_pct": float(loss_match.group(1)) if loss_match else None,
        "rtt_avg_ms": float(rtt_match.group(1)) if rtt_match else None,
        "raw": out.strip()[-600:],
    }
