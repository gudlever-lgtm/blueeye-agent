# Rate-limited traceroute + TTL-limited ping, captured

Read by [`test/pathMtuRateLimited.test.js`](../../pathMtuRateLimited.test.js).

Captured 2026-09-24 on the end-to-end rig (Ubuntu 24.04 under gVisor): agent
host `198.51.100.1` → router namespace `198.51.100.2`/`203.0.113.1` → target
namespace `203.0.113.2`, the target at Linux defaults
(`net.ipv4.icmp_ratelimit = 1000`, `icmp_ratemask = 6168`). Tools:
**Modern traceroute for Linux 2.1.5** and **iputils ping**. Byte-exact stdout.

| File | Command |
| --- | --- |
| `linux-ratelimited-q1.txt` | `traceroute -n -m 32 -q 1 -w 2 -- 203.0.113.2` — the target, two hops away, shows up at hop **18** |
| `linux-ratelimited-q2.txt` | same with `-q 2` — hop **10** |
| `linux-ratelimited-q3.txt` | same with `-q 3` — hop **7** |
| `linux-ping-ttl1-ttl-exceeded.txt` | `ping -c1 -t 1 -s 548 -W 1 203.0.113.2` — the router |
| `linux-ping-ttl2-reply.txt` | `ping -c1 -t 2 -s 548 -W 1 203.0.113.2` — the target answers at TTL 2 |

Traceroute sends up to 16 probes at once (`-N 16`), so the target receives the
probes for TTL 2..17 together and its ICMP port-unreachable rate limit answers
only a later one. More queries per hop shorten the error but do not remove it;
the TTL-limited ping, which the path_mtu probe already sends per hop, does.
