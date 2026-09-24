# Realistic syslog lines

Read by [`test/syslogRealLines.test.js`](../../syslogRealLines.test.js), which
runs every line through `src/syslog/parse.js` → `classify.js` → `mask.js` and
checks the `# expect:` annotation above it.

- **`real-captured.txt`** — datagrams captured off the wire (2026-09-24) from
  util-linux `logger` 2.39.3 (RFC 3164, RFC 5424 with structured data, RFC 5424
  without a timestamp) and from **rsyslogd 8.2312.0** forwarding one message in
  its three stock templates (`RSYSLOG_TraditionalForwardFormat`,
  `RSYSLOG_ForwardFormat`, `RSYSLOG_SyslogProtocol23Format`). Each command is in
  the file.
- **`cisco-shapes.txt`** — Cisco `%FAC-SEV-MNEMONIC` lines where the mnemonic
  is NOT in the syslog tag position: the two exact lines from the 2026-09-24
  end-to-end run (IOS `logging origin-id hostname`, RFC 5424) and util-linux
  `logger` 2.39.3 datagrams captured the same day (`-t ""`, RFC 5424 with and
  without structured data). Each command is in the file.
- **`vendor-documented.txt`** — Cisco IOS and Juniper Junos text copied exactly
  from vendor-published sources (Cisco DevNet sample log + Cisco CML CCNA lab
  guides, Juniper Mist sample webhooks), cited per line with repository, commit,
  file and line number, and their licences (MIT / BSD-3-Clause). How the PRI
  (Cisco) and header (Junos) were added is stated in the file.

## Found by these lines, fixed in the agent

| Line | Was | Now |
| --- | --- | --- |
| rsyslog `RSYSLOG_ForwardFormat` (`<78>2026-09-24T01:42:47.794495+00:00 vm CRON[15734]: …`) | `pri-only`, tag `2026-09-24T01`, no host, no device time | host, tag, pid and the RFC 3339 device time |
| IOS `service timestamps log datetime year` (`*Apr 19 2018 18:00:06: %LINEPROTO-5-UPDOWN: …`) | `pri-only`, no tag, no device time | tag + the stamp, with its own year |
| `%OSPF-5-ADJCHG: … FULL to DOWN, Neighbor Down: Interface down or detached` | `link.down` (generic "interface … down" rule ran first) | `ospf.adjacency_lost` |
| `%SEC-6-IPACCESSLOGP: list … permitted tcp …` | `acl.denied` | `syslog.raw` (only a *denied* line is a denial) |
| IOS `logging origin-id hostname` (`<187>52: sw-core-1: *Sep 24 08:21:50.123: %LINK-3-UPDOWN: …`) | `syslog.raw`, the HOSTNAME as tag, no device time | `link.down`, host `sw-core-1`, tag `%LINK-3-UPDOWN`, the stamp |
| RFC 5424 from a switch (`<187>1 … sw-core-1 switch - - - %LINK-3-UPDOWN: …`) | `syslog.raw` (the mnemonic is in the MSG, the APP-NAME in the tag) | `link.down` — a mnemonic opening the message is classified as the tag |
| `logger -t ""` (`<187>Sep 24 08:37:33 vm : %LINK-3-UPDOWN: …`) | `syslog.raw`, message `": %LINK…"` | `link.down`, message without the stray colon |
| generic "interface … down" wording, 41+ characters apart | `syslog.raw` | window widened from 40 to 64 characters (still stops at a full stop) |

## Not covered, and why

- **HPE/Aruba, MikroTik, `%CDP-4-DUPLEX_MISMATCH`, `%DHCPD-*`**: no
  vendor-published source with the exact line text was reachable from the
  capture sandbox (the vendor documentation sites are blocked by its egress
  proxy), and lines are only included when their text can be cited.
- **`logger --octet-count` over UDP** (`113 <188>1 2026-…`): RFC 6587 octet
  counting is TCP framing, but some senders use it over UDP too. The parser
  strips a leading `<digits> ` frame when a PRI follows, so these lines are
  kept (unit test in `test/syslogParse.test.js`).
