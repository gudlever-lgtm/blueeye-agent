# Real sFlow v5 datagrams from hsflowd

`hsflowd-2.1.26-NNN.bin` are raw UDP payloads, one datagram per file, exactly as
a real **Host sFlow daemon** sent them. `NNN` is the sFlow datagram sequence
number (1–28, consecutive: nothing was skipped). Used by
[`test/sflowRealCapture.test.js`](../../sflowRealCapture.test.js).

## How they were captured (2026-09-24)

- **Exporter:** hsflowd **2.1.26** built from source,
  <https://github.com/sflow/host-sflow> commit `41f10e6a2068ff15856e2bd1f1af2df1a506461b`
  (2026-06-12), with the agent's own build recipe (`make FEATURES=PCAP`, see
  `src/sflow/hsflowd.js`), on Ubuntu 24.04 / Linux 6.18.
- **Config:** `hsflowd-veth.conf` in this directory — rendered by
  `src/sflow/hsflowdConfig.js` `renderHsflowdConf({ collectorPort: 16343,
  samplingRate: 8, pollingSecs: 5, device: 'veth-p8' })`. Sampling 1-in-8 so a
  few seconds of traffic produce enough flow samples; counters every 5 s.
- **Traffic:** only synthetic, local traffic on a veth pair into a network
  namespace, so nothing third-party is in the sampled headers:
  `veth-p8` 198.51.100.1/24 ↔ `veth-p8n` 198.51.100.2/24 (RFC 5737 TEST-NET-2).
  In the namespace a Node HTTP server on tcp/8080 (bodies of `x` bytes) and a
  UDP echo on udp/5353. From the host: 20 HTTP GETs (20–39 kB bodies) with ten
  100–280-byte UDP datagrams each, and `ping -c 60 -i 0.3 198.51.100.2`.
- **Collector:** a plain Node `dgram` socket on 127.0.0.1:16343 writing each
  message to a file. hsflowd picked **192.0.2.2** (the sandbox's eth0, RFC 5737
  TEST-NET-1) as its agent address.

## What is in them

- sFlow **v5**, IPv4 agent address 192.0.2.2, sub-agent id 100000 (hsflowd's).
- **Expanded** flow samples (type 3) and **expanded** counter samples (type 4) —
  hsflowd never sends the compact types 1/2 that the hand-built datagrams in
  `test/sflow.test.js` use.
- Flow samples: sampling rate 8, one raw-packet-header record (type 1,
  Ethernet, ≤128 header bytes) plus the extended records hsflowd adds.
  TCP 198.51.100.1 ↔ 198.51.100.2:8080, UDP ↔ :5353, ICMP echo. Some TCP
  frame lengths exceed the MTU (e.g. 3820): pcap on a host sees TSO/GRO
  super-frames, so a host exporter reports them as one sampled "frame".
- Counter samples: the host sample (host-descr 2000, adaptors 2001, cpu 2003,
  memory 2004, disk 2005, net-io 2006, mib2 ip/icmp/tcp/udp 2007–2010) and the
  veth interface sample (generic interface counters 1 + ifName 1005).
  Datagrams 010 and 025–028 are counters only; the rest carry flows.
- hsflowd's host-descr carries the sandbox's hostname (`vm`) and kernel version
  — nothing else identifying.

## Found while capturing

hsflowd **ignores `sampling = N`** on any interface that reports a link speed:
it uses `ifSpeed / 1 000 000` (min 100) instead (`hsflowconfig.c`
`lookupPacketSamplingRate`, method `speed_default`). The first attempt, with the
agent's config as rendered at the time, sampled the 10 Gbit/s veth 1-in-**10000**
while the config said 8. `sampling.bps_ratio = 0` switches that off; the agent's
renderer (and `docker/hsflowd/entrypoint.sh`) now emits it, and these datagrams
were captured with it (their sampling rate is 8, as configured).

## Re-capturing

```sh
ip netns add p8ns
ip link add veth-p8 type veth peer name veth-p8n
ip link set veth-p8n netns p8ns
ip addr add 198.51.100.1/24 dev veth-p8 && ip link set veth-p8 up
ip netns exec p8ns ip addr add 198.51.100.2/24 dev veth-p8n
ip netns exec p8ns ip link set veth-p8n up
# servers in the namespace (HTTP :8080, UDP echo :5353), a dgram collector on
# 127.0.0.1:16343 that writes each message to a file, then:
hsflowd -dd -f "$PWD/hsflowd-veth.conf" &
# generate HTTP + UDP + ping traffic to 198.51.100.2, wait ~15 s for counters
```
