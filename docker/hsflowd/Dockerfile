# BlueEye hsflowd sidecar — turns a Linux host into an sFlow v5 exporter that
# samples the host's own traffic and ships it to the BlueEye agent's local
# collector (127.0.0.1:6343 by default). Run it alongside a host-networked agent
# whose monitor source is "sflow", on Linux hosts only.
#
# hsflowd (Host sFlow) is NOT in the Debian/Ubuntu archives — it ships from
# sflow.org. So we build it from source with the PCAP module (packet sampling,
# i.e. the src/dst data; without it hsflowd would export interface counters only).
FROM debian:bookworm-slim

# Build deps + libpcap are kept in the image (hsflowd links libpcap at runtime).
# Pin a release with HSFLOWD_REF at build time for reproducibility.
ARG HSFLOWD_REF=
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates build-essential libpcap-dev \
 && git clone --depth 1 ${HSFLOWD_REF:+--branch ${HSFLOWD_REF}} https://github.com/sflow/host-sflow /usr/local/src/host-sflow \
 && make -C /usr/local/src/host-sflow FEATURES="HOST PCAP" \
 && make -C /usr/local/src/host-sflow install \
 && rm -rf /usr/local/src/host-sflow /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Exporter only — it exposes no inbound port; it sends UDP to the collector.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
