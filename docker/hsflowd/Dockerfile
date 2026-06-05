# BlueEye hsflowd sidecar — turns a Linux host into an sFlow v5 exporter that
# samples the host's own traffic and ships it to the BlueEye agent's local
# collector (127.0.0.1:6343 by default). Run it alongside a host-networked agent
# whose monitor source is "sflow", on Linux hosts only.
#
# hsflowd (Host sFlow) is a small C daemon. We install it from the distro repo.
# If your distro/architecture doesn't carry the `hsflowd` package, build it from
# the official releases at https://github.com/sflow/host-sflow instead — the .deb
# installs the same `hsflowd` binary this entrypoint runs.
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends hsflowd ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Exporter only — it exposes no inbound port; it sends UDP to the collector.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
