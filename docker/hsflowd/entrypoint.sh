#!/usr/bin/env bash
set -euo pipefail

# Renders /etc/hsflowd.conf from environment, then runs hsflowd in the FOREGROUND
# so it is the container's PID 1 (and restarts with the container). The rendered
# format mirrors the agent's src/sflow/hsflowdConfig.js — keep the two in sync.
#
# pcap { dev } is what makes hsflowd sample PACKETS (the src/dst data the
# Destinations map needs). SFLOW_DEVICE must be the host's real interface
# (eth0 / ens.. / wlan0); with host networking the container sees the host's.
: "${COLLECTOR_IP:=127.0.0.1}"
: "${COLLECTOR_PORT:=6343}"
: "${SAMPLING_RATE:=256}"
: "${POLLING_SECS:=20}"
: "${SFLOW_DEVICE:=eth0}"

cat > /etc/hsflowd.conf <<EOF
# Managed by the BlueEye hsflowd sidecar — generated at container start.
sflow {
  collector { ip = ${COLLECTOR_IP}  udpport = ${COLLECTOR_PORT} }
  sampling = ${SAMPLING_RATE}
  polling = ${POLLING_SECS}
  pcap { dev = ${SFLOW_DEVICE} }
}
EOF

echo "hsflowd sidecar: sampling ${SFLOW_DEVICE} 1-in-${SAMPLING_RATE}, exporting to ${COLLECTOR_IP}:${COLLECTOR_PORT}"

# -dd keeps hsflowd in the FOREGROUND (no fork) and logs to stderr — required so
# it can be the container's PID 1.
exec hsflowd -dd
