# BlueEyes agent — runs on customer machines, connects to blueeye-server.
FROM node:22-alpine

WORKDIR /app

# ethtool lets the agent read per-NIC driver/firmware (`ethtool -i`) for the
# fleet firmware-drift inventory. Tiny, optional: the collector degrades to []
# when it's absent. Needs `network_mode: host` to see the host's real NICs.
# curl powers the `curl` content-verification probe (HTTP status/body/headers).
#
# iputils-ping IS NOT OPTIONAL. Alpine's ping is BusyBox's, and BusyBox has no
# don't-fragment option — it answers `ping: unrecognized option: M`. Every
# path-MTU measurement from a container on this image failed with that line,
# which names a flag the operator never typed. Without DF an oversized packet is
# simply fragmented and arrives, so there is no measuring around it: the probe
# needs a ping that can set the bit. /usr/bin/ping (iputils) comes before
# /bin/ping (BusyBox) on PATH, so installing it is all it takes.
RUN apk add --no-cache ethtool curl iputils-ping

# Install production dependencies first (better layer caching).
COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

ENV NODE_ENV=production

# The agent is an outbound client — it exposes no port. Configure it via env
# (BLUEEYE_SERVER_URL, BLUEEYE_ENROLLMENT_CODE, BLUEEYE_TOKEN_PATH, ...).
# Note: to measure host-wide traffic, run with `network_mode: host`; otherwise it
# measures the container's own interfaces.
CMD ["node", "src/index.js"]
