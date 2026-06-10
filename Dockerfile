# BlueEye agent — runs on customer machines, connects to blueeye-server.
FROM node:22-alpine

WORKDIR /app

# ethtool lets the agent read per-NIC driver/firmware (`ethtool -i`) for the
# fleet firmware-drift inventory. Tiny, optional: the collector degrades to []
# when it's absent. Needs `network_mode: host` to see the host's real NICs.
# curl powers the `curl` content-verification probe (HTTP status/body/headers).
RUN apk add --no-cache ethtool curl

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
