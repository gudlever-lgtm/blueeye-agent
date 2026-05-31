# BlueEye agent — runs on customer machines, connects to blueeye-server.
FROM node:22-alpine

WORKDIR /app

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
