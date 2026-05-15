FROM node:20-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    traceroute \
    curl \
    dnsutils \
    iperf3 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/blueeye-agent

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

CMD ["node", "index.js"]
