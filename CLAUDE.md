BlueEye Agent
Hvad dette er
En netværksdiagnostik-agent. Den modtager test-kommandoer fra BlueEye Server via WebSocket og udfører dem lokalt. Resultater sendes tilbage til serveren i JSON.
Projektet er en del af BlueEye-platformen:

BlueEye Server: Node.js + Express + WebSocket + SQLite — orkestrerer tests og gemmer resultater
BlueEye RCA: LLM-baseret root cause analysis — analyserer indkomne data og foreslår årsager
BlueEye Agent: Det her repo — kører som en service på klientmaskiner

Stack

Runtime: Node.js (>=20)
WebSocket: ws library
Sprog: JavaScript (ESM)
Testværktøjer: systemkommandoer via child_process (ping, traceroute, curl, dig, iperf3)

Projektstruktur
agent/
  index.js          # Entry point — WebSocket-forbindelse til server
  runner.js         # Kører individuelle tests via child_process
  tests/
    latency.js      # ICMP ping
    loss.js         # Packet loss (ping-baseret)
    jitter.js       # UDP jitter via iperf3
    http.js         # HTTP check via curl
    traceroute.js   # traceroute / tracert (Windows-kompatibel)
    dns.js          # DNS lookup via dig
    bandwidth.js    # Bandwidth via iperf3
  config.js         # SERVER_URL, AGENT_ID, timeouts
  package.json
Vigtige regler

Brug altid child_process.spawn (ikke exec) — giver streaming output og bedre timeout-kontrol
Alle tests returnerer samme JSON-struktur: { testId, type, target, status, result, error, durationMs }
status er altid "success" eller "error" — aldrig null
Timeout på alle systemkommandoer: 30 sekunder
Test altid for HTTP 404 og 500 inden deployment
Ved Windows: brug ping -n og tracert, ikke -c og traceroute
Push altid til main

Start og test
bashnpm install
node index.js                  # Start agenten (kræver SERVER_URL i env)
npm test                       # Kør unit tests
Environment variables
SERVER_URL=ws://server-ip:4000
AGENT_ID=min-unikke-agent-id   # fx hostname
WebSocket-protokol
Agenten modtager kommandoer fra serveren som JSON:
json{ "action": "run_test", "testId": "abc123", "type": "latency", "target": "8.8.8.8", "options": {} }
Agenten sender resultater tilbage:
json{ "action": "test_result", "testId": "abc123", "type": "latency", "target": "8.8.8.8", "status": "success", "result": { "avgMs": 14.2, "minMs": 12.1, "maxMs": 18.4, "loss": 0 }, "durationMs": 5012 }
Ved fejl:
json{ "action": "test_result", "testId": "abc123", "status": "error", "error": "Command timed out after 30s" }
Test-typer og forventede result-strukturer
latency
json{ "avgMs": 14.2, "minMs": 12.1, "maxMs": 18.4, "stddevMs": 1.1, "packets": 10 }
loss
json{ "sent": 50, "received": 48, "lossPercent": 4.0 }
jitter
json{ "jitterMs": 3.2, "lossPercent": 0.5, "bandwidthMbps": 94.1 }
http
json{ "statusCode": 200, "responseTimeMs": 142, "ttfbMs": 98, "contentLength": 4821 }
traceroute
json{ "hops": [ { "hop": 1, "ip": "192.168.1.1", "latencyMs": 1.2 }, ... ] }
dns
json{ "resolved": ["142.250.74.46"], "queryTimeMs": 8.3, "ttl": 300 }
bandwidth
json{ "sendMbps": 94.1, "receiveMbps": 91.3, "retransmits": 2 }
Kodekonventioner

Ingen klasser — brug plain functions og ESM exports
Fejlhåndtering: altid try/catch i test-runners, send aldrig uncaught exceptions over WebSocket
Log med prefix: [agent], [test], [ws] — brug ikke console.error til forventet fejl, kun console.warn
Ingen eksterne dependencies udover ws og uuid

Hvad du ikke skal gøre

Tilføj ikke features der ikke er bedt om
Lav ikke abstractions til brug én gang
Tilføj ikke error handling for ting der ikke kan ske
Omskriv ikke eksisterende tests medmindre du er bedt om det
