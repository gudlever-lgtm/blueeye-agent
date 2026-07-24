'use strict';

// Aggregates NetFlow records into per-port and per-protocol summaries, plus
// top talkers. This is the shape the agent reports and the server makes
// searchable ("how much traffic on port X / protocol Y").
//
// The "service port" of a flow is the lower of src/dst port — for well-known
// services (< 1024 or any registered port) the server side is the smaller one,
// which is the useful key for "traffic on port 443/53/...".
function servicePort(flow) {
  const a = flow.srcPort || 0;
  const b = flow.dstPort || 0;
  if (!a) return b;
  if (!b) return a;
  return Math.min(a, b);
}

function add(map, key, bytes, packets) {
  const e = map.get(key) || { bytes: 0, packets: 0, flows: 0 };
  e.bytes += bytes;
  e.packets += packets;
  e.flows += 1;
  map.set(key, e);
}

// Folds one flow into the full-5-tuple accumulator keyed by
// (srcAddr, dstAddr, dstPort, proto). Keeps the endpoints/port/proto so the
// server can rebuild who-talks-to-whom-on-which-port (the service dependency
// graph). Metadata only — still no payload, same 5-tuple we already decode.
function addFlow(map, f, bytes, packets) {
  const proto = (f.protocolName || (f.protocol != null ? String(f.protocol) : '') || '').toLowerCase();
  const srcPort = Number(f.srcPort) || null;
  const dstPort = Number(f.dstPort) || null;
  const key = `${f.srcAddr}|${f.dstAddr}|${dstPort ?? ''}|${proto}`;
  const e = map.get(key);
  if (e) {
    e.bytes += bytes;
    e.packets += packets;
    e.flows += 1;
    return;
  }
  map.set(key, {
    srcIp: f.srcAddr, dstIp: f.dstAddr, proto: proto || null,
    srcPort, dstPort, bytes, packets, flows: 1,
  });
}

// Aggregates an array of flow records (as produced by parseV5) into:
//   { totals, byPort: [...], byProtocol: [...], topTalkers: [...], flows: [...] }
// `topN` caps the summary lists; `flowTopN` caps the per-5-tuple `flows` list
// (kept larger — it is the input to the server's service dependency graph).
// `flows` is additive: older servers ignore it and keep using `topTalkers`.
function aggregateFlows(flows, { topN = 50, flowTopN = 200 } = {}) {
  const byPort = new Map();
  const byProto = new Map();
  const byTalker = new Map();
  const byFlow = new Map();
  const totals = { bytes: 0, packets: 0, flows: 0 };

  for (const f of flows) {
    const bytes = Number(f.bytes) || 0;
    const packets = Number(f.packets) || 0;
    totals.bytes += bytes;
    totals.packets += packets;
    totals.flows += 1;

    add(byPort, servicePort(f), bytes, packets);
    add(byProto, f.protocolName || String(f.protocol), bytes, packets);
    add(byTalker, `${f.srcAddr}->${f.dstAddr}`, bytes, packets);
    if (f.srcAddr && f.dstAddr) addFlow(byFlow, f, bytes, packets);
  }

  const toSorted = (map, mapKey) =>
    Array.from(map.entries())
      .map(([key, v]) => ({ [mapKey]: key, ...v }))
      .sort((a, b) => b.bytes - a.bytes)
      .slice(0, topN);

  return {
    totals,
    byPort: toSorted(byPort, 'port'),
    byProtocol: toSorted(byProto, 'protocol'),
    topTalkers: toSorted(byTalker, 'pair'),
    flows: Array.from(byFlow.values())
      .sort((a, b) => b.bytes - a.bytes)
      .slice(0, flowTopN),
  };
}

module.exports = { aggregateFlows, servicePort };
