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

// Aggregates an array of flow records (as produced by parseV5) into:
//   { totals, byPort: [...], byProtocol: [...], topTalkers: [...] }
// `topN` caps each list.
function aggregateFlows(flows, { topN = 50 } = {}) {
  const byPort = new Map();
  const byProto = new Map();
  const byTalker = new Map();
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
  };
}

module.exports = { aggregateFlows, servicePort };
