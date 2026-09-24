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

// A VLAN id worth keeping (1..4094), an ifIndex worth keeping (a positive
// 32-bit integer), or null.
function vlanOf(v) {
  const n = Number(v);
  return Number.isInteger(n) && n >= 1 && n <= 4094 ? n : null;
}
function ifOf(v) {
  const n = Number(v);
  return Number.isInteger(n) && n > 0 && n <= 0xffffffff ? n : null;
}

// Folds one flow into the full-5-tuple accumulator keyed by
// (srcAddr, dstAddr, dstPort, proto, vlan). Keeps the endpoints/port/proto so
// the server can rebuild who-talks-to-whom-on-which-port (the service
// dependency graph). Metadata only — still no payload, same 5-tuple we already
// decode.
//
// The VLAN is part of the key: the same pair of addresses on two VLANs is two
// different conversations (overlapping address plans, or a host that is on the
// wrong one). The in/out ifIndex is NOT — one conversation can enter by more
// than one port (ECMP, a LAG member, two exporters), and keying on it would
// split a flow into fragments; the first port seen is kept, which answers
// "where does this traffic enter" without inventing a precision it lacks.
// All three are only present on the record when the exporter reported them,
// so a NetFlow v5 flow costs the payload nothing extra.
function addFlow(map, f, bytes, packets) {
  const proto = (f.protocolName || (f.protocol != null ? String(f.protocol) : '') || '').toLowerCase();
  const srcPort = Number(f.srcPort) || null;
  const dstPort = Number(f.dstPort) || null;
  const vlan = vlanOf(f.vlan);
  const key = `${f.srcAddr}|${f.dstAddr}|${dstPort ?? ''}|${proto}|${vlan ?? ''}`;
  const e = map.get(key);
  if (e) {
    e.bytes += bytes;
    e.packets += packets;
    e.flows += 1;
    if (e.inIf == null && ifOf(f.inIf) != null) e.inIf = ifOf(f.inIf);
    if (e.outIf == null && ifOf(f.outIf) != null) e.outIf = ifOf(f.outIf);
    return;
  }
  const rec = {
    srcIp: f.srcAddr, dstIp: f.dstAddr, proto: proto || null,
    srcPort, dstPort, bytes, packets, flows: 1,
  };
  if (vlan != null) rec.vlan = vlan;
  if (ifOf(f.inIf) != null) rec.inIf = ifOf(f.inIf);
  if (ifOf(f.outIf) != null) rec.outIf = ifOf(f.outIf);
  map.set(key, rec);
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
