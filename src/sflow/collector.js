'use strict';

const dgram = require('dgram');
const { parseSflow, ETHERNET_FIELDS } = require('./parse');
const { aggregateFlows } = require('../netflow/aggregate');
const { fitToBudget, bytesOf } = require('../resultBudget');

const silentLogger = { info() {}, warn() {}, error() {}, debug() {} };

// sFlow COUNTER samples, forwarded to the server as `sflowCounters` in the
// traffic snapshot — the only per-port error/duplex source on a switch nobody
// polls over SNMP.
//
// WIRE FORMAT (PROTOCOL.md): one object per (exporter, ifIndex), the counters
// as two arrays in sFlow's own record order rather than as named keys. A result
// is capped at 64 KB on the server and the flow summary already uses about half
// of that on a busy exporter; named keys cost ~500 bytes an interface, the
// arrays ~200.
//   { agent, ifIndex, at, uptimeMs, ifType, speed, direction, status,
//     if: [...IF_COUNTER_FIELDS], eth: [...ETHERNET_FIELDS] | absent }
// A counter the exporter marks unavailable (all-ones) is null, never 0.
const IF_COUNTER_FIELDS = [
  'ifInOctets', 'ifInUcastPkts', 'ifInMulticastPkts', 'ifInBroadcastPkts', 'ifInDiscards',
  'ifInErrors', 'ifInUnknownProtos', 'ifOutOctets', 'ifOutUcastPkts', 'ifOutMulticastPkts',
  'ifOutBroadcastPkts', 'ifOutDiscards', 'ifOutErrors',
];
// At most this many entries, and this many bytes, per snapshot — and never
// more than keeps the WHOLE snapshot under RESULT_BUDGET_BYTES, which leaves
// room below the server's 64 KB per result for the system metrics and the
// result wrapper. A busy flow summary shrinks the counter share, never the
// other way round: a result over the limit is refused whole.
const COUNTERS_MAX = 1024;
const COUNTERS_BUDGET_BYTES = 24 * 1024;
const RESULT_BUDGET_BYTES = 56 * 1024;
// The share the counters get EVEN WHEN the flow summary alone fills the
// budget. Without it a busy exporter starves them for good: 200 IPv6 flows are
// ~57 KB, over RESULT_BUDGET_BYTES on their own, so the counters' "room" was
// negative every interval and no interface was ever sent — the per-port error
// series simply stopped. With it, the smallest flows make way (the snapshot
// says how many, under `truncated`), and 8 KB is ~40 interfaces an interval,
// which the rotation turns into every port of a 48-port switch every two.
const COUNTERS_FLOOR_BYTES = 8 * 1024;
// Distinct exporters named per snapshot (`sflowExporters`).
const EXPORTERS_MAX = 256;
// Interfaces waiting to be sent. Past this a NEW interface is not tracked.
const COUNTERS_PENDING_MAX = 4096;
// A pending reading older than this is dropped: the server's rate needs two
// readings at most ten minutes apart, so an older one only ever yields a gap.
const COUNTERS_STALE_MS = 10 * 60 * 1000;

// Listens for sFlow v5 datagrams on a UDP port (default 6343) and accumulates
// the rate-scaled flow records decoded from sampled packet headers. drain()
// returns an aggregated snapshot (same shape as the NetFlow collector) and
// clears the buffer. The socket factory is injectable for tests.
function createSflowCollector({
  port = 6343,
  bindAddress = '0.0.0.0',
  maxFlows = 100000,
  logger = silentLogger,
  createSocket = () => dgram.createSocket('udp4'),
  now = () => Date.now(),
} = {}) {
  let socket = null;
  let buffer = [];
  let received = 0;
  let dropped = 0;
  let decoded = 0; // cumulative flow records decoded (survives drain)
  let counterSamples = 0; // cumulative counter samples seen (carry no flow data)
  let lastAt = null; // ms epoch of the last datagram seen (any datagram)
  let bound = false; // the UDP socket actually bound (vs failed/closed)
  // Latest counter reading per `${exporter}|${ifIndex}`, and when each key
  // was last sent. Sending the longest-unsent first means a snapshot that
  // cannot carry every interface ROTATES through them instead of starving the
  // same ones every time.
  const counterPending = new Map();
  const counterLastSent = new Map();
  let counterOverflow = 0; // readings for a new interface refused (pending full)
  // The exporters (the sFlow agent address in the datagram header) heard from
  // since the last drain, in ANY sample. Counter readings carry the address
  // with them, but flows are aggregated without it — so an exporter that only
  // sends flow samples (counter polling off, a common default) was never
  // named anywhere, and the server could not tell it was reporting at all.
  let exporters = new Set();

  function handlePacket(msg) {
    lastAt = now();
    let parsed;
    try {
      parsed = parseSflow(msg);
    } catch (err) {
      dropped += 1;
      logger.debug(`sFlow: dropped a datagram (${err.message})`);
      return;
    }
    decoded += parsed.flows.length;
    counterSamples += parsed.counterSamples || 0;
    const agent = parsed.header && parsed.header.agent;
    if (agent && parsed.header.numSamples > 0 && exporters.size < EXPORTERS_MAX) exporters.add(agent);
    for (const c of parsed.counters || []) rememberCounters(c, lastAt);
    for (const flow of parsed.flows) {
      if (buffer.length >= maxFlows) break;
      buffer.push(flow);
    }
    received += 1;
  }

  function rememberCounters(c, at) {
    if (!c || !c.agent || !Number.isInteger(c.ifIndex)) return;
    const key = `${c.agent}|${c.ifIndex}`;
    let e = counterPending.get(key);
    if (!e) {
      if (counterPending.size >= COUNTERS_PENDING_MAX) { counterOverflow += 1; return; }
      e = { agent: c.agent, ifIndex: c.ifIndex };
      counterPending.set(key, e);
    }
    e.at = at;
    if (Number.isFinite(c.uptimeMs)) e.uptimeMs = c.uptimeMs;
    // A generic and an Ethernet record normally ride in the same sample; when
    // an exporter splits them, each keeps its own latest reading.
    if (c.generic) {
      const g = c.generic;
      e.ifType = g.ifType;
      e.speed = g.ifSpeed;
      e.direction = g.ifDirection;
      e.status = g.ifStatus;
      e.if = IF_COUNTER_FIELDS.map((f) => (g[f] == null ? null : g[f]));
    }
    if (c.ethernet) e.eth = ETHERNET_FIELDS.map((f) => (c.ethernet[f] == null ? null : c.ethernet[f]));
  }

  // The counter readings for one snapshot: longest-unsent first, bounded by
  // count and by bytes. What does not fit stays pending (and is replaced by a
  // newer reading if one arrives), so nothing is lost for longer than a few
  // intervals, and nothing is sent twice.
  // What the fresh pending readings would cost, up to the floor — so the floor
  // takes no more from the flows than the counters will actually use.
  function pendingBytes(nowMs) {
    let bytes = 2;
    for (const e of counterPending.values()) {
      if (nowMs - e.at > COUNTERS_STALE_MS) continue;
      bytes += bytesOf(e) + 1;
      if (bytes >= COUNTERS_FLOOR_BYTES) break;
    }
    return bytes;
  }

  function drainCounters(nowMs, budget) {
    for (const [key, e] of counterPending) {
      if (nowMs - e.at > COUNTERS_STALE_MS) counterPending.delete(key);
    }
    for (const [key, t] of counterLastSent) {
      if (!counterPending.has(key) && nowMs - t > COUNTERS_STALE_MS * 6) counterLastSent.delete(key);
    }
    const order = [...counterPending.keys()].sort((a, b) => (counterLastSent.get(a) ?? -1) - (counterLastSent.get(b) ?? -1)
      || (a < b ? -1 : a > b ? 1 : 0));
    const out = [];
    let bytes = 2;
    for (const key of order) {
      if (out.length >= COUNTERS_MAX) break;
      const e = counterPending.get(key);
      const size = Buffer.byteLength(JSON.stringify(e)) + 1;
      if (bytes + size > budget) break;
      bytes += size;
      out.push(e);
      counterPending.delete(key);
      counterLastSent.set(key, nowMs);
    }
    return out;
  }

  // Counter readings a snapshot carried but the RESULT could not (the runtime's
  // size guard trimmed them), handed back so they go out next interval. A
  // newer reading for the same interface wins over the returned one, and a
  // returned one goes to the front of the rotation — it was never sent.
  function requeueCounters(entries) {
    let requeued = 0;
    for (const e of Array.isArray(entries) ? entries : []) {
      if (!e || !e.agent || !Number.isInteger(e.ifIndex)) continue;
      const key = `${e.agent}|${e.ifIndex}`;
      counterLastSent.delete(key);
      if (counterPending.has(key)) continue;
      if (counterPending.size >= COUNTERS_PENDING_MAX) { counterOverflow += 1; continue; }
      counterPending.set(key, e);
      requeued += 1;
    }
    return requeued;
  }

  function start() {
    return new Promise((resolve, reject) => {
      socket = createSocket();
      socket.on('message', handlePacket);
      socket.on('error', (err) => logger.error(`sFlow socket error: ${err.message}`));
      socket.once('error', reject);
      try {
        socket.bind(port, bindAddress, () => {
          bound = true;
          logger.info(`sFlow collector listening on ${bindAddress}:${port}`);
          resolve();
        });
      } catch (err) {
        reject(err);
      }
    });
  }

  function drain(opts) {
    const flows = buffer;
    buffer = [];
    const agg = aggregateFlows(flows, opts);
    let snapshot = { source: 'sflow', datagrams: received, droppedDatagrams: dropped, sampled: true, ...agg };
    // Additive, like sflowCounters: an older server ignores the key, and an
    // interval with no datagrams does not carry it.
    if (exporters.size) snapshot.sflowExporters = [...exporters];
    exporters = new Set();
    // Room for the counters' floor, when there are counters to send, taken
    // from the tail of the flow list (the smallest flows) and then the top
    // talkers — never from the totals, which were summed before any cut.
    const t = now();
    const reserve = counterPending.size ? Math.min(COUNTERS_FLOOR_BYTES, pendingBytes(t)) : 0;
    const fitted = fitToBudget(snapshot, {
      maxBytes: RESULT_BUDGET_BYTES - reserve - 64,
      order: [['flows'], ['topTalkers']],
    });
    snapshot = fitted.value;
    // Additive: an older server ignores the key, and a snapshot with no
    // counter samples does not carry it at all.
    const room = RESULT_BUDGET_BYTES - bytesOf(snapshot) - 64;
    const sflowCounters = drainCounters(t, Math.min(COUNTERS_BUDGET_BYTES, room));
    if (sflowCounters.length) snapshot.sflowCounters = sflowCounters;
    if (counterPending.size) snapshot.sflowCountersPending = counterPending.size;
    return snapshot;
  }

  function stop() {
    if (socket) {
      try { socket.close(); } catch { /* ignore */ }
      socket = null;
    }
    bound = false;
  }

  // Non-destructive health snapshot (does NOT clear the buffer) for the
  // dashboard "Diagnose" action: is the socket bound, how many datagrams have
  // arrived, how many flow records we decoded, and when we last heard anything.
  function stats() {
    return {
      listening: bound,
      datagrams: received,
      dropped,
      decodedFlows: decoded,
      counterSamples,
      counterInterfaces: counterPending.size,
      counterOverflow,
      bufferedFlows: buffer.length,
      lastDatagramAt: lastAt ? new Date(lastAt).toISOString() : null,
    };
  }

  function _feed(msg) { handlePacket(msg); }

  return {
    start, drain, stop, stats, requeueCounters, _feed, get bufferedFlows() { return buffer.length; },
  };
}

module.exports = {
  createSflowCollector, IF_COUNTER_FIELDS, COUNTERS_MAX, COUNTERS_BUDGET_BYTES, RESULT_BUDGET_BYTES,
  COUNTERS_FLOOR_BYTES, EXPORTERS_MAX,
};
