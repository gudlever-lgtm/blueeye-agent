'use strict';

const { decodeSampledHeader } = require('./decodePacket');
const { ipv4, ipv6 } = require('../netflow/ip');

// Parses an sFlow v5 datagram (UDP). sFlow is sampling-based: the agent on the
// switch captures 1-in-N packets and exports the first bytes of each sampled
// frame plus the sampling rate. To estimate real traffic we scale each sample's
// bytes by its rate. We decode "flow samples" (type 1/3) containing a "raw packet
// header" flow record (type 1) — the common case for port/protocol visibility —
// plus the "extended switch" record (type 1001) for the VLAN when the sampled
// frame itself carries no 802.1Q tag.
//
// COUNTER SAMPLES (type 2/4) are decoded too: the switch's own interface
// counters (generic, format 1) and Ethernet error counters (format 2), pushed
// every polling interval without anyone asking. On a switch nobody polls over
// SNMP they are the ONLY source of per-port errors and duplex, and they used to
// be counted and thrown away.
//
// Datagram layout (v5): version(4)=5 ipVersion(4) agentAddr(4|16) subAgentId(4)
// seq(4) uptime(4) numSamples(4) then numSamples samples. Each sample:
// sampleType(4) sampleLength(4) body.
//
// Returns { header, flows, counterSamples, counters } where flows match the
// NetFlow flow shape (bytes are rate-scaled), counterSamples counts the counter
// samples seen, and counters holds the decoded interface-counter records.
// Throws on a malformed/too-short datagram.

// sFlow's "this counter is not available" is the type's all-ones value. Kept
// as null, never as a number: absent is not zero (the same rule the SNMP
// counter path follows).
const U32_UNKNOWN = 0xffffffff;

// ifIndex fields in a flow sample: 0x3FFFFFFF means "unknown", and a non-zero
// format (the top two bits of a compact field) means the value is not an
// ifIndex at all (a discard reason, or a count of output ports).
const IF_UNKNOWN = 0x3fffffff;

// The compressed RFC 5952 form ("2001:db8::1"), so the server can match the
// exporter against a device address typed the way people type them.
function canonicalIpv6(s) {
  try { return new URL(`http://[${s}]/`).hostname.slice(1, -1); } catch { return s; }
}

function parseSflow(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 28) {
    throw new Error('sFlow: datagram too short');
  }
  const version = buf.readUInt32BE(0);
  if (version !== 5) {
    throw new Error(`sFlow: unsupported version ${version}`);
  }
  const ipVersion = buf.readUInt32BE(4);
  let o = 8;
  let agent = null;
  if (ipVersion === 2) {
    if (o + 16 > buf.length) throw new Error('sFlow: truncated header');
    agent = canonicalIpv6(ipv6(buf, o));
    o += 16;
  } else {
    agent = ipv4(buf, o);
    o += 4;
  }
  o += 4; // sub-agent id
  o += 4; // sequence
  if (o + 8 > buf.length) throw new Error('sFlow: truncated header');
  const uptimeMs = buf.readUInt32BE(o); // the exporter's own uptime, ms
  o += 4;
  const numSamples = buf.readUInt32BE(o);
  o += 4;

  const header = { version, numSamples, agent, uptimeMs };
  const flows = [];
  const counters = [];
  let counterSamples = 0; // sampleType 2/4: counter samples — no per-flow data

  for (let s = 0; s < numSamples && o + 8 <= buf.length; s += 1) {
    const sampleType = buf.readUInt32BE(o);
    const sampleLen = buf.readUInt32BE(o + 4);
    const sampleStart = o + 8;
    const sampleEnd = sampleStart + sampleLen;
    if (sampleEnd > buf.length) break;

    // sampleType 1/3 = (expanded) flow sample; 2/4 = (expanded) counter sample.
    // Counter samples are also COUNTED, so Diagnose can distinguish "datagrams
    // arriving but only counters" (packet sampling not active) from "no
    // datagrams at all".
    if (sampleType === 1 || sampleType === 3) {
      parseFlowSample(buf, sampleStart, sampleEnd, sampleType === 3, flows);
    } else if (sampleType === 2 || sampleType === 4) {
      counterSamples += 1;
      const rec = parseCounterSample(buf, sampleStart, sampleEnd, sampleType === 4);
      if (rec) counters.push({ agent, uptimeMs, ...rec });
    }
    o = sampleEnd;
  }

  return { header, flows, counterSamples, counters };
}

// An interface index from a compact (32-bit) flow-sample field: top two bits
// are the format, the low 30 the value. Only format 0 is an ifIndex.
function compactIfIndex(v) {
  if ((v >>> 30) !== 0) return null;
  const idx = v & IF_UNKNOWN;
  return idx === IF_UNKNOWN || idx === 0 ? null : idx;
}

// Expanded form: an explicit format word, then the value.
function expandedIfIndex(format, value) {
  if (format !== 0) return null;
  return value === IF_UNKNOWN || value === 0 ? null : value;
}

function parseFlowSample(buf, start, end, expanded, flows) {
  let p = start;
  p += 4; // sequence number
  // source id: 4 bytes (normal) or 8 bytes (expanded)
  p += expanded ? 8 : 4;
  if (p + 12 > end) return;
  const samplingRate = buf.readUInt32BE(p); p += 4;
  p += 4; // sample pool
  p += 4; // drops
  // input/output interface: 4 each (normal) or format+value 8 each (expanded)
  let inIf = null;
  let outIf = null;
  if (expanded) {
    if (p + 16 > end) return;
    inIf = expandedIfIndex(buf.readUInt32BE(p), buf.readUInt32BE(p + 4));
    outIf = expandedIfIndex(buf.readUInt32BE(p + 8), buf.readUInt32BE(p + 12));
    p += 16;
  } else {
    if (p + 8 > end) return;
    inIf = compactIfIndex(buf.readUInt32BE(p));
    outIf = compactIfIndex(buf.readUInt32BE(p + 4));
    p += 8;
  }
  if (p + 4 > end) return;
  const numRecords = buf.readUInt32BE(p); p += 4;

  const rate = samplingRate > 0 ? samplingRate : 1;
  let flow = null;
  let switchVlan = null; // extended switch data (record 1001): the ingress VLAN

  for (let r = 0; r < numRecords && p + 8 <= end; r += 1) {
    const recType = buf.readUInt32BE(p);
    const recLen = buf.readUInt32BE(p + 4);
    const recStart = p + 8;
    const recEnd = recStart + recLen;
    if (recEnd > end) break;

    // flow record type 1 = raw packet header (enterprise 0).
    if (recType === 1 && recStart + 16 <= recEnd && !flow) {
      // header_protocol(4) frame_length(4) stripped(4) header_length(4) header[]
      const frameLength = buf.readUInt32BE(recStart + 4);
      const headerLength = buf.readUInt32BE(recStart + 12);
      const hStart = recStart + 16;
      const hEnd = Math.min(hStart + headerLength, recEnd);
      if (hEnd > hStart) flow = decodeSampledHeader(buf.subarray(hStart, hEnd), frameLength);
    } else if (recType === 1001 && recStart + 16 <= recEnd) {
      // src_vlan(4) src_priority(4) dst_vlan(4) dst_priority(4)
      const v = buf.readUInt32BE(recStart);
      if (v >= 1 && v <= 4094) switchVlan = v;
    }
    p = recEnd;
  }

  if (flow) {
    // Scale by the sampling rate: each sample stands in for ~rate packets.
    flow.bytes *= rate;
    flow.packets *= rate;
    flow.sampled = true;
    // The 802.1Q tag in the frame wins; the switch's own record fills in when
    // the port stripped the tag before sampling (an access port).
    if (flow.vlan == null && switchVlan != null) flow.vlan = switchVlan;
    if (inIf != null) flow.inIf = inIf;
    if (outIf != null) flow.outIf = outIf;
    flows.push(flow);
  }
}

// ---------------------------------------------------------------- counters

function u32(buf, o) {
  const v = buf.readUInt32BE(o);
  return v === U32_UNKNOWN ? null : v;
}

// A 64-bit counter as a Number (exact to 2^53, which an octet counter reaches
// after ~2.8 years at 100 Gbit/s). All-ones is "unknown".
function u64(buf, o) {
  const hi = buf.readUInt32BE(o);
  const lo = buf.readUInt32BE(o + 4);
  if (hi === U32_UNKNOWN && lo === U32_UNKNOWN) return null;
  return hi * 2 ** 32 + lo;
}

// Generic interface counters (enterprise 0, format 1), 88 bytes.
function parseGenericIf(buf, o) {
  const status = buf.readUInt32BE(o + 20);
  return {
    ifIndex: buf.readUInt32BE(o),
    ifType: u32(buf, o + 4),
    ifSpeed: u64(buf, o + 8), // bits per second
    // 0 unknown, 1 full-duplex, 2 half-duplex, 3 in, 4 out (RFC 3635 / sFlow v5)
    ifDirection: buf.readUInt32BE(o + 16),
    // bit 0 = ifAdminStatus up, bit 1 = ifOperStatus up
    ifStatus: status,
    ifInOctets: u64(buf, o + 24),
    ifInUcastPkts: u32(buf, o + 32),
    ifInMulticastPkts: u32(buf, o + 36),
    ifInBroadcastPkts: u32(buf, o + 40),
    ifInDiscards: u32(buf, o + 44),
    ifInErrors: u32(buf, o + 48),
    ifInUnknownProtos: u32(buf, o + 52),
    ifOutOctets: u64(buf, o + 56),
    ifOutUcastPkts: u32(buf, o + 64),
    ifOutMulticastPkts: u32(buf, o + 68),
    ifOutBroadcastPkts: u32(buf, o + 72),
    ifOutDiscards: u32(buf, o + 76),
    ifOutErrors: u32(buf, o + 80),
    ifPromiscuousMode: buf.readUInt32BE(o + 84),
  };
}

// Ethernet interface counters (enterprise 0, format 2), 52 bytes.
const ETHERNET_FIELDS = [
  'dot3StatsAlignmentErrors', 'dot3StatsFCSErrors', 'dot3StatsSingleCollisionFrames',
  'dot3StatsMultipleCollisionFrames', 'dot3StatsSQETestErrors', 'dot3StatsDeferredTransmissions',
  'dot3StatsLateCollisions', 'dot3StatsExcessiveCollisions', 'dot3StatsInternalMacTransmitErrors',
  'dot3StatsCarrierSenseErrors', 'dot3StatsFrameTooLongs', 'dot3StatsInternalMacReceiveErrors',
  'dot3StatsSymbolErrors',
];

function parseEthernet(buf, o) {
  const out = {};
  ETHERNET_FIELDS.forEach((f, i) => { out[f] = u32(buf, o + i * 4); });
  return out;
}

// One counter sample → { ifIndex, generic?, ethernet? } or null when it
// carries neither record we read (a CPU/host-only sample, say).
function parseCounterSample(buf, start, end, expanded) {
  let p = start;
  p += 4; // sequence
  let sourceIndex = null;
  if (expanded) {
    if (p + 8 > end) return null;
    if (buf.readUInt32BE(p) === 0) sourceIndex = buf.readUInt32BE(p + 4); // type 0 = ifIndex
    p += 8;
  } else {
    if (p + 4 > end) return null;
    const src = buf.readUInt32BE(p);
    if ((src >>> 24) === 0) sourceIndex = src & 0x00ffffff;
    p += 4;
  }
  if (p + 4 > end) return null;
  const numRecords = buf.readUInt32BE(p); p += 4;

  let generic = null;
  let ethernet = null;
  for (let r = 0; r < numRecords && p + 8 <= end; r += 1) {
    const format = buf.readUInt32BE(p); // enterprise(20 bits) << 12 | format(12)
    const len = buf.readUInt32BE(p + 4);
    const recStart = p + 8;
    const recEnd = recStart + len;
    if (recEnd > end) break;
    if (format === 1 && len >= 88) generic = parseGenericIf(buf, recStart);
    else if (format === 2 && len >= 52) ethernet = parseEthernet(buf, recStart);
    p = recEnd;
  }
  if (!generic && !ethernet) return null;
  const ifIndex = generic ? generic.ifIndex : sourceIndex;
  if (!Number.isInteger(ifIndex) || ifIndex <= 0) return null;
  return { ifIndex, generic, ethernet };
}

module.exports = { parseSflow, ETHERNET_FIELDS };
