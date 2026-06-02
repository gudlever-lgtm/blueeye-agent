'use strict';

const { ipv4, ipv6 } = require('./ip');

// NetFlow v9 / IPFIX share the same field-type IDs (Information Elements) for
// the fields we care about. We only decode the handful needed to build the same
// flow record shape as the v5 parser; everything else is skipped by length.
const FIELD = {
  IN_BYTES: 1,
  IN_PKTS: 2,
  PROTOCOL: 4,
  L4_SRC_PORT: 7,
  IPV4_SRC_ADDR: 8,
  L4_DST_PORT: 11,
  IPV4_DST_ADDR: 12,
  IPV6_SRC_ADDR: 27,
  IPV6_DST_ADDR: 28,
  // IPFIX octet/packet delta counters (aliases of IN_BYTES/IN_PKTS semantics).
  OCTET_DELTA_COUNT: 1,
  PACKET_DELTA_COUNT: 2,
};

const PROTO_NAMES = { 1: 'icmp', 6: 'tcp', 17: 'udp', 47: 'gre', 50: 'esp', 58: 'icmpv6' };

// Reads an unsigned integer of `len` bytes (1..8) big-endian. >6 bytes uses
// BigInt then narrows to Number (flow counters fit comfortably in a double).
function readUInt(buf, off, len) {
  if (len <= 0) return 0;
  if (len <= 6) return buf.readUIntBE(off, len);
  let v = 0n;
  for (let i = 0; i < len; i += 1) v = (v << 8n) | BigInt(buf[off + i]);
  return Number(v);
}

// Applies one decoded field (by type/length) onto a flow record.
function applyField(flow, type, buf, off, len) {
  switch (type) {
    case FIELD.IN_BYTES:
      flow.bytes = readUInt(buf, off, len);
      break;
    case FIELD.IN_PKTS:
      flow.packets = readUInt(buf, off, len);
      break;
    case FIELD.PROTOCOL:
      flow.protocol = readUInt(buf, off, len);
      break;
    case FIELD.L4_SRC_PORT:
      flow.srcPort = readUInt(buf, off, len);
      break;
    case FIELD.L4_DST_PORT:
      flow.dstPort = readUInt(buf, off, len);
      break;
    case FIELD.IPV4_SRC_ADDR:
      if (len >= 4) flow.srcAddr = ipv4(buf, off);
      break;
    case FIELD.IPV4_DST_ADDR:
      if (len >= 4) flow.dstAddr = ipv4(buf, off);
      break;
    case FIELD.IPV6_SRC_ADDR:
      if (len >= 16) flow.srcAddr = ipv6(buf, off);
      break;
    case FIELD.IPV6_DST_ADDR:
      if (len >= 16) flow.dstAddr = ipv6(buf, off);
      break;
    default:
      break; // unknown/uninteresting field — skipped by length
  }
}

// Builds the normalised flow record from raw field reads, filling defaults so it
// matches the v5 parser output.
function finaliseFlow(flow) {
  const protocol = flow.protocol ?? 0;
  return {
    srcAddr: flow.srcAddr ?? '0.0.0.0',
    dstAddr: flow.dstAddr ?? '0.0.0.0',
    packets: flow.packets ?? 0,
    bytes: flow.bytes ?? 0,
    srcPort: flow.srcPort ?? 0,
    dstPort: flow.dstPort ?? 0,
    protocol,
    protocolName: PROTO_NAMES[protocol] || String(protocol),
  };
}

module.exports = { FIELD, PROTO_NAMES, readUInt, applyField, finaliseFlow };
