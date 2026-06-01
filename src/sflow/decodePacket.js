'use strict';

// Decodes the start of a sampled raw packet (Ethernet II + IPv4/IPv6 + TCP/UDP)
// far enough to extract the L3/L4 5-tuple. sFlow ships the first N bytes of the
// actual frame (header_protocol = 1 means Ethernet/ISO88023), so unlike NetFlow
// we parse the packet ourselves. Returns a flow-ish record or null if it isn't
// an IP/TCP/UDP packet we can read.
const { PROTO_NAMES } = require('../netflow/fields');

const ETH_HDR = 14;
const ETHERTYPE_IPV4 = 0x0800;
const ETHERTYPE_IPV6 = 0x86dd;
const ETHERTYPE_VLAN = 0x8100;

function ipv4(buf, o) {
  return `${buf[o]}.${buf[o + 1]}.${buf[o + 2]}.${buf[o + 3]}`;
}
function ipv6(buf, o) {
  const parts = [];
  for (let i = 0; i < 16; i += 2) parts.push(buf.readUInt16BE(o + i).toString(16));
  return parts.join(':');
}

// Reads L4 ports for TCP(6)/UDP(17); other protocols get ports 0.
function readPorts(buf, o, protocol, end) {
  if ((protocol === 6 || protocol === 17) && o + 4 <= end) {
    return { srcPort: buf.readUInt16BE(o), dstPort: buf.readUInt16BE(o + 2) };
  }
  return { srcPort: 0, dstPort: 0 };
}

// header = the sampled raw bytes (Buffer). frameLength = the original (un-
// sampled) frame length reported by sFlow, used to scale bytes accurately.
function decodeSampledHeader(header, frameLength) {
  if (!Buffer.isBuffer(header) || header.length < ETH_HDR + 20) return null;

  let etherType = header.readUInt16BE(12);
  let l3 = ETH_HDR;
  // Skip up to one VLAN tag.
  if (etherType === ETHERTYPE_VLAN && header.length >= l3 + 4) {
    etherType = header.readUInt16BE(l3 + 2);
    l3 += 4;
  }

  const bytes = Number.isFinite(frameLength) && frameLength > 0 ? frameLength : header.length;
  const flow = { srcAddr: '0.0.0.0', dstAddr: '0.0.0.0', srcPort: 0, dstPort: 0, protocol: 0, bytes, packets: 1 };

  if (etherType === ETHERTYPE_IPV4) {
    if (header.length < l3 + 20) return null;
    const ihl = (header[l3] & 0x0f) * 4;
    flow.protocol = header[l3 + 9];
    flow.srcAddr = ipv4(header, l3 + 12);
    flow.dstAddr = ipv4(header, l3 + 16);
    const l4 = l3 + (ihl >= 20 ? ihl : 20);
    Object.assign(flow, readPorts(header, l4, flow.protocol, header.length));
  } else if (etherType === ETHERTYPE_IPV6) {
    if (header.length < l3 + 40) return null;
    flow.protocol = header[l3 + 6]; // next header (no extension-header walking)
    flow.srcAddr = ipv6(header, l3 + 8);
    flow.dstAddr = ipv6(header, l3 + 24);
    Object.assign(flow, readPorts(header, l3 + 40, flow.protocol, header.length));
  } else {
    return null; // not IP — nothing to aggregate by port/protocol
  }

  flow.protocolName = PROTO_NAMES[flow.protocol] || String(flow.protocol);
  return flow;
}

module.exports = { decodeSampledHeader, ETHERTYPE_IPV4, ETHERTYPE_IPV6 };
