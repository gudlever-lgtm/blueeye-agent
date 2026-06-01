'use strict';

// Parses a NetFlow v5 export packet (the fixed-format version Cisco devices emit
// most widely). Pure function over a Buffer — no sockets — so it is fully
// unit-testable. Returns { header, flows } or throws on a malformed packet.
//
// Packet layout: a 24-byte header followed by `count` 48-byte flow records.
// Reference: Cisco NetFlow v5 record format.
const HEADER_BYTES = 24;
const RECORD_BYTES = 48;

const PROTO_NAMES = { 1: 'icmp', 6: 'tcp', 17: 'udp', 47: 'gre', 50: 'esp' };

function ipv4(buf, offset) {
  return `${buf[offset]}.${buf[offset + 1]}.${buf[offset + 2]}.${buf[offset + 3]}`;
}

function parseV5(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < HEADER_BYTES) {
    throw new Error('NetFlow v5: packet too short for header');
  }
  const version = buf.readUInt16BE(0);
  if (version !== 5) {
    throw new Error(`NetFlow v5: unexpected version ${version}`);
  }
  const count = buf.readUInt16BE(2);
  if (buf.length < HEADER_BYTES + count * RECORD_BYTES) {
    throw new Error('NetFlow v5: packet too short for flow count');
  }

  const header = {
    version,
    count,
    sysUptimeMs: buf.readUInt32BE(4),
    unixSecs: buf.readUInt32BE(8),
  };

  const flows = [];
  for (let i = 0; i < count; i += 1) {
    const o = HEADER_BYTES + i * RECORD_BYTES;
    const protocol = buf[o + 38];
    flows.push({
      srcAddr: ipv4(buf, o + 0),
      dstAddr: ipv4(buf, o + 4),
      packets: buf.readUInt32BE(o + 16),
      bytes: buf.readUInt32BE(o + 20),
      srcPort: buf.readUInt16BE(o + 32),
      dstPort: buf.readUInt16BE(o + 34),
      protocol,
      protocolName: PROTO_NAMES[protocol] || String(protocol),
      tcpFlags: buf[o + 37],
    });
  }

  return { header, flows };
}

module.exports = { parseV5, PROTO_NAMES, HEADER_BYTES, RECORD_BYTES };
