'use strict';

// Decodes one captured frame into a HEADER RECORD — never a payload.
//
// THE PRIVACY BOUNDARY IS THIS FILE. Everything the capture path ever reports
// comes out of `decodeFrame`, and it returns a fixed set of named header fields.
// The frame buffer is read here and referenced nowhere else, so there is no path
// by which application bytes reach a buffer that is stored, sent or logged. A
// field that is not in the record below does not exist downstream.
//
// What is read, and why each one earns its place:
//
//   flags   SYN with no SYN-ACK is a path or firewall drop; RST is a refusal.
//           Those are different faults and a connect timeout looks like both.
//   seq/ack retransmissions (a segment sent twice) and duplicate ACKs
//           (out-of-order delivery) — i.e. packet loss, which a latency number
//           only ever shows as "sometimes slow".
//   win     a zero window is the RECEIVER saying it has no buffer left. That is
//           an application fault wearing a network fault's clothes.
//   ttl     the hop count that got here. Two different TTLs from one address
//           means two different paths.
//   mss     what each end offered in its SYN — an MTU or tunnel mismatch, found
//           before it becomes an unexplainable stall on large responses.
//
// Deliberately NOT read: anything past the transport header. No DNS question
// name, no TLS SNI, no HTTP host or path. Those are the fields that would make
// the feature more useful and make it a payload capture; the line is here.

const { ipv4, ipv6 } = require('../netflow/ip');

// pcap link types this decoder understands. `tcpdump -i any` on Linux produces
// cooked captures (SLL/SLL2) rather than Ethernet, and that is the interface a
// transaction capture most often runs on, so both matter.
const LINKTYPE = Object.freeze({
  NULL: 0, EN10MB: 1, RAW_BSD: 12, RAW_OPENBSD: 14, LOOP: 108, LINUX_SLL: 113, RAW: 101, LINUX_SLL2: 276,
});

const ETHERTYPE_IPV4 = 0x0800;
const ETHERTYPE_IPV6 = 0x86dd;
const ETHERTYPE_VLAN = 0x8100;
const ETHERTYPE_QINQ = 0x88a8;

const PROTO_TCP = 6;
const PROTO_UDP = 17;
const PROTO_ICMP = 1;
const PROTO_ICMPV6 = 58;

// TCP flag letters, most significant first, in the order tcpdump prints them.
const TCP_FLAGS = Object.freeze([
  [0x01, 'F'], [0x02, 'S'], [0x04, 'R'], [0x08, 'P'], [0x10, 'A'], [0x20, 'U'], [0x40, 'E'], [0x80, 'C'],
]);

function flagString(bits) {
  let out = '';
  for (const [bit, letter] of TCP_FLAGS) if (bits & bit) out += letter;
  return out;
}

// Strips the link layer and returns { etherType, offset }, or null when the
// frame is not one we can read. VLAN tags (up to two, for QinQ) are skipped.
function stripLink(buf, linkType) {
  switch (linkType) {
    case LINKTYPE.EN10MB: {
      if (buf.length < 14) return null;
      let type = buf.readUInt16BE(12);
      let off = 14;
      for (let i = 0; i < 2 && (type === ETHERTYPE_VLAN || type === ETHERTYPE_QINQ); i += 1) {
        if (buf.length < off + 4) return null;
        type = buf.readUInt16BE(off + 2);
        off += 4;
      }
      return { etherType: type, offset: off };
    }
    case LINKTYPE.LINUX_SLL: {
      // 16-byte cooked header; the protocol is the last 2 bytes.
      if (buf.length < 16) return null;
      return { etherType: buf.readUInt16BE(14), offset: 16 };
    }
    case LINKTYPE.LINUX_SLL2: {
      // 20-byte cooked v2 header; the protocol is the FIRST 2 bytes.
      if (buf.length < 20) return null;
      return { etherType: buf.readUInt16BE(0), offset: 20 };
    }
    case LINKTYPE.NULL:
    case LINKTYPE.LOOP: {
      // 4-byte address-family header. NULL is host-endian, LOOP big-endian;
      // reading both ways and accepting a known family covers either.
      if (buf.length < 4) return null;
      const be = buf.readUInt32BE(0);
      const le = buf.readUInt32LE(0);
      const fam = (be === 2 || be === 24 || be === 28 || be === 30) ? be : le;
      if (fam === 2) return { etherType: ETHERTYPE_IPV4, offset: 4 };
      if (fam === 24 || fam === 28 || fam === 30) return { etherType: ETHERTYPE_IPV6, offset: 4 };
      return null;
    }
    case LINKTYPE.RAW:
    case LINKTYPE.RAW_BSD:
    case LINKTYPE.RAW_OPENBSD: {
      // No link header at all: the IP version nibble decides.
      if (buf.length < 1) return null;
      const version = buf[0] >> 4;
      if (version === 4) return { etherType: ETHERTYPE_IPV4, offset: 0 };
      if (version === 6) return { etherType: ETHERTYPE_IPV6, offset: 0 };
      return null;
    }
    default:
      return null;
  }
}

// Reads the MSS option out of a TCP header, when present (SYN packets carry it).
// Walks the option list defensively: a malformed length must end the walk, not
// loop forever or read past the header.
function readMss(buf, optStart, optEnd) {
  let o = optStart;
  while (o < optEnd && o < buf.length) {
    const kind = buf[o];
    if (kind === 0) return null;          // EOL
    if (kind === 1) { o += 1; continue; } // NOP has no length byte
    if (o + 1 >= optEnd) return null;
    const len = buf[o + 1];
    if (len < 2) return null;             // malformed: stop rather than spin
    if (kind === 2 && len === 4 && o + 4 <= optEnd && o + 4 <= buf.length) return buf.readUInt16BE(o + 2);
    o += len;
  }
  return null;
}

// Decodes one frame. `tsMs` is the capture timestamp in ms (float), `capLen` the
// bytes actually captured and `wireLen` the original frame length — the record
// reports the WIRE length, because a snaplen-truncated frame still travelled its
// full size and a throughput figure built on the captured length would be wrong.
//
// Returns null for anything that is not IPv4/IPv6 — ARP, STP, and the rest are
// not what a transaction capture is about.
function decodeFrame(buf, { linkType = LINKTYPE.EN10MB, tsMs = 0, wireLen = null } = {}) {
  if (!Buffer.isBuffer(buf) || buf.length < 4) return null;
  const link = stripLink(buf, linkType);
  if (!link) return null;

  const rec = {
    t: Math.round(tsMs * 1000) / 1000,
    src: null, dst: null, proto: 0, sport: 0, dport: 0,
    len: Number.isFinite(wireLen) && wireLen > 0 ? wireLen : buf.length,
    ttl: null, flags: null, seq: null, ack: null, win: null, mss: null, icmp: null, payload: 0,
  };

  let l3 = link.offset;
  let l4 = null;
  let l4End = buf.length;

  if (link.etherType === ETHERTYPE_IPV4) {
    if (buf.length < l3 + 20) return null;
    const ihl = (buf[l3] & 0x0f) * 4;
    if (ihl < 20) return null;
    const totalLen = buf.readUInt16BE(l3 + 2);
    rec.proto = buf[l3 + 9];
    rec.ttl = buf[l3 + 8];
    rec.src = ipv4(buf, l3 + 12);
    rec.dst = ipv4(buf, l3 + 16);
    l4 = l3 + ihl;
    // The IP total length bounds the transport header, so a snaplen-truncated
    // frame is not read past its captured end either way.
    if (totalLen >= ihl) l4End = Math.min(buf.length, l3 + totalLen);
  } else if (link.etherType === ETHERTYPE_IPV6) {
    if (buf.length < l3 + 40) return null;
    rec.proto = buf[l3 + 6]; // next header; extension headers are not walked
    rec.ttl = buf[l3 + 7];   // hop limit
    rec.src = ipv6(buf, l3 + 8);
    rec.dst = ipv6(buf, l3 + 24);
    const payloadLen = buf.readUInt16BE(l3 + 4);
    l4 = l3 + 40;
    if (payloadLen > 0) l4End = Math.min(buf.length, l4 + payloadLen);
  } else {
    return null;
  }

  if (rec.proto === PROTO_TCP && l4 + 20 <= buf.length) {
    rec.sport = buf.readUInt16BE(l4);
    rec.dport = buf.readUInt16BE(l4 + 2);
    rec.seq = buf.readUInt32BE(l4 + 4);
    rec.ack = buf.readUInt32BE(l4 + 8);
    const dataOffset = (buf[l4 + 12] >> 4) * 4;
    rec.flags = flagString(buf[l4 + 13]);
    rec.win = buf.readUInt16BE(l4 + 14);
    if (dataOffset > 20) rec.mss = readMss(buf, l4 + 20, Math.min(l4 + dataOffset, l4End));
    // How many bytes of application data this segment carried. The COUNT only —
    // it is what separates an empty ACK from a segment that has to be
    // retransmitted, and it is the one thing about the payload worth knowing.
    const hdr = dataOffset >= 20 ? dataOffset : 20;
    rec.payload = Math.max(0, l4End - (l4 + hdr));
  } else if (rec.proto === PROTO_UDP && l4 + 8 <= buf.length) {
    rec.sport = buf.readUInt16BE(l4);
    rec.dport = buf.readUInt16BE(l4 + 2);
    rec.payload = Math.max(0, buf.readUInt16BE(l4 + 4) - 8);
  } else if ((rec.proto === PROTO_ICMP || rec.proto === PROTO_ICMPV6) && l4 + 4 <= buf.length) {
    rec.icmp = { type: buf[l4], code: buf[l4 + 1] };
  }

  return rec;
}

module.exports = { decodeFrame, stripLink, flagString, LINKTYPE, PROTO_TCP, PROTO_UDP, PROTO_ICMP, PROTO_ICMPV6 };
