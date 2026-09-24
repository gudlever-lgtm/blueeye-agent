'use strict';

// Decodes an SNMPv1 / SNMPv2c trap datagram (BER) into
//   { version, community, pduType, varbinds: [{ oid, value }] }
//
// WHY OUR OWN DECODER. The receiver used to call `net-snmp`'s
// `Message.createFromBuffer`, but the library does not export `Message`, so the
// default decoder threw on every datagram and every real trap was counted as
// "undecodable". The tests never saw it because they inject the decoder. A trap
// message is a handful of BER types, and a pure decoder needs no optional
// dependency, so the trap path now works on a host where net-snmp failed to
// install too.
//
// SNMPv3 is NOT decoded: its PDU can be encrypted and authenticating it needs
// the USM user table. A v3 datagram throws with code TRAP_V3_UNSUPPORTED, so
// the receiver can count it apart from garbage.
//
// Every read is bounds-checked and a malformed datagram THROWS (code
// TRAP_MALFORMED); the receiver catches it. Nothing here ever reads past the
// buffer or allocates in proportion to a length field it has not checked.

const OID_SYSUPTIME = '1.3.6.1.2.1.1.3.0';
const OID_TRAP_OID = '1.3.6.1.6.3.1.1.4.1.0';
const OID_TRAP_ENTERPRISE = '1.3.6.1.6.3.1.1.4.3.0';

const PDU_TRAP_V1 = 0xa4;
const PDU_INFORM = 0xa6;
const PDU_TRAP_V2 = 0xa7;

const MAX_VARBINDS = 128;

function malformed(msg) {
  const err = new Error(`not an SNMP trap (${msg})`);
  err.code = 'TRAP_MALFORMED';
  return err;
}

// Reads one TLV at `o`. Returns { tag, start, end } — the value's bounds.
function readTlv(buf, o, limit) {
  if (o + 2 > limit) throw malformed('truncated tag');
  const tag = buf[o];
  let len = buf[o + 1];
  let p = o + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || p + n > limit) throw malformed('bad length');
    len = 0;
    for (let i = 0; i < n; i += 1) len = (len * 256) + buf[p + i];
    p += n;
  }
  if (p + len > limit) throw malformed('length past end');
  return { tag, start: p, end: p + len };
}

function readSigned(buf, start, end) {
  if (end <= start || end - start > 6) throw malformed('bad integer');
  return buf.readIntBE(start, end - start);
}

function readUnsigned(buf, start, end) {
  if (end <= start) return 0;
  // A leading 0x00 keeps a high-bit value positive; up to 5 bytes for 32-bit.
  if (end - start > 6) throw malformed('bad unsigned');
  return buf.readUIntBE(start, end - start);
}

function readOid(buf, start, end) {
  if (end <= start) throw malformed('empty OID');
  const subs = [];
  let v = 0;
  for (let i = start; i < end; i += 1) {
    v = (v * 128) + (buf[i] & 0x7f);
    if (v > Number.MAX_SAFE_INTEGER) throw malformed('OID arc too large');
    if (!(buf[i] & 0x80)) { subs.push(v); v = 0; }
  }
  if (!subs.length) throw malformed('unterminated OID');
  // The first subidentifier packs the first two arcs (X*40 + Y).
  const first = subs[0];
  const head = first < 80 ? [Math.floor(first / 40), first % 40] : [2, first - 80];
  return [...head, ...subs.slice(1)].join('.');
}

// A varbind value, in the shapes net-snmp produced (translate.js reads both):
// OCTET STRING / Opaque / Counter64 as a Buffer, OID and IpAddress as strings,
// the integer types as numbers, NULL and the v2 exceptions as null.
function readValue(buf, tlv) {
  const { tag, start, end } = tlv;
  switch (tag) {
    case 0x02: return readSigned(buf, start, end); // INTEGER
    case 0x04: return Buffer.from(buf.subarray(start, end)); // OCTET STRING
    case 0x05: return null; // NULL
    case 0x06: return readOid(buf, start, end); // OBJECT IDENTIFIER
    case 0x40: // IpAddress
      if (end - start !== 4) throw malformed('bad IpAddress');
      return `${buf[start]}.${buf[start + 1]}.${buf[start + 2]}.${buf[start + 3]}`;
    case 0x41: case 0x42: case 0x43: case 0x47: // Counter32 Gauge32 TimeTicks UInteger32
      return readUnsigned(buf, start, end);
    case 0x44: case 0x46: return Buffer.from(buf.subarray(start, end)); // Opaque, Counter64
    case 0x80: case 0x81: case 0x82: return null; // noSuchObject noSuchInstance endOfMibView
    default: return Buffer.from(buf.subarray(start, end));
  }
}

function readVarbinds(buf, start, end) {
  const out = [];
  let o = start;
  while (o < end) {
    if (out.length >= MAX_VARBINDS) break; // a bounded record, not a transcript
    const vb = readTlv(buf, o, end);
    if (vb.tag !== 0x30) throw malformed('varbind is not a sequence');
    const name = readTlv(buf, vb.start, vb.end);
    if (name.tag !== 0x06) throw malformed('varbind name is not an OID');
    const value = readTlv(buf, name.end, vb.end);
    out.push({ oid: readOid(buf, name.start, name.end), value: readValue(buf, value) });
    o = vb.end;
  }
  return out;
}

// RFC 3584 §3.1: a v1 trap becomes the v2 varbind shape — sysUpTime.0,
// snmpTrapOID.0, the trap's own varbinds, then snmpTrapEnterprise.0 — so there
// is one translation path rather than two.
function v1ToV2(buf, pdu) {
  const ent = readTlv(buf, pdu.start, pdu.end);
  if (ent.tag !== 0x06) throw malformed('v1 enterprise is not an OID');
  const enterprise = readOid(buf, ent.start, ent.end);
  const addr = readTlv(buf, ent.end, pdu.end);
  const generic = readTlv(buf, addr.end, pdu.end);
  const specific = readTlv(buf, generic.end, pdu.end);
  const stamp = readTlv(buf, specific.end, pdu.end);
  const list = readTlv(buf, stamp.end, pdu.end);
  if (list.tag !== 0x30) throw malformed('v1 varbind list');
  const g = readSigned(buf, generic.start, generic.end);
  const s = readSigned(buf, specific.start, specific.end);
  const trapOid = g >= 0 && g < 6 ? `1.3.6.1.6.3.1.1.5.${g + 1}` : `${enterprise}.0.${s}`;
  return [
    { oid: OID_SYSUPTIME, value: readUnsigned(buf, stamp.start, stamp.end) },
    { oid: OID_TRAP_OID, value: trapOid },
    ...readVarbinds(buf, list.start, list.end),
    { oid: OID_TRAP_ENTERPRISE, value: enterprise },
  ];
}

function decodeTrap(msg) {
  if (!Buffer.isBuffer(msg) || msg.length < 8) throw malformed('too short');
  const top = readTlv(msg, 0, msg.length);
  if (top.tag !== 0x30) throw malformed('not a sequence');
  const ver = readTlv(msg, top.start, top.end);
  if (ver.tag !== 0x02) throw malformed('no version');
  const version = readSigned(msg, ver.start, ver.end);
  if (version === 3) {
    const err = new Error('SNMPv3 trap (not supported: v3 traps need the USM user table)');
    err.code = 'TRAP_V3_UNSUPPORTED';
    throw err;
  }
  if (version !== 0 && version !== 1) throw malformed(`version ${version}`);
  const comm = readTlv(msg, ver.end, top.end);
  if (comm.tag !== 0x04) throw malformed('no community');
  const community = msg.toString('latin1', comm.start, comm.end);
  const pdu = readTlv(msg, comm.end, top.end);

  let varbinds;
  if (pdu.tag === PDU_TRAP_V1) {
    varbinds = v1ToV2(msg, pdu);
  } else if (pdu.tag === PDU_TRAP_V2 || pdu.tag === PDU_INFORM) {
    // request-id, error-status, error-index, then the varbind list.
    const reqId = readTlv(msg, pdu.start, pdu.end);
    const errStatus = readTlv(msg, reqId.end, pdu.end);
    const errIndex = readTlv(msg, errStatus.end, pdu.end);
    const list = readTlv(msg, errIndex.end, pdu.end);
    if (list.tag !== 0x30) throw malformed('varbind list');
    varbinds = readVarbinds(msg, list.start, list.end);
  } else {
    throw malformed(`PDU type 0x${pdu.tag.toString(16)} is not a trap`);
  }
  return { version: version === 0 ? '1' : '2c', community, pduType: pdu.tag, varbinds };
}

module.exports = { decodeTrap, PDU_TRAP_V1, PDU_TRAP_V2, PDU_INFORM };
