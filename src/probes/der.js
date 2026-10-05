'use strict';

// A minimal DER reader/writer — just enough for OCSP (src/probes/ocsp.js).
//
// WHY BY HAND. An OCSP request is a hand-rolled ASN.1 structure and node
// exposes no encoder for it, so the alternative is a dependency. This agent has
// two (`ws`, optional `net-snmp`) and a certificate-revocation check is not
// worth a third: the subset DER actually needs here is a tag, a length and a
// handful of primitives, which is this file. It parses, it does not trust —
// every length is bounds-checked against the buffer and a malformed structure
// throws rather than reading past the end.
//
// Definite-length encodings only. BER's indefinite lengths are illegal in DER,
// so a responder that sends one is malformed and gets the same throw.

function read(buf, off = 0) {
  if (!Buffer.isBuffer(buf)) throw new Error('der: not a buffer');
  if (off + 2 > buf.length) throw new Error('der: truncated header');
  const tag = buf[off];
  let i = off + 1;
  let len = buf[i];
  i += 1;
  if (len & 0x80) {
    const n = len & 0x7f;
    // 0 is an indefinite length (BER only); more than 4 bytes is a length no
    // response this code reads could legitimately need.
    if (n === 0 || n > 4) throw new Error('der: unsupported length');
    if (i + n > buf.length) throw new Error('der: truncated length');
    len = 0;
    for (let k = 0; k < n; k += 1) { len = len * 256 + buf[i]; i += 1; }
  }
  const end = i + len;
  if (end > buf.length) throw new Error('der: truncated value');
  return { tag, start: i, len, end, content: buf.subarray(i, end), raw: buf.subarray(off, end) };
}

// The TLVs sitting inside a constructed value's content.
function children(content) {
  const out = [];
  let off = 0;
  while (off < content.length) {
    const tlv = read(content, off);
    out.push(tlv);
    if (tlv.end <= off) throw new Error('der: zero-length advance');
    off = tlv.end;
  }
  return out;
}

const TAG = {
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  ENUMERATED: 0x0a,
  SEQUENCE: 0x30,
  GENERALIZED_TIME: 0x18,
};

// Context-specific tags, as the OCSP module writes and reads them.
const ctx = (n, constructed = true) => (constructed ? 0xa0 : 0x80) | n;

function encodeLength(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  let v = n;
  while (v > 0) { bytes.unshift(v & 0xff); v = Math.floor(v / 256); }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

const tlv = (tag, content) => Buffer.concat([Buffer.from([tag]), encodeLength(content.length), content]);
const seq = (...parts) => tlv(TAG.SEQUENCE, Buffer.concat(parts));
const octetString = (b) => tlv(TAG.OCTET_STRING, b);
const nullValue = () => Buffer.from([TAG.NULL, 0x00]);
const explicit = (n, content) => tlv(ctx(n), content);

function encodeOid(dotted) {
  const parts = String(dotted).split('.').map((p) => Number.parseInt(p, 10));
  if (parts.length < 2 || parts.some((p) => !Number.isInteger(p) || p < 0)) throw new Error('der: bad oid');
  const bytes = [40 * parts[0] + parts[1]];
  for (const part of parts.slice(2)) {
    const chunk = [part & 0x7f];
    let v = Math.floor(part / 128);
    while (v > 0) { chunk.unshift((v & 0x7f) | 0x80); v = Math.floor(v / 128); }
    bytes.push(...chunk);
  }
  return Buffer.from(bytes);
}

const oid = (dotted) => tlv(TAG.OID, encodeOid(dotted));

function decodeOid(content) {
  if (!content.length) return null;
  const first = content[0];
  const out = [Math.floor(first / 40), first % 40];
  let value = 0;
  for (let i = 1; i < content.length; i += 1) {
    value = value * 128 + (content[i] & 0x7f);
    if (!(content[i] & 0x80)) { out.push(value); value = 0; }
  }
  return out.join('.');
}

// A serial number as an INTEGER, from the colon-or-plain hex node reports
// (`0A1B2C`). Leading zero bytes are dropped and a 0x00 is prepended when the
// top bit is set, because a CertID serial is a signed INTEGER and a responder
// that gets the sign wrong answers about a different certificate.
function integerFromHex(hex) {
  const raw = String(hex == null ? '' : hex).trim();
  // Hex, optionally colon-separated, and NOTHING else: stripping unknown
  // characters out of arbitrary input would turn a typo into a different
  // serial number, which a responder would happily answer about.
  if (!/^[0-9a-fA-F]+(:[0-9a-fA-F]+)*$/.test(raw)) return null;
  const clean = raw.replace(/:/g, '');
  if (!clean || clean.length % 2) return null;
  let bytes = Buffer.from(clean, 'hex');
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0x00 && !(bytes[i + 1] & 0x80)) i += 1;
  bytes = bytes.subarray(i);
  if (bytes[0] & 0x80) bytes = Buffer.concat([Buffer.from([0x00]), bytes]);
  return tlv(TAG.INTEGER, bytes);
}

// 'YYYYMMDDHHMMSSZ' (with optional fractional seconds) → epoch ms, or null.
function generalizedTime(content) {
  const s = content.toString('latin1');
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?Z$/.exec(s);
  if (!m) return null;
  const ms = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
  return Number.isFinite(ms) ? ms : null;
}

module.exports = {
  read, children, TAG, ctx,
  tlv, seq, octetString, nullValue, explicit, oid, encodeOid, decodeOid,
  integerFromHex, generalizedTime,
};
