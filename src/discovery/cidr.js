'use strict';

// Pure IPv4 CIDR helpers for scoped active discovery. No I/O. IPv4 only — the
// scan probes IPv4 addresses; IPv6 CIDRs are rejected by parseCidr (a /64 is
// astronomically large and would blow any address-count cap anyway).

function ipToInt(ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(ip).trim());
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return null;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function intToIp(n) {
  const x = n >>> 0;
  return `${(x >>> 24) & 255}.${(x >>> 16) & 255}.${(x >>> 8) & 255}.${x & 255}`;
}

// Parse "10.0.0.0/24" → { base, prefix, first, last, count }. Returns null on a
// malformed or non-IPv4 CIDR. A bare IP is treated as /32.
function parseCidr(cidr) {
  const s = String(cidr).trim();
  if (!s) return null;
  const [ipPart, prefixPart] = s.split('/');
  const base = ipToInt(ipPart);
  if (base == null) return null;
  const prefix = prefixPart === undefined ? 32 : Number(prefixPart);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = (base & mask) >>> 0;
  const count = 2 ** (32 - prefix);
  const last = (network + count - 1) >>> 0;
  return { cidr: s, base: network, prefix, first: network, last, count };
}

// Total address count across a list of CIDRs (for the cap check) — computed
// WITHOUT enumerating, so an over-cap scope is refused before any allocation.
// Returns { count, cidrs, invalid } where invalid lists unparseable entries.
function totalAddresses(cidrList) {
  const cidrs = [];
  const invalid = [];
  let count = 0;
  for (const c of Array.isArray(cidrList) ? cidrList : []) {
    const p = parseCidr(c);
    if (!p) { invalid.push(c); continue; }
    cidrs.push(p);
    count += p.count;
  }
  return { count, cidrs, invalid };
}

// Lazily enumerate every address in a parsed CIDR as a dotted string.
function* expand(parsed) {
  for (let n = parsed.first; n <= parsed.last; n += 1) yield intToIp(n >>> 0);
}

// Is `ip` inside ANY of the parsed CIDRs? The scan uses this as a hard guard so a
// probe target outside the configured scope can never be issued.
function inScope(ip, parsedCidrs) {
  const n = ipToInt(ip);
  if (n == null) return false;
  for (const p of Array.isArray(parsedCidrs) ? parsedCidrs : []) {
    if ((n & (p.prefix === 0 ? 0 : (0xffffffff << (32 - p.prefix)) >>> 0)) >>> 0 === p.first) return true;
  }
  return false;
}

module.exports = { ipToInt, intToIp, parseCidr, totalAddresses, expand, inScope };
