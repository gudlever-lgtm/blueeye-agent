'use strict';

const net = require('net');

// Everything the active probes need to know about the difference between IPv4
// and IPv6, in one place.
//
// WHY THIS EXISTS. The difference is not one flag. It is a header size, a
// minimum packet size, a different address syntax in every tool's output, a
// different spelling for "limit the hop count" on every OS, and — for the
// path-MTU probe — a fundamentally different fragmentation model. Before this
// module those facts were scattered across four probe files as inline constants
// and regexes, each one quietly assuming IPv4, which is why the traceroute
// parser had read only IPv4 hop addresses since it was written: nobody could see
// the assumption because it was never written down in one piece.
//
// THE ONE THING WORTH KNOWING. **IPv6 has no don't-fragment bit.** Routers are
// forbidden from fragmenting IPv6 in transit — RFC 8200 moved fragmentation to
// the sender — so "don't fragment" is the permanent, built-in behaviour and
// there is no flag to set. A packet too large for a link produces ICMPv6 Packet
// Too Big (type 2), which is the exact analogue of IPv4's "fragmentation needed
// and DF set" (type 3 code 4). Both carry the next-hop MTU; both are routinely
// filtered; a filtered one is a PMTUD blackhole either way. So the path-MTU
// probe's whole argument transfers to IPv6 unchanged — only the argv and the
// message text differ, and both of those live here.
//
// PURE: no I/O, no process spawning. Command builders return `{ bin, args }`
// for a caller to run, which is what makes every one of them testable by
// comparing an array.

const FAMILIES = Object.freeze([4, 6]);

// Bytes between the IP packet size an operator configures (what an MTU is) and
// the payload length `ping` takes on its `-s`/`-l` flag.
//   IPv4: 20 IP + 8 ICMP · IPv6: 40 IPv6 + 8 ICMPv6
const HEADER_OVERHEAD = Object.freeze({ 4: 28, 6: 48 });

// TCP MSS = MTU minus the IP and TCP headers.
const MSS_OVERHEAD = Object.freeze({ 4: 40, 6: 60 });

// The minimum a conforming stack must carry, so there is nothing to learn below
// it: RFC 791 §3.2 for IPv4, RFC 8200 §5 for IPv6.
const MIN_PACKET_SIZE = Object.freeze({ 4: 576, 6: 1280 });

// The family of a literal address, or null for a hostname (which could resolve
// to either, so guessing would be a lie).
function familyOf(host) {
  const v = net.isIP(String(host == null ? '' : host).trim());
  return v === 4 || v === 6 ? v : null;
}

// The family a probe should run as. An explicit request wins; otherwise a
// literal target names its own family, and only a hostname falls back to IPv4.
// That fallback is why an operator can type an IPv6 literal and simply get IPv6
// without also remembering to set a parameter.
function resolveFamily(requested, host) {
  const n = Number(requested);
  if (n === 4 || n === 6) return n;
  return familyOf(host) || 4;
}

// Strips what a tool prints AROUND an address: parentheses (`traceroute` without
// `-n`), brackets (`[2001:db8::1]`), and trailing punctuation. A trailing colon
// is NOT stripped — `2001:db8::` is a legal address and chopping it would turn a
// valid hop into a different one.
function unwrap(token) {
  let s = String(token || '').trim();
  s = s.replace(/^[([]+/, '').replace(/[)\],]+$/, '');
  return s;
}

// The first IP address — v4 or v6 — in one line of tool output, or null.
//
// Token-based, using Node's own `net.isIP`, rather than a regex for the address
// syntax. An IPv6 regex loose enough to match every legal form (`::1`,
// `::ffff:192.0.2.1`, compressed runs) is also loose enough to match fragments
// of surrounding text, and an address parser that is nearly right is worse than
// none: it yields a plausible-looking hop that was never on the path. `isIP` is
// exact by construction.
//
// A `%zone` suffix (`fe80::1%eth0`) is dropped — the zone is local to the host
// that printed it and means nothing to a server storing the address.
//
// The embedded-IPv4 fallback at the end preserves the behaviour this replaced,
// for any layout that glues an address to other characters.
function findAddress(line) {
  const text = String(line == null ? '' : line);
  for (const token of text.split(/\s+/)) {
    const bare = unwrap(token);
    if (!bare) continue;
    const zoneless = bare.includes('%') ? bare.slice(0, bare.indexOf('%')) : bare;
    if (net.isIP(zoneless)) return zoneless;
    // A trailing colon is a separator in "1400 bytes from 2001:db8::7: icmp_seq=1"
    // and an address character in "2001:db8::". It cannot be stripped blindly, so
    // the full token is tested FIRST and only a failure is retried without it.
    if (zoneless.endsWith(':')) {
      const trimmed = zoneless.slice(0, -1);
      if (net.isIP(trimmed)) return trimmed;
    }
  }
  const embedded = text.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
  return embedded ? embedded[1] : null;
}

// argv for one sized ping, optionally limited to `ttl` hops.
//
// The flags differ by more than spelling, which is the entire reason this is one
// table and not conditionals sprinkled through the probes:
//
//   Linux    -M do sets DF (v4) / refuses local fragmentation (v6)
//            -s payload · -W per-reply wait in SECONDS · -t TTL or hop limit
//   macOS    ping (v4): -D sets DF · -s · -t WHOLE-RUN timeout in seconds · -m TTL
//            ping6 (v6): no DF flag exists · -s · -W per-reply wait in
//            MILLISECONDS · -h hop limit
//   Windows  -f sets DF and is IPv4-ONLY · -l payload · -w wait in
//            MILLISECONDS · -i TTL or hop limit
//
// macOS `-t` meaning a timeout while Linux `-t` means a TTL, and macOS `-W`
// being milliseconds while Linux `-W` is seconds, are exactly the collisions
// that make a command line copied between platforms measure the wrong thing and
// report it confidently.
function pingCommand({ platform, family, payload, timeoutMs, ttl = null, host }) {
  const secs = Math.max(1, Math.round(timeoutMs / 1000));
  const v6 = family === 6;

  if (platform === 'win32') {
    const args = [v6 ? '-6' : '-4'];
    // `-f` is IPv4-only on Windows. It is also unnecessary on IPv6, where no
    // router may fragment in the first place.
    if (!v6) args.push('-f');
    args.push('-l', String(payload), '-n', '1', '-w', String(timeoutMs));
    if (ttl) args.push('-i', String(ttl));
    // Windows `ping` has no `--` end-of-options marker; safeHost() has already
    // rejected any leading-`-` target, which is what closes option injection.
    args.push(host);
    return { bin: 'ping', args };
  }

  if (platform === 'darwin') {
    if (v6) {
      // Separate binary on macOS, with its own flag letters. No DF flag: IPv6
      // forbids in-transit fragmentation, so an oversized packet already comes
      // back as ICMPv6 Packet Too Big without asking.
      const args = ['-s', String(payload), '-c', '1', '-W', String(timeoutMs)];
      if (ttl) args.push('-h', String(ttl));
      args.push('--', host);
      return { bin: 'ping6', args };
    }
    const args = ['-D', '-s', String(payload), '-c', '1', '-t', String(secs)];
    if (ttl) args.push('-m', String(ttl));
    args.push('--', host);
    return { bin: 'ping', args };
  }

  const args = [v6 ? '-6' : '-4', '-M', 'do', '-s', String(payload), '-c', '1', '-W', String(secs)];
  if (ttl) args.push('-t', String(ttl));
  args.push('--', host);
  return { bin: 'ping', args };
}

// argv candidates for a traceroute, in the order to try them.
//
// A LIST, because IPv6 tracing is split across two binaries in the field and
// which one exists depends on the distribution: `traceroute -6` on most modern
// Linux, the separate `traceroute6` on macOS and on older or minimal installs.
// Trying both is the difference between "IPv6 paths work" and "IPv6 paths work
// on the machines the author happened to have". IPv4 returns a single candidate,
// so nothing about the existing path changes.
function tracerouteCommands({ platform, family, host, maxHops, queries }) {
  const v6 = family === 6;
  if (platform === 'win32') {
    return [{ bin: 'tracert', args: [...(v6 ? ['-6'] : ['-4']), '-d', '-h', String(maxHops), host] }];
  }
  const unix = (bin, extra) => ({
    bin,
    // `--` ends option parsing so the host can never be read as a flag.
    args: ['-n', ...extra, '-m', String(maxHops), '-q', String(queries), '-w', '2', '--', host],
  });
  if (!v6) return [unix('traceroute', [])];
  return platform === 'darwin'
    ? [unix('traceroute6', []), unix('traceroute', ['-6'])]
    : [unix('traceroute', ['-6']), unix('traceroute6', [])];
}

module.exports = {
  FAMILIES,
  HEADER_OVERHEAD,
  MSS_OVERHEAD,
  MIN_PACKET_SIZE,
  familyOf,
  resolveFamily,
  findAddress,
  pingCommand,
  tracerouteCommands,
};
