'use strict';

const { execFile } = require('child_process');
const net = require('net');
const { clampInt, round, safeHost } = require('./stats');
const { traceroute } = require('./traceroute');
const {
  HEADER_OVERHEAD, MSS_OVERHEAD, MIN_PACKET_SIZE, resolveFamily, pingCommand, findAddress,
} = require('./ipFamily');

// Path-MTU probe: finds the largest packet that survives the path from this
// agent to a target, per hop, and says WHY a smaller one is needed.
//
// The failure this exists for: a service connects and then loses data, because
// something on the path has a smaller MTU and the ICMP that would have said so
// is filtered. TCP completes its handshake with small packets, then stalls the
// moment a full-size segment goes out. Nothing in a latency or loss test sees
// it — the small probes all get through. That is why this measures BY SIZE.
//
// Three outcomes have to stay distinguishable, and the whole design is about
// not confusing them:
//
//   reduced     — a smaller MTU AND the router said so (ICMP frag-needed).
//                 Normal. Tunnels do this (IPsec/GRE/PPPoE) and PMTUD copes.
//   blackhole   — large packets vanish, small ones pass, no ICMP at all. This
//                 is the fault: PMTUD cannot work, so the sender never learns.
//   no_response — the hop does not answer ICMP at all. NOT a fault, and it must
//                 never be read as one; it just means this hop can't be measured.
//
// Ordinary packet loss is the fourth thing that must not be mistaken for an MTU
// limit, and `probes_per_size` is what separates them: a size counts as passing
// if ANY of its probes get through, so a lossy-but-unrestricted link still
// reports its true MTU instead of a fake ceiling.
//
// PER-HOP MEASUREMENT. A hop is measured by pinging the TARGET with the TTL
// limited to that hop, not by pinging the hop itself: that way the packet
// crosses exactly the links up to that hop, and a TTL-exceeded reply means the
// whole prefix of the path carried that size. The measured MTU is therefore
// monotonically non-increasing along the path, which is what makes
// `mtu_drop_at_hop` meaningful — and what lets each hop start its search from
// the previous hop's ceiling instead of from scratch (2 probes for a hop that
// adds no restriction, rather than a full binary search).
//
// `exec`, `platform`, `tracerouteFn`, `connectImpl` and `now` are injectable, so
// every test here runs against canned output without spawning a process or
// touching the network.

// Header sizes, minimums and the per-OS argv all live in
// [`ipFamily`](./ipFamily.js) — the one place that knows how IPv4 and IPv6
// differ. IPv6 has no don't-fragment bit (routers may not fragment it at all),
// so the "too big" answer arrives as ICMPv6 Packet Too Big instead of
// "fragmentation needed and DF set"; everything this probe concludes from that
// answer is identical either way.
const MAX_SIZE_CEILING = 9216; // jumbo frames
const DEFAULT_MAX_SIZE = 1500;
const MAX_HOPS_PROBED = 32;
// A whole-probe time budget. Without it a 30-hop path against a silent target
// is minutes of timeouts; hops past the budget are reported as `skipped` rather
// than silently missing, so the operator can see the run was cut short.
const DEFAULT_BUDGET_MS = 120000;

// What one ping told us. `outcome` is deliberately five-valued: "it failed" is
// not an answer here, since frag_needed and timeout mean opposite things.
//   reply         — the target answered
//   ttl_exceeded  — a router on the way answered; the packet got that far
//   frag_needed   — too big, and something said so (may carry the real MTU)
//   local_error   — too big for THIS host's own interface; never a path fault
//   tool_error    — `ping` itself refused to run: no permission for an ICMP
//                   socket, a flag this build does not take, a name that does
//                   not resolve. NOT a statement about the path.
//   timeout       — nothing came back
//
// `frag_needed` covers both protocols. IPv4 sends ICMP type 3 code 4,
// "fragmentation needed and DF set"; IPv6 sends ICMPv6 type 2, "Packet Too Big".
// They are the same event under two names — a router saying "this will not fit,
// here is what will" — and both are filtered by the same careless firewall rule,
// so the blackhole they leave behind is the same fault.
const OUTCOME = {
  REPLY: 'reply',
  TTL_EXCEEDED: 'ttl_exceeded',
  FRAG_NEEDED: 'frag_needed',
  LOCAL_ERROR: 'local_error',
  TOOL_ERROR: 'tool_error',
  TIMEOUT: 'timeout',
};

const HOP_STATUS = {
  OK: 'ok',
  REDUCED: 'reduced',
  BLACKHOLE: 'blackhole',
  NO_RESPONSE: 'no_response',
  SKIPPED: 'skipped',
};

// Parses one `ping` run, across Linux (iputils), macOS (BSD) and Windows.
//
// The ORDER of these tests is the whole correctness argument, because the
// strings overlap: macOS writes both a frag-needed and a TTL-exceeded notice as
// "36 bytes from <ip>: …", which also matches the success pattern, and Windows
// writes its TTL-exceeded as "Reply from …", which likewise does. So the
// specific verdicts are recognised first and the generic "something came back"
// last. Getting this backwards reports a blackhole as a success.
function parsePingProbe(text) {
  const s = String(text || '');

  // A local refusal: the size exceeds this host's own interface MTU, so nothing
  // was ever put on the wire. Checked first — it is the only outcome that says
  // nothing at all about the path.
  // Linux "ping: local error: message too long, mtu=1500" · macOS IPv4
  // "ping: sendto: Message too long" · macOS IPv6 "ping6: sendmsg: Message too
  // long" — three spellings of the same thing: the packet never left this host.
  if (/local error:\s*message too long/i.test(s)
    || /send(?:to|msg):\s*Message too long/i.test(s)
    || /^ping6?:.*Message too long/im.test(s)) {
    return { outcome: OUTCOME.LOCAL_ERROR, mtu: mtuIn(s), from: null, rttMs: null };
  }
  // IPv4: "Frag needed and DF set (mtu = 1420)" · macOS "frag needed and DF set
  // (MTU 1420)" · Windows "Packet needs to be fragmented but DF set."
  // IPv6: "Packet too big: mtu=1400" (Linux) · "Packet too big mtu = 1400" (BSD).
  if (/frag(?:mentation)?\s+needed/i.test(s)
    || /needs to be fragmented but DF set/i.test(s)
    || /packet too big/i.test(s)) {
    return { outcome: OUTCOME.FRAG_NEEDED, mtu: mtuIn(s), from: fromIn(s), rttMs: null };
  }
  // IPv4: "Time to live exceeded" · Windows "TTL expired in transit".
  // IPv6: Linux prints "Time exceeded: Hop limit", BSD "hop limit exceeded" —
  // neither contains the other's wording, so both spellings are listed.
  if (/time to live exceeded/i.test(s) || /time exceeded/i.test(s)
    || /hop limit exceeded/i.test(s) || /TTL expired in transit/i.test(s)) {
    return { outcome: OUTCOME.TTL_EXCEEDED, mtu: null, from: fromIn(s), rttMs: null };
  }
  if (/bytes from /i.test(s) || /Reply from .*bytes\s*=/i.test(s)) {
    return { outcome: OUTCOME.REPLY, mtu: null, from: fromIn(s), rttMs: rttIn(s) };
  }
  // `ping` complaining about itself, AFTER every real verdict has had its turn
  // (the local "message too long" above is also a `ping:` line, and it means
  // something quite different). A successful run prints no such line and
  // neither does a timeout, so this cannot swallow either.
  //
  // WHY THIS EXISTS. Without it every one of these fell through to TIMEOUT, and
  // a timeout at min_size reads as `no_response` — so an agent with no
  // permission to open an ICMP socket reported a blank path MTU and ok:true,
  // indistinguishable from a target that simply does not answer. The probe
  // claimed to have measured something it never attempted.
  const complaint = s.match(/^\s*(ping6?|traceroute6?):\s*(.+)$/im);
  if (complaint) {
    return { outcome: OUTCOME.TOOL_ERROR, mtu: null, from: null, rttMs: null, reason: complaint[2].trim().slice(0, 120) };
  }
  return { outcome: OUTCOME.TIMEOUT, mtu: null, from: null, rttMs: null };
}

// "mtu = 1420" / "MTU 1420" / "mtu=1500" — the next-hop MTU a router volunteers.
// Windows never reports it, so null is a normal answer, not a parse failure.
function mtuIn(s) {
  const m = s.match(/\bmtu\s*[=:]?\s*(\d+)/i);
  const n = m ? Number(m[1]) : null;
  return Number.isInteger(n) && n > 0 ? n : null;
}

// Who answered. Linux "From 198.51.100.7 …", macOS "36 bytes from 198.51.100.7: …",
// Windows "Reply from 192.0.2.1: …", and the IPv6 forms of all three.
//
// The address is pulled out by `findAddress`, which validates with `net.isIP`
// rather than matching a shape — but only from the LINE that names a responder.
// Run over the whole output it would return the address in ping's own banner
// ("PING 2001:db8::40 …"), i.e. the target, and confidently report the
// destination as the router that dropped the packet.
function fromIn(s) {
  for (const line of String(s).split('\n')) {
    if (!/^\s*From\s/i.test(line) && !/bytes from /i.test(line) && !/Reply from /i.test(line)) continue;
    const ip = findAddress(line);
    if (ip) return ip;
  }
  return null;
}

// "time=12.3 ms" / "time=12ms" / Windows "time<1ms".
function rttIn(s) {
  const m = s.match(/time\s*([<=])\s*([\d.]+)\s*ms/i);
  if (!m) return null;
  return m[1] === '<' ? 0.5 : round(Number(m[2]));
}

// Normalizes the operator's spec. Every bound is enforced here as well as on the
// server, because the agent trusts nothing it is handed.
function normalizeSpec(spec, host) {
  const s = spec && typeof spec === 'object' ? spec : {};
  // A literal IPv6 target selects IPv6 on its own, so an operator who types an
  // address does not also have to remember a parameter.
  const ipVersion = resolveFamily(s.ip_version ?? s.ipVersion, host);
  const floor = MIN_PACKET_SIZE[ipVersion];
  const maxSize = clampInt(s.max_size ?? s.maxSize, DEFAULT_MAX_SIZE, floor, MAX_SIZE_CEILING);
  const minSize = clampInt(s.min_size ?? s.minSize, floor, floor, maxSize);
  return {
    ipVersion,
    minSize,
    maxSize,
    perHop: (s.per_hop ?? s.perHop) !== false,
    probesPerSize: clampInt(s.probes_per_size ?? s.probesPerSize, 3, 1, 10),
    timeoutMs: clampInt(s.timeout_ms ?? s.timeoutMs, 1000, 100, 10000),
    tcpPort: tcpPortOf(s.tcp_port ?? s.tcpPort),
    budgetMs: clampInt(s.budget_ms ?? s.budgetMs, DEFAULT_BUDGET_MS, 5000, 600000),
  };
}

function tcpPortOf(v) {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isInteger(n) && n >= 1 && n <= 65535 ? n : null;
}

function failure(target, error, extra = {}) {
  return {
    type: 'path_mtu',
    target,
    ok: false,
    error: String(error),
    ip_version: 4,
    path_mtu: null,
    blackhole_detected: false,
    icmp_frag_needed_seen: false,
    mtu_drop_at_hop: null,
    hops: [],
    mss_supported: false,
    mss_observed: null,
    recommended_mss: null,
    duration_ms: 0,
    ...extra,
  };
}

async function pathMtuProbe(spec, {
  exec = execFile,
  platform = process.platform,
  tracerouteFn = traceroute,
  connectImpl = net.connect,
  now = () => Date.now(),
} = {}) {
  const rawHost = String((spec && (spec.host || spec.target)) || '').trim();
  const host = safeHost(rawHost);
  if (!host) return failure(rawHost, 'invalid host');

  const opts = normalizeSpec(spec, host);
  const startedAt = now();

  // `fragCount` is a COUNTER, not a flag, so each measurement can ask whether a
  // frag-needed arrived DURING it. A flag would leak the end-to-end run's
  // frag-needed into the first hop's verdict and turn a plain `reduced` into a
  // reported blackhole — the one mistake this whole probe exists to avoid.
  const state = { fragCount: 0, missing: null, toolError: null };

  // Runs one probe of one size, optionally TTL-limited. `probes_per_size`
  // separates an MTU limit from ordinary loss: a size passes if ANY attempt
  // gets through. Only a TIMEOUT is retried — frag-needed and a local error are
  // already definitive answers, and re-asking costs a second of nothing.
  async function probeSize(size, ttl) {
    const payload = size - HEADER_OVERHEAD[opts.ipVersion];
    let last = { outcome: OUTCOME.TIMEOUT, mtu: null, from: null, rttMs: null };
    for (let i = 0; i < opts.probesPerSize; i += 1) {
      const cmd = pingCommand({ platform, family: opts.ipVersion, payload, timeoutMs: opts.timeoutMs, ttl, host });
      // eslint-disable-next-line no-await-in-loop
      const run = await runPing(exec, cmd, opts.timeoutMs);
      if (run.missing) { state.missing = cmd.bin; return { pass: false, ...last, outcome: OUTCOME.TIMEOUT }; }
      last = parsePingProbe(run.text);
      if (last.outcome === OUTCOME.FRAG_NEEDED) { state.fragCount += 1; break; }
      if (last.outcome === OUTCOME.LOCAL_ERROR) break;
      // The tool refused. Retrying cannot change that, and continuing would
      // turn a setup problem into a fabricated measurement.
      if (last.outcome === OUTCOME.TOOL_ERROR) { state.toolError = state.toolError || last.reason; break; }
      if (last.outcome === OUTCOME.REPLY || last.outcome === OUTCOME.TTL_EXCEEDED) break;
    }
    const pass = last.outcome === OUTCOME.REPLY || last.outcome === OUTCOME.TTL_EXCEEDED;
    return { pass, ...last };
  }

  // Largest passing size in [lo, hi], given that `lo` passes and `hi` does not.
  // Byte-exact: an MTU is a byte count, and rounding it up is how you ship a
  // recommended MSS that still does not fit.
  async function bisect(lo, hi, ttl, probe) {
    let good = lo;
    let bad = hi;
    while (bad - good > 1) {
      const mid = Math.floor((good + bad) / 2);
      // eslint-disable-next-line no-await-in-loop
      const r = await probe(mid);
      if (r.pass) good = mid; else bad = mid;
    }
    return good;
  }

  // Measures one point on the path (a TTL, or the target when ttl is null),
  // searching no higher than `ceiling` — the MTU already proven upstream, since
  // a later hop can never carry more than an earlier one did.
  async function measure(ttl, ceiling) {
    const fragBefore = state.fragCount;
    const seen = () => state.fragCount > fragBefore;
    // Did an oversized packet actually go out and never come back? That — not
    // merely "the MTU is lower than max_size" — is what a blackhole IS. A local
    // refusal never reached the wire, so it can lower the measured MTU without
    // ever being a path fault, and a router's frag-needed is the opposite of a
    // blackhole. Only a genuine silent drop counts.
    let silentDrop = false;
    // A local refusal also means the ceiling we were searching under is this
    // HOST's, not the path's — the run has to be re-based on it, or every hop
    // downstream gets blamed for the local NIC.
    let localLimited = false;
    const probe = async (size) => {
      const r = await probeSize(size, ttl);
      if (!r.pass && r.outcome === OUTCOME.TIMEOUT) silentDrop = true;
      if (r.outcome === OUTCOME.LOCAL_ERROR) localLimited = true;
      return r;
    };
    // The control probe comes FIRST and decides whether anything else means
    // anything: if the smallest packet gets no answer, this point is silent, and
    // every larger size would "fail" for a reason that has nothing to do with size.
    const control = await probeSize(opts.minSize, ttl);
    if (!control.pass) return { silent: true, maxMtu: null, ip: control.from, fragSeen: seen(), silentDrop: false, localLimited: false };
    const hi = Math.max(opts.minSize, Math.min(ceiling, opts.maxSize));
    const done = (maxMtu, ip) => ({ silent: false, maxMtu, ip, fragSeen: seen(), silentDrop, localLimited });
    if (hi <= opts.minSize) return done(opts.minSize, control.from);
    const top = await probe(hi);
    if (top.pass) return done(hi, top.from || control.from);
    // A router that volunteered its next-hop MTU has already answered the
    // question — believe it rather than spending ten more probes rediscovering
    // it, but only when it is inside the window we were searching.
    if (top.mtu && top.mtu > opts.minSize && top.mtu < hi) {
      return done(top.mtu, top.from || control.from);
    }
    const found = await bisect(opts.minSize, hi, ttl, probe);
    return done(found, top.from || control.from);
  }

  // --------------------------------------------------------------- the path
  let hopList = [];
  if (opts.perHop) {
    const tr = await tracerouteFn(
      { host, maxHops: MAX_HOPS_PROBED, queries: 1, ip_version: opts.ipVersion },
      { exec, platform },
    );
    hopList = (tr && Array.isArray(tr.hops) ? tr.hops : []).filter((h) => h && h.ip).slice(0, MAX_HOPS_PROBED);
  }

  // End-to-end first: it is the number the operator actually asked for, and the
  // one that must exist even when the budget runs out mid-path.
  const endToEnd = await measure(null, opts.maxSize);
  if (state.missing) return failure(host, `${state.missing} not installed`, { ip_version: opts.ipVersion });
  // A tool that would not run is reported as a failure to MEASURE, never as a
  // path with no answer. The operator gets ping's own words back.
  if (state.toolError) return failure(host, `ping failed: ${state.toolError}`, { ip_version: opts.ipVersion });

  const hops = [];
  // When this host's own interface capped the run, that cap — not max_size — is
  // what the path was actually asked to carry, so a hop that carries all of it
  // is `ok` rather than `reduced`.
  const effectiveMax = endToEnd.localLimited && endToEnd.maxMtu != null ? endToEnd.maxMtu : opts.maxSize;
  let ceiling = effectiveMax;
  // The status carried forward: once the path is restricted, a later hop that
  // adds no NEW restriction inherits why, instead of being re-diagnosed as a
  // blackhole because it never had a chance to emit its own frag-needed.
  let inherited = HOP_STATUS.OK;
  let budgetSpent = false;
  for (const h of hopList) {
    if (budgetSpent || now() - startedAt > opts.budgetMs) {
      budgetSpent = true;
      hops.push({ hop: h.hop, ip: h.ip, max_mtu: null, status: HOP_STATUS.SKIPPED });
      continue;
    }
    // eslint-disable-next-line no-await-in-loop
    const m = await measure(h.hop, ceiling);
    if (m.silent) {
      hops.push({ hop: h.hop, ip: h.ip, max_mtu: null, status: HOP_STATUS.NO_RESPONSE });
      continue;
    }
    // A NEW restriction at this hop is this hop's to explain: with an ICMP
    // frag-needed it is a normal, PMTUD-visible reduction; without one the large
    // packets went into a hole and no sender will ever be told. No new
    // restriction means the hop simply carries what it was handed, so it
    // inherits the upstream verdict rather than being re-diagnosed.
    // A NEW restriction with an ICMP frag-needed is a normal, PMTUD-visible
    // reduction; one where the large packets simply went silent is the
    // blackhole. Anything else that lowered the ceiling without a silent drop
    // (a local refusal) is not this hop's doing either, so it reads as reduced.
    const status = m.maxMtu < ceiling
      ? (m.silentDrop && !m.fragSeen ? HOP_STATUS.BLACKHOLE : HOP_STATUS.REDUCED)
      : inherited;
    hops.push({ hop: h.hop, ip: h.ip, max_mtu: m.maxMtu, status });
    ceiling = m.maxMtu;
    inherited = status;
  }

  // The first hop that carries less than the hop before it — where the path
  // narrows, which is the router an operator has to go and look at.
  let dropAt = null;
  let prev = effectiveMax;
  for (const h of hops) {
    if (h.max_mtu == null) continue;
    if (h.max_mtu < prev) { dropAt = h.hop; break; }
    prev = h.max_mtu;
  }

  // End-to-end wins as the path MTU: the hop list can be truncated, filtered or
  // empty, and the number the applications live with is the one measured to the
  // target itself.
  const measuredHops = hops.filter((h) => h.max_mtu != null).map((h) => h.max_mtu);
  const pathMtu = endToEnd.silent
    ? (measuredHops.length ? Math.min(...measuredHops) : null)
    : endToEnd.maxMtu;

  // A blackhole anywhere is a blackhole: either a hop was classified as one, or
  // the end-to-end run itself lost the large packets with nothing to explain why.
  const blackhole = hops.some((h) => h.status === HOP_STATUS.BLACKHOLE)
    || (!endToEnd.silent && endToEnd.maxMtu != null && endToEnd.maxMtu < opts.maxSize
      && !endToEnd.fragSeen && endToEnd.silentDrop && !endToEnd.localLimited);

  const mss = await measureMss({ host, port: opts.tcpPort, platform, exec, connectImpl, timeoutMs: opts.timeoutMs });

  return {
    type: 'path_mtu',
    target: host,
    // The probe SUCCEEDED — it measured what it set out to measure. A blackhole
    // is a finding about the path, not a failure of the agent, and reporting it
    // as ok:false would make the fleet-health verdict count this target as
    // unreachable and take the agent's status down with it.
    ok: true,
    ip_version: opts.ipVersion,
    path_mtu: pathMtu,
    blackhole_detected: blackhole,
    icmp_frag_needed_seen: state.fragCount > 0,
    mtu_drop_at_hop: dropAt,
    hops,
    mss_supported: mss.supported,
    mss_observed: mss.observed,
    recommended_mss: pathMtu != null ? pathMtu - MSS_OVERHEAD[opts.ipVersion] : null,
    duration_ms: Math.max(0, now() - startedAt),
  };
}

// One ping run. stderr is joined in because macOS reports the local
// "Message too long" refusal there, and that refusal is a verdict. The binary
// comes from the command builder — IPv6 on macOS is a different program.
function runPing(exec, { bin, args }, timeoutMs) {
  return new Promise((resolve) => {
    exec(bin, args, { timeout: timeoutMs + 2000 }, (err, stdout, stderr) => {
      resolve({
        missing: !!(err && err.code === 'ENOENT'),
        text: `${stdout || ''}\n${stderr || ''}`,
      });
    });
  });
}

// Optional MSS check (Linux only). Opens a TCP connection and reads the MSS the
// kernel negotiated for it out of `ss -tin`. An MSS larger than the measured
// path allows is the direct, observable evidence that MSS clamping is missing —
// the connection will establish and then stall on its first full-size segment.
//
// The socket is matched on its own LOCAL PORT, not on the target: `ss` prints
// addresses, so a hostname would never match, and resolving it here would be a
// second name lookup that could legitimately disagree with the first.
async function measureMss({ host, port, platform, exec, connectImpl, timeoutMs }) {
  if (!port) return { supported: platform === 'linux', observed: null };
  if (platform !== 'linux') return { supported: false, observed: null };
  let socket = null;
  try {
    const localPort = await new Promise((resolve, reject) => {
      socket = connectImpl({ host, port }, () => resolve(socket.localPort));
      socket.setTimeout(timeoutMs, () => reject(new Error('connect timed out')));
      socket.on('error', reject);
    });
    if (!localPort) return { supported: true, observed: null };
    const text = await new Promise((resolve) => {
      exec('ss', ['-tin'], { timeout: 5000 }, (err, stdout) => resolve(err ? '' : String(stdout || '')));
    });
    return { supported: true, observed: parseSsMss(text, localPort) };
  } catch {
    return { supported: true, observed: null };
  } finally {
    try { if (socket) socket.destroy(); } catch { /* already gone */ }
  }
}

// Pulls `mss:<n>` for the socket bound to `localPort` out of `ss -tin`, whose
// per-socket detail sits on the line AFTER the address line.
function parseSsMss(text, localPort) {
  const lines = String(text || '').split('\n');
  const re = new RegExp(`:${localPort}\\s`);
  for (let i = 0; i < lines.length; i += 1) {
    if (!re.test(lines[i])) continue;
    const block = `${lines[i]} ${lines[i + 1] || ''}`;
    const m = block.match(/\bmss:(\d+)/);
    if (m) return Number(m[1]);
  }
  return null;
}

module.exports = { pathMtuProbe, parsePingProbe, parseSsMss, OUTCOME, HOP_STATUS, MAX_SIZE_CEILING };
