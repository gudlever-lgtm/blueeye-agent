'use strict';

const { execFile } = require('child_process');
const { clampInt, safeHost } = require('./stats');
const { parseTraceroute } = require('./traceroute');

// TCP path probe: traces the route to host:port with TCP SYN packets instead of
// the ICMP/UDP probes plain `traceroute` sends.
//
// Why it exists: a firewall or transit provider that rate-limits or drops
// ICMP/UDP makes an ordinary traceroute go dark long before the destination,
// while the traffic the service actually uses (a TCP session to :443) gets
// through fine. Tracing with SYNs follows the path the real traffic takes, so
// the per-hop numbers describe the connection the user is complaining about.
//
// Two binaries can do this, and both print the same hop layout as traceroute,
// so [`parseTraceroute`](./traceroute.js) does the parsing for all three:
//   1. `tcptraceroute` — purpose-built, port is a POSITIONAL arg after the host.
//   2. `traceroute -T -p <port>` — the same thing from the traceroute package,
//      which is already a prerequisite for the ICMP probe. Used when
//      `tcptraceroute` is absent, so on most hosts this probe works with nothing
//      installed; when BOTH are missing the reported reason names
//      `tcptraceroute`, which is the tool the server's auto-install offers.
//
// Both need raw sockets, i.e. root (the agent's systemd unit runs as root) or
// CAP_NET_RAW. A permission failure is reported as its own reason rather than an
// empty path, so the dashboard can say what to fix.
//
// Result shape matches the traceroute probe — `target` is `host:port` so a TCP
// trace and an ICMP trace to the same host stay separate series on the server.
// `exec` is injectable for tests.
function tcptraceroute(spec, { exec = execFile } = {}) {
  const rawHost = String((spec && (spec.host || spec.target)) || '').trim();
  const host = safeHost(rawHost);
  const port = Number(spec && spec.port !== undefined ? spec.port : 443);
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
    const shown = `${rawHost}:${spec && spec.port !== undefined ? spec.port : 443}`;
    return Promise.resolve({
      type: 'tcptraceroute', target: shown, ok: false, port: null, hopCount: 0, hops: [],
      error: host ? 'invalid port' : 'invalid host',
    });
  }
  const maxHops = clampInt(spec.maxHops, 20, 1, 40);
  const queries = clampInt(spec.queries, 3, 1, 10);
  const target = `${host}:${port}`;

  // `--` ends option parsing so a target can never be read as a flag; safeHost()
  // has already rejected a leading `-`, this is the belt-and-braces half.
  const attempts = [
    { bin: 'tcptraceroute', args: ['-n', '-q', String(queries), '-m', String(maxHops), '-w', '2', '--', host, String(port)] },
    { bin: 'traceroute', args: ['-n', '-T', '-p', String(port), '-m', String(maxHops), '-q', String(queries), '-w', '2', '--', host] },
  ];

  return runFirstAvailable(exec, attempts).then((run) => {
    const hops = parseTraceroute(run.stdout, queries);
    if (hops.length > 0) return { type: 'tcptraceroute', target, port, ok: true, hopCount: hops.length, queries, hops };
    return {
      type: 'tcptraceroute', target, port, ok: false, hopCount: 0, queries, hops: [],
      error: failureReason(run),
    };
  });
}

// Runs the candidates in order, stopping at the first one that EXISTS. A missing
// binary (ENOENT) falls through to the next; every other outcome — including a
// non-zero exit — belongs to the binary that ran and is returned as-is, since
// only the caller can tell "no route" from "no permission".
async function runFirstAvailable(exec, attempts) {
  let last = null;
  for (const attempt of attempts) {
    // eslint-disable-next-line no-await-in-loop
    const run = await runOnce(exec, attempt);
    if (run.err && run.err.code === 'ENOENT') { last = run; continue; }
    return run;
  }
  // Nothing was installed: report against the FIRST candidate, the one the
  // server's install-tool allowlist can actually fix.
  return { ...last, bin: attempts[0].bin, missing: true };
}

function runOnce(exec, { bin, args }) {
  return new Promise((resolve) => {
    exec(bin, args, { timeout: 60000 }, (err, stdout, stderr) => {
      resolve({ bin, err: err || null, stdout: String(stdout || ''), stderr: String(stderr || '') });
    });
  });
}

// Explains an empty path. The ordering matters: a permission failure also exits
// non-zero, so it has to be recognised before the generic message.
function failureReason(run) {
  const { bin, err, stderr } = run;
  if (run.missing) return `${bin} not installed`;
  if (err && err.killed) return `${bin} timed out`;
  const s = String(stderr || '').toLowerCase();
  if (/permission denied|must be root|operation not permitted|not permitted|raw socket/.test(s)) {
    return `${bin} needs root (raw socket)`;
  }
  const line = String((err && err.message) || stderr || 'no hops returned').split('\n')[0].trim();
  return line.slice(0, 120) || 'no hops returned';
}

module.exports = { tcptraceroute };
