'use strict';

const net = require('net');
const dns = require('dns').promises;
const { execFile } = require('child_process');
const { buildPingArgs, parsePing } = require('../probes/ping');
const { safeHost } = require('../probes/stats');

// Probe primitives for active discovery. TCP-connect and reverse-DNS are fully
// native and portable; ICMP echo goes through the system `ping`, the same
// machinery the ping probe uses. No nmap, nothing that sends a payload.

// Native TCP connect: resolves true if the port accepts a connection, false on
// refuse/timeout/error. Always tears the socket down.
function tcpConnect(host, port, { timeoutMs = 1000 } = {}) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (open) => { if (done) return; done = true; try { sock.destroy(); } catch { /* ignore */ } resolve(open); };
    const sock = net.createConnection({ host, port });
    sock.setTimeout(timeoutMs, () => finish(false));
    sock.on('connect', () => finish(true));
    sock.on('error', () => finish(false));
  });
}

async function reverseDns(host) {
  try {
    const names = await dns.reverse(host);
    return Array.isArray(names) && names[0] ? names[0] : null;
  } catch {
    return null;
  }
}

// ICMP echo, one packet, short deadline. Resolves:
//   true  — an echo reply came back;
//   false — ping ran and nothing answered;
//   null  — unknown: no `ping` on this host, or a run that produced nothing
//           readable (e.g. no permission). Liveness then rests on TCP alone,
//           exactly as it did before this probe existed.
//
// Why it matters: a PLC, RTU or IP camera commonly answers ping and exposes no
// TCP port on the default list, so a TCP-only sweep reported the device that
// the site most wanted found as "nothing there". Node core has no raw socket,
// so this uses the system `ping` — which is setuid/cap_net_raw on every
// mainstream OS, so no privilege is needed here.
//
// Windows `ping` counts "Destination host unreachable" — a reply from the
// local ROUTER — as a received packet, with 0% loss. Only a line carrying
// TTL= is an echo reply from the target itself, so that is what counts there.
//
// `exec`/`platform` are injectable so tests need no process.
function createIcmpProbe({ exec = execFile, platform = process.platform, timeoutMs = 1000 } = {}) {
  const deadlineSec = Math.max(1, Math.round(timeoutMs / 1000));
  let missing = false; // latched on ENOENT: a sweep must not spawn 65 536 failures
  return function icmpEcho(host) {
    const safe = safeHost(host);
    if (missing || !safe) return Promise.resolve(null);
    const args = buildPingArgs({ platform, count: 1, host: safe, deadlineSec });
    return new Promise((resolve) => {
      try {
        exec('ping', args, { timeout: deadlineSec * 1000 + 2000 }, (err, stdout, stderr) => {
          if (err && err.code === 'ENOENT') { missing = true; resolve(null); return; }
          const text = `${String(stdout || '')}\n${String(stderr || '')}`;
          const parsed = parsePing(text);
          if (!parsed) { resolve(err && err.killed ? false : null); return; }
          if (parsed.lossPct >= 100) { resolve(false); return; }
          resolve(platform === 'win32' ? /TTL=/i.test(text) : true);
        });
      } catch {
        resolve(null);
      }
    });
  };
}

// Kept for callers that want TCP-only liveness (and for older tests): always
// "unknown".
async function icmpUnsupported() { return null; }

module.exports = { tcpConnect, reverseDns, createIcmpProbe, icmpUnsupported };
