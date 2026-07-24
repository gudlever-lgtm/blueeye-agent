'use strict';

const net = require('net');
const dns = require('dns').promises;

// Native Node probe primitives for active discovery. NO external binary — no
// nmap, no `ping`. TCP-connect and reverse-DNS are fully native and portable.

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

// Native ICMP echo needs a raw socket (CAP_NET_RAW / root) that Node core does
// NOT expose, and shelling out to `ping` is forbidden. So the default ICMP probe
// is UNSUPPORTED: it returns null (unknown), and liveness falls back to the TCP
// connect probes. A privileged deployment can inject a raw-socket implementation
// via the scanner's `icmpProbe` option without touching the engine.
async function icmpUnsupported() { return null; }

module.exports = { tcpConnect, reverseDns, icmpUnsupported };
