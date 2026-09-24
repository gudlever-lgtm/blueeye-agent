'use strict';

const { parseCidr, totalAddresses, expand, inScope } = require('./cidr');
const { tcpConnect, reverseDns, createIcmpProbe } = require('./probes');
const { createRateLimiter } = require('./rateLimiter');

// Scoped active-discovery scanner. Given a list of admin-configured CIDRs, it
// probes ONLY addresses inside that scope — ICMP echo (one packet via the
// system ping; injectable), TCP connect on a small port list, reverse DNS — and
// returns the live hosts as discovery candidates. Rate-limited. Never expands
// scope.
//
// Refuses (throws {code}) when scope is empty/invalid or exceeds the address cap
// — checked BEFORE any address is enumerated or probed.

// The IT ports, then the OT/ICS ones: a PLC or RTU typically exposes nothing
// on 22/80/443 and would otherwise be invisible to the sweep.
//   102 S7comm (Siemens) · 502 Modbus/TCP · 2404 IEC 60870-5-104
//   20000 DNP3 · 44818 EtherNet/IP · 4840 OPC UA
// BACnet (47808) is UDP-only, so a TCP connect can never find it; it is left
// out rather than listed as a port that always reads "closed".
// A connect-and-close sends no application bytes, so none of these is asked
// to do anything — the same as the IT ports.
const DEFAULT_PORTS = [22, 80, 161, 443, 3389, 102, 502, 2404, 20000, 44818, 4840];
const DEFAULT_PORT_CONCURRENCY = 4;

class DiscoveryScopeError extends Error {
  constructor(code, message) { super(message); this.code = code; this.name = 'DiscoveryScopeError'; }
}

function validateScope({ cidrs, addressCap }) {
  const list = Array.isArray(cidrs) ? cidrs.filter((c) => String(c).trim()) : [];
  if (list.length === 0) throw new DiscoveryScopeError('scope_unconfigured', 'Discovery scope is not configured');
  const { count, cidrs: parsed, invalid } = totalAddresses(list);
  if (invalid.length) throw new DiscoveryScopeError('scope_invalid', `Invalid CIDR(s): ${invalid.join(', ')}`);
  if (count > addressCap) throw new DiscoveryScopeError('scope_too_large', `Scope covers ${count} addresses, exceeds cap ${addressCap}`);
  return { parsed, count };
}

function createScanner({
  tcpProbe = tcpConnect,
  icmpProbe = createIcmpProbe(),
  dnsReverse = reverseDns,
  ports = DEFAULT_PORTS,
  tcpTimeoutMs = 1000,
  // How many of ONE address's ports are tried at once. Sequential, a silent
  // address cost one full connect timeout per port — ~11 s with the default
  // list; four at a time it is ~3 s. Bounded rather than all-at-once so a
  // sweep never looks like a SYN burst to the address it is asking about.
  portConcurrency = DEFAULT_PORT_CONCURRENCY,
} = {}) {
  // Scan the configured scope. `rateLimiter` may be injected (tests); otherwise
  // one is built from `ratePerSec`. Returns { candidates, probed, addresses }.
  async function scan({ cidrs, addressCap = 65536, ratePerSec = 50, rateLimiter = null, portList = ports } = {}) {
    const { parsed, count } = validateScope({ cidrs, addressCap });
    const limiter = rateLimiter || createRateLimiter({ ratePerSec });
    // Concurrent port probes take their grants ONE AT A TIME, in order. The
    // limiter computes each wait from the previous grant, so two callers
    // waiting on it together would both wake at the same slot and the rate
    // would silently double. Queuing the acquires keeps "N probes per second"
    // exactly what it was when the sweep was sequential — what changed is how
    // many connects may be waiting on their timeout at once, not how fast new
    // ones are sent.
    let grantChain = Promise.resolve();
    const acquire = () => {
      const next = grantChain.then(() => limiter.acquire());
      grantChain = next.catch(() => {});
      return next;
    };
    const width = Math.max(1, Math.floor(Number(portConcurrency)) || 1);
    const probePorts = Array.isArray(portList) && portList.length ? portList : DEFAULT_PORTS;

    const candidates = [];
    const probed = [];
    for (const p of parsed) {
      for (const ip of expand(p)) {
        // Hard scope guard — a target outside the configured CIDRs is never probed.
        if (!inScope(ip, parsed)) continue;

        await acquire(); // eslint-disable-line no-await-in-loop
        probed.push(ip);
        // The echo runs WHILE the ports are tried rather than before them: a
        // silent address costs its ping deadline once, not on top of every
        // port's timeout. A probe that throws is "unknown", never fatal.
        const icmpP = Promise.resolve().then(() => icmpProbe(ip)).catch(() => null);

        const openPorts = await sweepPorts(ip, probePorts, width, acquire); // eslint-disable-line no-await-in-loop
        const icmp = await icmpP; // eslint-disable-line no-await-in-loop

        const alive = icmp === true || openPorts.length > 0;
        if (!alive) continue;

        await acquire(); // eslint-disable-line no-await-in-loop
        const hostname = await dnsReverse(ip); // eslint-disable-line no-await-in-loop
        candidates.push({ ip, hostname: hostname || null, openPorts, icmp: icmp === true });
      }
    }
    return { candidates, probed, addresses: count };
  }

  // Tries one address's ports, at most `width` in flight, each started only
  // once the rate limiter grants it. Ports are STARTED in list order (a worker
  // takes the next port, then waits for its grant in the queue), and the open
  // ones come back in list order whatever order their connects finished in. A
  // probe that throws counts as closed — one bad port is not a failed address.
  async function sweepPorts(ip, list, width, acquire) {
    const open = new Array(list.length).fill(false);
    let next = 0;
    async function worker() {
      while (next < list.length) {
        const i = next;
        next += 1;
        await acquire(); // eslint-disable-line no-await-in-loop
        try {
          open[i] = Boolean(await tcpProbe(ip, list[i], { timeoutMs: tcpTimeoutMs })); // eslint-disable-line no-await-in-loop
        } catch {
          open[i] = false;
        }
      }
    }
    await Promise.all(Array.from({ length: Math.min(width, list.length) }, worker));
    return list.filter((_, i) => open[i]);
  }

  return { scan };
}

module.exports = { createScanner, validateScope, DiscoveryScopeError, DEFAULT_PORTS, DEFAULT_PORT_CONCURRENCY };
