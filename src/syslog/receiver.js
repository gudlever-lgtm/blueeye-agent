'use strict';

const dgram = require('dgram');
const net = require('net');
const { parseSyslogLine } = require('./parse');
const { classifySyslog } = require('./classify');
const { maskSyslogMessage } = require('./mask');

const silentLogger = { info() {}, warn() {}, error() {}, debug() {} };

// The agent is the syslog collector. Devices point their logging at the agent
// on the customer's own network, so nothing new leaves the site and the server
// needs no listener anywhere near the edge.
//
// Same shape as src/netflow/collector.js — start() / drain() / stats() / stop()
// with an injectable socket factory — because it does the same job: bind a
// port, buffer what arrives, hand over one interval's worth on demand. A
// technician who has debugged the NetFlow path can read this one.
//
// PORT. The default is 1514, not 514. Binding below 1024 needs root or
// CAP_NET_BIND_SERVICE, and running a monitoring agent as root to receive
// untrusted UDP from every switch on the network is the wrong trade. Hosts that
// want the well-known port grant the capability to the service instead (see
// docs in blueeye-server: docs/device-events.md).

// A line longer than this is truncated, not dropped: a 9 KB stack trace still
// says which device and which interface in its first 2 KB.
const MAX_LINE_BYTES = 2048;

// Per-sender token bucket. A switch in an STP loop can emit thousands of lines a
// second, and the agent must survive that without eating the host's memory —
// the whole point of monitoring being that it does not become the outage.
const DEFAULT_RATE_PER_SEC = 200;
const DEFAULT_BURST = 400;

// Folds repeats inside ONE drain window. A device logging the same line 40
// times in a minute is one event with occurrences=40, not 40 rows. Folding only
// within the window keeps it honest: two windows are two rows, so a rate that
// changes over time is still visible.
function foldKey(row) {
  return [row.sourceIp, row.eventType, row.ifname || '', row.summary].join('\u0000');
}

function createSyslogReceiver({
  port = 1514,
  bindAddress = '0.0.0.0',
  udp = true,
  tcp = true,
  maxEvents = 5000,
  ratePerSec = DEFAULT_RATE_PER_SEC,
  burst = DEFAULT_BURST,
  logger = silentLogger,
  createSocket = () => dgram.createSocket({ type: 'udp4', reuseAddr: true }),
  createServer = (onConnection) => net.createServer(onConnection),
  now = () => Date.now(),
} = {}) {
  let socket = null;
  let server = null;
  const connections = new Set();

  let buffer = new Map(); // foldKey -> row
  let received = 0; // lines accepted since start (cumulative)
  let dropped = 0; // lines refused by the rate limit (cumulative)
  let unparsed = 0; // lines with no usable PRI (cumulative)
  let overflowed = 0; // lines dropped because the buffer was full (cumulative)
  let lastAt = null; // ms epoch of the last line seen
  let boundUdp = false;
  let boundTcp = false;

  // sourceIp -> { tokens, at }
  const buckets = new Map();

  function allow(sourceIp) {
    const t = now();
    let b = buckets.get(sourceIp);
    if (!b) {
      // Cap the number of tracked senders so a spoofed-source flood cannot turn
      // the rate limiter itself into the memory leak it exists to prevent.
      if (buckets.size >= 1024) return true;
      b = { tokens: burst, at: t };
      buckets.set(sourceIp, b);
    }
    const refill = ((t - b.at) / 1000) * ratePerSec;
    b.tokens = Math.min(burst, b.tokens + refill);
    b.at = t;
    if (b.tokens < 1) return false;
    b.tokens -= 1;
    return true;
  }

  // Turns one received line into a buffered row. Never throws: a receiver that
  // dies on a malformed datagram is a receiver an attacker can switch off.
  function ingestLine(line, sourceIp) {
    lastAt = now();
    if (!allow(sourceIp)) {
      dropped += 1;
      return;
    }
    let raw = typeof line === 'string' ? line : '';
    if (raw.length > MAX_LINE_BYTES) raw = raw.slice(0, MAX_LINE_BYTES);

    let parsed;
    try {
      parsed = parseSyslogLine(raw, { receivedAt: lastAt });
    } catch (err) {
      unparsed += 1;
      logger.debug(`syslog: unparseable line from ${sourceIp} (${err.message})`);
      return;
    }
    if (!parsed) {
      unparsed += 1;
      return;
    }

    const { eventType, ifname } = classifySyslog(parsed);
    // Mask before anything is stored, so the unmasked text exists only inside
    // this function's stack frame.
    const summary = maskSyslogMessage(parsed.message) || '(tom besked)';
    const row = {
      sourceIp,
      receivedAt: new Date(lastAt).toISOString(),
      deviceTime: parsed.deviceTime ? parsed.deviceTime.toISOString() : null,
      clockSkewMs: parsed.deviceTime ? lastAt - parsed.deviceTime.getTime() : null,
      transport: 'syslog',
      facility: parsed.facility,
      severity: parsed.severity,
      eventType,
      host: parsed.host,
      tag: parsed.tag,
      ifname,
      summary: summary.slice(0, 512),
      raw: maskSyslogMessage(parsed.raw).slice(0, MAX_LINE_BYTES),
      occurrences: 1,
    };

    const key = foldKey(row);
    const existing = buffer.get(key);
    if (existing) {
      existing.occurrences += 1;
      // Keep the LAST time it happened; the first is implied by the window.
      existing.receivedAt = row.receivedAt;
      existing.deviceTime = row.deviceTime;
      existing.clockSkewMs = row.clockSkewMs;
      received += 1;
      return;
    }
    if (buffer.size >= maxEvents) {
      overflowed += 1;
      return;
    }
    buffer.set(key, row);
    received += 1;
  }

  // One UDP datagram may carry several lines (some relays pack them).
  function handleDatagram(msg, rinfo) {
    const text = Buffer.isBuffer(msg) ? msg.toString('utf8') : String(msg || '');
    for (const line of text.split('\n')) {
      if (line.trim()) ingestLine(line, rinfo && rinfo.address ? rinfo.address : 'unknown');
    }
  }

  // RFC 6587 gives TCP syslog two framings. Non-transparent framing (one line
  // per LF) is what devices actually send; octet-counting ("123 <PRI>...") is
  // handled too because it is cheap and a relay in the path may re-frame.
  function handleConnection(sock) {
    const sourceIp = sock.remoteAddress ? sock.remoteAddress.replace(/^::ffff:/, '') : 'unknown';
    connections.add(sock);
    let pending = '';
    sock.setEncoding('utf8');
    sock.on('data', (chunk) => {
      pending += chunk;
      // Bound the un-framed remainder so a sender that never emits a newline
      // cannot grow this string without limit.
      if (pending.length > MAX_LINE_BYTES * 8) {
        ingestLine(pending.slice(0, MAX_LINE_BYTES), sourceIp);
        pending = '';
        return;
      }
      for (;;) {
        const octet = /^(\d{1,6}) /.exec(pending);
        if (octet) {
          const len = Number(octet[1]);
          const start = octet[0].length;
          if (pending.length < start + len) break;
          ingestLine(pending.slice(start, start + len), sourceIp);
          pending = pending.slice(start + len);
          continue;
        }
        const nl = pending.indexOf('\n');
        if (nl === -1) break;
        const line = pending.slice(0, nl);
        pending = pending.slice(nl + 1);
        if (line.trim()) ingestLine(line, sourceIp);
      }
    });
    const done = () => {
      if (pending.trim()) ingestLine(pending, sourceIp);
      pending = '';
      connections.delete(sock);
    };
    sock.on('end', done);
    sock.on('close', done);
    sock.on('error', (err) => {
      connections.delete(sock);
      logger.debug(`syslog TCP error from ${sourceIp}: ${err.message}`);
    });
  }

  // Binds the configured transports. A failure on ONE transport is logged and
  // survived rather than thrown: a host where something already holds the TCP
  // port should still collect UDP syslog, which is what almost every device
  // sends. start() only rejects when nothing at all could be bound.
  async function start() {
    const failures = [];
    if (udp) {
      try {
        await new Promise((resolve, reject) => {
          socket = createSocket();
          socket.on('message', handleDatagram);
          socket.on('error', (err) => logger.error(`syslog UDP socket error: ${err.message}`));
          socket.once('error', reject);
          socket.bind(port, bindAddress, () => {
            boundUdp = true;
            resolve();
          });
        });
        logger.info(`Syslog receiver listening on udp/${bindAddress}:${port}`);
      } catch (err) {
        failures.push(`udp: ${err.message}`);
        if (socket) { try { socket.close(); } catch { /* ignore */ } socket = null; }
      }
    }
    if (tcp) {
      try {
        await new Promise((resolve, reject) => {
          server = createServer(handleConnection);
          server.on('error', (err) => logger.error(`syslog TCP server error: ${err.message}`));
          server.once('error', reject);
          server.listen(port, bindAddress, () => {
            boundTcp = true;
            resolve();
          });
        });
        logger.info(`Syslog receiver listening on tcp/${bindAddress}:${port}`);
      } catch (err) {
        failures.push(`tcp: ${err.message}`);
        if (server) { try { server.close(); } catch { /* ignore */ } server = null; }
      }
    }
    if (!boundUdp && !boundTcp) {
      const err = new Error(`Syslog receiver could not bind port ${port} (${failures.join('; ') || 'no transport enabled'}).`);
      err.code = 'SYSLOG_BIND_FAILED';
      throw err;
    }
    return { udp: boundUdp, tcp: boundTcp, port };
  }

  // Returns the folded rows for this interval and clears the buffer.
  function drain() {
    const events = Array.from(buffer.values());
    buffer = new Map();
    return events;
  }

  // Non-destructive health snapshot for the `diagnose` command — same role as
  // the NetFlow collector's stats(), so "where do the device events stop?" is
  // answerable from the dashboard without shell access to the host.
  function stats() {
    return {
      port,
      udp: boundUdp,
      tcp: boundTcp,
      buffered: buffer.size,
      received,
      dropped,
      unparsed,
      overflowed,
      senders: buckets.size,
      lastAt: lastAt ? new Date(lastAt).toISOString() : null,
    };
  }

  function stop() {
    if (socket) {
      try { socket.close(); } catch { /* ignore */ }
      socket = null;
    }
    for (const sock of connections) {
      try { sock.destroy(); } catch { /* ignore */ }
    }
    connections.clear();
    if (server) {
      try { server.close(); } catch { /* ignore */ }
      server = null;
    }
    boundUdp = false;
    boundTcp = false;
  }

  return { start, drain, stats, stop, ingestLine };
}

module.exports = { createSyslogReceiver, MAX_LINE_BYTES };
