'use strict';

// Tests for the syslog receiver (src/syslog/receiver.js) and its wiring into
// the runtime.
//
// The socket and server factories are injected, so every transport path — UDP
// datagrams, both RFC 6587 TCP framings, a bind that fails — is exercised
// without binding a real port. The clock is injected too, so the rate limiter's
// refill is tested deterministically instead of with sleeps.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('events');

const { createSyslogReceiver, MAX_LINE_BYTES } = require('../src/syslog/receiver');

const LINE = '<186>Sep 20 09:41:09 sw-core-1 %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down';

// A dgram-shaped fake: bind() succeeds, and send() delivers to the handler.
function fakeSocket({ failBind = false } = {}) {
  const sock = new EventEmitter();
  sock.bind = (port, addr, cb) => {
    if (failBind) {
      setImmediate(() => sock.emit('error', new Error('EADDRINUSE')));
      return;
    }
    setImmediate(cb);
  };
  sock.close = () => {};
  sock.deliver = (text, address = '10.14.0.11') =>
    sock.emit('message', Buffer.from(text), { address });
  return sock;
}

// A net.Server-shaped fake that hands out fake sockets.
function fakeServer({ failListen = false } = {}) {
  const srv = new EventEmitter();
  let onConnection = null;
  srv.listen = (port, addr, cb) => {
    if (failListen) {
      setImmediate(() => srv.emit('error', new Error('EACCES')));
      return;
    }
    setImmediate(cb);
  };
  srv.close = () => {};
  srv.setHandler = (fn) => { onConnection = fn; };
  srv.connect = (remoteAddress = '10.14.0.12') => {
    const sock = new EventEmitter();
    sock.remoteAddress = remoteAddress;
    sock.setEncoding = () => {};
    sock.destroy = () => {};
    onConnection(sock);
    return sock;
  };
  return srv;
}

function build(opts = {}) {
  const socket = fakeSocket(opts.socketOpts);
  const server = fakeServer(opts.serverOpts);
  const rx = createSyslogReceiver({
    createSocket: () => socket,
    createServer: (handler) => { server.setHandler(handler); return server; },
    ...opts.receiverOpts,
  });
  return { rx, socket, server };
}

test('a UDP datagram becomes one classified, folded row', async () => {
  const { rx, socket } = build();
  await rx.start();
  socket.deliver(LINE);
  const events = rx.drain();
  assert.equal(events.length, 1);
  assert.equal(events[0].eventType, 'link.down');
  assert.equal(events[0].ifname, 'GigabitEthernet0/1');
  assert.equal(events[0].sourceIp, '10.14.0.11');
  assert.equal(events[0].transport, 'syslog');
  assert.equal(events[0].severity, 2);
  assert.equal(events[0].occurrences, 1);
  assert.equal(typeof events[0].clockSkewMs, 'number');
  rx.stop();
});

test('one datagram carrying several lines yields several rows', async () => {
  const { rx, socket } = build();
  await rx.start();
  socket.deliver(`${LINE}\n<14>Sep 20 09:41:10 sw-core-1 other: hello\n`);
  assert.equal(rx.drain().length, 2);
  rx.stop();
});

test('repeats inside one window fold onto one row', async () => {
  const { rx, socket } = build();
  await rx.start();
  socket.deliver(LINE);
  socket.deliver(LINE);
  socket.deliver(LINE);
  const events = rx.drain();
  assert.equal(events.length, 1);
  assert.equal(events[0].occurrences, 3);
  rx.stop();
});

test('two windows are two rows, so a changing rate stays visible', async () => {
  const { rx, socket } = build();
  await rx.start();
  socket.deliver(LINE);
  assert.equal(rx.drain()[0].occurrences, 1);
  socket.deliver(LINE);
  socket.deliver(LINE);
  assert.equal(rx.drain()[0].occurrences, 2);
  rx.stop();
});

test('the same message from two devices does not fold together', async () => {
  const { rx, socket } = build();
  await rx.start();
  socket.deliver(LINE, '10.14.0.11');
  socket.deliver(LINE, '10.14.0.12');
  const events = rx.drain();
  assert.equal(events.length, 2);
  rx.stop();
});

test('drain empties the buffer', async () => {
  const { rx, socket } = build();
  await rx.start();
  socket.deliver(LINE);
  rx.drain();
  assert.deepEqual(rx.drain(), []);
  rx.stop();
});

test('the buffer is bounded — an overflowing device cannot eat the host', async () => {
  const { rx, socket } = build({ receiverOpts: { maxEvents: 3, ratePerSec: 1e6, burst: 1e6 } });
  await rx.start();
  for (let i = 0; i < 50; i += 1) {
    socket.deliver(`<14>Sep 20 09:41:09 sw-1 tag: distinct message ${i}`);
  }
  const events = rx.drain();
  assert.equal(events.length, 3);
  assert.ok(rx.stats().overflowed >= 40);
  rx.stop();
});

test('the rate limiter refuses a flood and refills over time', async () => {
  let clock = 1_000_000;
  const { rx, socket } = build({
    receiverOpts: { ratePerSec: 10, burst: 5, now: () => clock },
  });
  await rx.start();
  for (let i = 0; i < 20; i += 1) {
    socket.deliver(`<14>Sep 20 09:41:09 sw-1 tag: msg ${i}`);
  }
  assert.equal(rx.drain().length, 5, 'only the burst allowance is accepted');
  assert.equal(rx.stats().dropped, 15);

  clock += 1000; // one second of refill at 10/s
  for (let i = 0; i < 20; i += 1) {
    socket.deliver(`<14>Sep 20 09:41:09 sw-1 tag: later ${i}`);
  }
  assert.equal(rx.drain().length, 5, 'refill is capped at the burst size');
  rx.stop();
});

test('the rate limiter itself is bounded against spoofed sources', async () => {
  const { rx, socket } = build({ receiverOpts: { maxEvents: 1e6 } });
  await rx.start();
  for (let i = 0; i < 1200; i += 1) {
    socket.deliver('<14>Sep 20 09:41:09 sw-1 tag: m', `10.0.${Math.floor(i / 256)}.${i % 256}`);
  }
  assert.ok(rx.stats().senders <= 1024, 'tracked senders are capped');
  rx.stop();
});

test('a line with no PRI is counted as unparsed, not stored', async () => {
  const { rx, socket } = build();
  await rx.start();
  socket.deliver('this is not syslog at all');
  assert.deepEqual(rx.drain(), []);
  assert.equal(rx.stats().unparsed, 1);
  rx.stop();
});

test('an over-long line is truncated, not dropped', async () => {
  const { rx, socket } = build();
  await rx.start();
  socket.deliver(`${LINE}${'x'.repeat(9000)}`);
  const events = rx.drain();
  assert.equal(events.length, 1);
  assert.ok(events[0].raw.length <= MAX_LINE_BYTES);
  assert.ok(events[0].summary.length <= 512);
  assert.equal(events[0].eventType, 'link.down', 'the first 2 KB still names the fault');
  rx.stop();
});

test('TCP: newline framing (RFC 6587 non-transparent)', async () => {
  const { rx, server } = build();
  await rx.start();
  const sock = server.connect('10.14.0.12');
  sock.emit('data', `${LINE}\n<14>Sep 20 09:41:10 sw-1 tag: second\n`);
  const events = rx.drain();
  assert.equal(events.length, 2);
  assert.equal(events[0].sourceIp, '10.14.0.12');
  rx.stop();
});

test('TCP: octet-counting framing', async () => {
  const { rx, server } = build();
  await rx.start();
  const sock = server.connect();
  sock.emit('data', `${LINE.length} ${LINE}`);
  assert.equal(rx.drain().length, 1);
  rx.stop();
});

test('TCP: a line split across chunks is reassembled', async () => {
  const { rx, server } = build();
  await rx.start();
  const sock = server.connect();
  sock.emit('data', LINE.slice(0, 20));
  assert.deepEqual(rx.drain(), [], 'nothing until the frame completes');
  sock.emit('data', `${LINE.slice(20)}\n`);
  assert.equal(rx.drain().length, 1);
  rx.stop();
});

test('TCP: an IPv4-mapped IPv6 peer is recorded as plain IPv4', async () => {
  const { rx, server } = build();
  await rx.start();
  server.connect('::ffff:10.14.0.99').emit('data', `${LINE}\n`);
  assert.equal(rx.drain()[0].sourceIp, '10.14.0.99');
  rx.stop();
});

test('TCP: a sender that never sends a newline cannot grow the buffer', async () => {
  const { rx, server } = build();
  await rx.start();
  const sock = server.connect();
  sock.emit('data', `${LINE} `.repeat(400)); // well past MAX_LINE_BYTES * 8
  const events = rx.drain();
  assert.ok(events.length >= 1, 'the truncated prefix is still ingested');
  assert.ok(events[0].raw.length <= MAX_LINE_BYTES);
  rx.stop();
});

test('TCP: a trailing unterminated line is flushed on close', async () => {
  const { rx, server } = build();
  await rx.start();
  const sock = server.connect();
  sock.emit('data', LINE);
  sock.emit('end');
  assert.equal(rx.drain().length, 1);
  rx.stop();
});

test('one transport failing to bind does not take the other down', async () => {
  const { rx } = build({ socketOpts: { failBind: true } });
  const bound = await rx.start();
  assert.equal(bound.udp, false);
  assert.equal(bound.tcp, true, 'TCP still listens when UDP is taken');
  rx.stop();
});

test('start rejects with a coded error only when nothing binds at all', async () => {
  const { rx } = build({ socketOpts: { failBind: true }, serverOpts: { failListen: true } });
  await assert.rejects(() => rx.start(), (err) => {
    assert.equal(err.code, 'SYSLOG_BIND_FAILED');
    return true;
  });
});

test('stats does not drain the buffer', async () => {
  const { rx, socket } = build();
  await rx.start();
  socket.deliver(LINE);
  assert.equal(rx.stats().buffered, 1);
  assert.equal(rx.stats().buffered, 1, 'reading stats twice still shows the event');
  assert.equal(rx.drain().length, 1);
  rx.stop();
});

test('the default port is 1514, not 514', () => {
  // Binding below 1024 needs root or CAP_NET_BIND_SERVICE; a monitoring agent
  // must not run as root to receive untrusted UDP from every switch.
  const rx = createSyslogReceiver({});
  assert.equal(rx.stats().port, 1514);
});

test('stop is idempotent and safe before start', () => {
  const { rx } = build();
  rx.stop();
  rx.stop();
});
