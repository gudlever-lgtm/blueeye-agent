'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  collectConnections, aggregateEdges, orientEdge,
  parseSs, parseNetstatLinux, parseNetstatMac, parseWindows,
} = require('../src/connTable');

// ---- per-platform parsers --------------------------------------------------

test('parseSs parses ss -Htan established output', () => {
  const text = [
    'ESTAB 0      0      10.0.0.1:22          10.0.0.5:54321',
    'ESTAB 0      0      10.0.0.1:44012       10.0.0.9:443',
    'garbage line',
  ].join('\n');
  const conns = parseSs(text);
  assert.equal(conns.length, 2);
  assert.deepEqual(conns[0], { localIp: '10.0.0.1', localPort: 22, remoteIp: '10.0.0.5', remotePort: 54321 });
  assert.deepEqual(conns[1], { localIp: '10.0.0.1', localPort: 44012, remoteIp: '10.0.0.9', remotePort: 443 });
});

// Captured from the REAL command (iproute2 6.1, `ss -Htan state established`,
// public addresses swapped for documentation ranges, whitespace kept): with one
// state filtered, ss prints NO State column. The parser used to expect one and
// dropped every line of this.
test('parseSs reads the real `ss -Htan state established` output (no State column)', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const text = fs.readFileSync(path.join(__dirname, 'fixtures', 'ss-Htan-state-established.txt'), 'utf8');
  const conns = parseSs(text);
  assert.equal(conns.length, 5);
  assert.deepEqual(conns[0], { localIp: '192.0.2.2', localPort: 46234, remoteIp: '198.51.100.65', remotePort: 443 });
  assert.deepEqual(conns[4], { localIp: '192.0.2.2', localPort: 4455, remoteIp: '192.0.2.2', remotePort: 37752 });
  // And the collector turns it into edges without falling back to netstat.
  const edges = aggregateEdges(conns);
  assert.ok(edges.some((e) => e.dstIp === '203.0.113.100' && e.dstPort === 443 && e.connCount === 2));
});

test('parseSs with a State column keeps only ESTAB rows', () => {
  const text = [
    'LISTEN    0      128      0.0.0.0:2024         0.0.0.0:*',
    'ESTAB     0      0      192.0.2.2:46234  198.51.100.65:443',
    'TIME-WAIT 0      0      192.0.2.2:40414 185.125.190.83:80',
    'ESTAB     0      0      [2001:db8::1]:22  [2001:db8::9]:50000',
  ].join('\n');
  const conns = parseSs(text);
  assert.equal(conns.length, 2);
  assert.equal(conns[1].localIp, '2001:db8::1');
  assert.equal(conns[1].remotePort, 50000);
});

test('collectConnections uses the real ss shape without calling netstat', async () => {
  const calls = [];
  const fakeExec = (cmd, args, opts, cb) => {
    calls.push(cmd);
    cb(null, '0      0      192.0.2.2:35792 203.0.113.100:443  \n');
  };
  const edges = await collectConnections({ platform: 'linux', execFileFn: fakeExec });
  assert.deepEqual(calls, ['ss']);
  assert.deepEqual(edges, [{ srcIp: '192.0.2.2', dstIp: '203.0.113.100', dstPort: 443, connCount: 1 }]);
});

test('parseNetstatLinux keeps only ESTABLISHED tcp rows', () => {
  const text = [
    'Active Internet connections (w/o servers)',
    'Proto Recv-Q Send-Q Local Address           Foreign Address         State',
    'tcp        0      0 10.0.0.1:22             10.0.0.5:54321          ESTABLISHED',
    'tcp        0      0 10.0.0.1:80             0.0.0.0:*               LISTEN',
  ].join('\n');
  const conns = parseNetstatLinux(text);
  assert.equal(conns.length, 1);
  assert.equal(conns[0].remotePort, 54321);
});

test('parseNetstatMac parses addr.port form', () => {
  const text = [
    'Active Internet connections',
    'Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)',
    'tcp4       0      0  10.0.0.1.22            10.0.0.5.54321         ESTABLISHED',
    'tcp4       0      0  10.0.0.1.80            *.*                    LISTEN',
  ].join('\n');
  const conns = parseNetstatMac(text);
  assert.equal(conns.length, 1);
  assert.deepEqual(conns[0], { localIp: '10.0.0.1', localPort: 22, remoteIp: '10.0.0.5', remotePort: 54321 });
});

test('parseWindows parses ConvertTo-Json array and a single object', () => {
  const arr = JSON.stringify([{ LocalAddress: '10.0.0.1', LocalPort: 49500, RemoteAddress: '10.0.0.9', RemotePort: 443 }]);
  assert.equal(parseWindows(arr).length, 1);
  const one = JSON.stringify({ LocalAddress: '10.0.0.1', LocalPort: 22, RemoteAddress: '10.0.0.5', RemotePort: 60000 });
  const conns = parseWindows(one);
  assert.equal(conns.length, 1);
  assert.equal(conns[0].localPort, 22);
});

// ---- orientation (client vs server) ----------------------------------------

test('orientEdge: ephemeral side is the client (source), service side the dest', () => {
  // This host is the CLIENT (local ephemeral 44012 → remote service 443).
  assert.deepEqual(orientEdge({ localIp: 'A', localPort: 44012, remoteIp: 'B', remotePort: 443 }, 32768),
    { srcIp: 'A', dstIp: 'B', dstPort: 443 });
  // This host is the SERVER (local service 22 ← remote ephemeral 54321).
  assert.deepEqual(orientEdge({ localIp: 'A', localPort: 22, remoteIp: 'B', remotePort: 54321 }, 32768),
    { srcIp: 'B', dstIp: 'A', dstPort: 22 });
  // Ambiguous (both non-ephemeral) → lower port is the service.
  assert.deepEqual(orientEdge({ localIp: 'A', localPort: 8080, remoteIp: 'B', remotePort: 5000 }, 32768),
    { srcIp: 'A', dstIp: 'B', dstPort: 5000 });
});

// ---- aggregation -----------------------------------------------------------

test('aggregateEdges dedups by (src,dst,port), counts, drops loopback/self', () => {
  const conns = [
    { localIp: '10.0.0.1', localPort: 40001, remoteIp: '10.0.0.9', remotePort: 443 },
    { localIp: '10.0.0.1', localPort: 40002, remoteIp: '10.0.0.9', remotePort: 443 }, // same edge, +1
    { localIp: '10.0.0.1', localPort: 40003, remoteIp: '127.0.0.1', remotePort: 5432 }, // loopback → dropped
    { localIp: '10.0.0.1', localPort: 22, remoteIp: '10.0.0.1', remotePort: 40004 }, // self → dropped
  ];
  const edges = aggregateEdges(conns, { ephemeralMin: 32768 });
  assert.equal(edges.length, 1);
  assert.deepEqual(edges[0], { srcIp: '10.0.0.1', dstIp: '10.0.0.9', dstPort: 443, connCount: 2 });
});

test('aggregateEdges caps the heaviest N edges', () => {
  const conns = [];
  for (let p = 1; p <= 10; p += 1) conns.push({ localIp: '10.0.0.1', localPort: 40000 + p, remoteIp: `10.0.0.${p}`, remotePort: 443 });
  const edges = aggregateEdges(conns, { ephemeralMin: 32768, cap: 3 });
  assert.equal(edges.length, 3);
});

// ---- collector (injected exec) ---------------------------------------------

test('collectConnections runs ss on Linux and returns edges', async () => {
  const fakeExec = (cmd, args, opts, cb) => {
    assert.equal(cmd, 'ss');
    cb(null, 'ESTAB 0 0 10.0.0.1:40100 10.0.0.9:443\n');
  };
  const edges = await collectConnections({ platform: 'linux', execFileFn: fakeExec });
  assert.equal(edges.length, 1);
  assert.deepEqual(edges[0], { srcIp: '10.0.0.1', dstIp: '10.0.0.9', dstPort: 443, connCount: 1 });
});

test('collectConnections falls back to netstat when ss yields nothing', async () => {
  const calls = [];
  const fakeExec = (cmd, args, opts, cb) => {
    calls.push(cmd);
    if (cmd === 'ss') return cb(null, '');
    return cb(null, 'tcp 0 0 10.0.0.1:22 10.0.0.5:54321 ESTABLISHED\n');
  };
  const edges = await collectConnections({ platform: 'linux', execFileFn: fakeExec });
  assert.deepEqual(calls, ['ss', 'netstat']);
  assert.equal(edges.length, 1);
  assert.equal(edges[0].dstPort, 22);
});

test('collectConnections returns [] when the command errors (best-effort)', async () => {
  const fakeExec = (cmd, args, opts, cb) => cb(new Error('command not found'));
  const edges = await collectConnections({ platform: 'linux', execFileFn: fakeExec });
  assert.deepEqual(edges, []);
});
