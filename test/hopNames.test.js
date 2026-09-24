'use strict';

// Router PTR names ride along on a traced path so the server can read the city
// out of them. Looked up after the trace, public addresses only, bounded.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');

const { nameHops, isPublicIp, cleanName } = require('../src/probes/hopNames');
const { traceroute } = require('../src/probes/traceroute');
const { tcptraceroute } = require('../src/probes/tcptraceroute');

const OUT = [
  'traceroute to 151.101.1.67 (151.101.1.67), 20 hops max, 60 byte packets',
  ' 1  192.168.1.1  0.5 ms  0.4 ms  0.4 ms',
  ' 2  100.64.0.1  2.0 ms  2.1 ms  2.2 ms',
  ' 3  62.115.1.1  5.0 ms  5.1 ms  5.2 ms',
  ' 4  * * *',
  ' 5  151.101.1.67  9.0 ms  9.1 ms  9.2 ms',
  '',
].join('\n');

function exec(out) {
  return (_bin, _args, _opts, cb) => {
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    setImmediate(() => { child.stdout.emit('data', Buffer.from(out)); cb(null, out, ''); });
    return child;
  };
}

const PTR = {
  '62.115.1.1': ['AE3.CPH-BB1.Telia.net.'],
  '151.101.1.67': ['edge.example.net'],
};

test('isPublicIp keeps the customer network out', () => {
  for (const ip of ['10.0.0.1', '172.16.5.5', '172.31.255.1', '192.168.1.1', '127.0.0.1', '169.254.1.1',
    '100.64.0.1', '100.127.255.254', '0.0.0.0', '224.0.0.1', '::1', 'fd00::1', 'fe80::1', '::ffff:10.0.0.1', '', null, 'router']) {
    assert.equal(isPublicIp(ip), false, ip);
  }
  for (const ip of ['62.115.1.1', '172.32.0.1', '100.128.0.1', '8.8.8.8', '2001:4860::8888', '::ffff:8.8.8.8']) {
    assert.equal(isPublicIp(ip), true, ip);
  }
});

test('cleanName lower-cases, drops the root dot and refuses anything that is not a DNS name', () => {
  assert.equal(cleanName('AE3.CPH-BB1.Telia.net.'), 'ae3.cph-bb1.telia.net');
  assert.equal(cleanName('bad name.example'), null);
  assert.equal(cleanName('<script>.example'), null);
  assert.equal(cleanName('-lead.example'), null);
  assert.equal(cleanName(''), null);
  assert.equal(cleanName(`${'a'.repeat(250)}.net`), null);
});

test('nameHops names public hops only, once per address', async () => {
  const asked = [];
  const hops = [
    { hop: 1, ip: '192.168.1.1' }, { hop: 2, ip: '62.115.1.1' }, { hop: 3, ip: '62.115.1.1' },
    { hop: 4, ip: null }, { hop: 5, ip: '151.101.1.67' },
  ];
  await nameHops(hops, { reverse: async (ip) => { asked.push(ip); return PTR[ip] || []; } });
  assert.deepEqual(asked.sort(), ['151.101.1.67', '62.115.1.1']);
  assert.equal(hops[0].hostname, undefined);
  assert.equal(hops[1].hostname, 'ae3.cph-bb1.telia.net');
  assert.equal(hops[2].hostname, 'ae3.cph-bb1.telia.net');
  assert.equal(hops[3].hostname, undefined);
  assert.equal(hops[4].hostname, 'edge.example.net');
});

test('a failing or slow lookup leaves the hop unnamed and never holds the probe', async () => {
  const hops = [{ hop: 1, ip: '8.8.8.8' }, { hop: 2, ip: '9.9.9.9' }, { hop: 3, ip: '1.1.1.1' }];
  const t0 = Date.now();
  await nameHops(hops, {
    timeoutMs: 50,
    budgetMs: 200,
    reverse: (ip) => {
      if (ip === '8.8.8.8') return Promise.reject(Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }));
      if (ip === '9.9.9.9') return new Promise(() => {}); // never answers
      return Promise.resolve(['one.one.one.one']);
    },
  });
  assert.ok(Date.now() - t0 < 5000, 'returned although one lookup never answers');
  assert.equal(hops[0].hostname, undefined);
  assert.equal(hops[1].hostname, undefined);
  assert.equal(hops[2].hostname, 'one.one.one.one');
});

test('the overall budget caps a path of slow resolvers', async () => {
  const hops = Array.from({ length: 30 }, (_, i) => ({ hop: i + 1, ip: `8.8.${i}.1` }));
  const t0 = Date.now();
  await nameHops(hops, { timeoutMs: 1000, budgetMs: 150, reverse: () => new Promise(() => {}) });
  assert.ok(Date.now() - t0 < 5000, 'returned on the budget, not after 30 lookups');
  assert.ok(hops.every((h) => h.hostname === undefined));
});

test('reverse: null skips naming', async () => {
  const hops = [{ hop: 1, ip: '8.8.8.8' }];
  await nameHops(hops, { reverse: null });
  assert.equal(hops[0].hostname, undefined);
});

test('traceroute results carry the PTR name on public hops', async () => {
  const res = await traceroute({ host: '151.101.1.67' }, { exec: exec(OUT), platform: 'linux', reverse: async (ip) => PTR[ip] || [] });
  assert.deepEqual(res.hops.map((h) => h.hostname), [undefined, undefined, 'ae3.cph-bb1.telia.net', undefined, 'edge.example.net']);
});

test('tcptraceroute results carry the PTR name too', async () => {
  const res = await tcptraceroute({ host: '151.101.1.67', port: 443 }, { exec: exec(OUT), reverse: async (ip) => PTR[ip] || [] });
  assert.equal(res.ok, true);
  assert.equal(res.hops[2].hostname, 'ae3.cph-bb1.telia.net');
});

test('the live hop frames are not held back by the lookups', async () => {
  const seen = [];
  let resolved = false;
  await traceroute({ host: '151.101.1.67' }, {
    exec: exec(OUT),
    platform: 'linux',
    onHop: (h) => seen.push({ hop: h.hop, namedYet: resolved }),
    reverse: async (ip) => { resolved = true; return PTR[ip] || []; },
  });
  assert.equal(seen.length, 5);
  assert.ok(seen.every((s) => s.namedYet === false), 'every hop streamed before any name lookup ran');
});
