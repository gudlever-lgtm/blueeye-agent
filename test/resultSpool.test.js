'use strict';

// A measurement is taken at a moment that does not come back. An outage should
// cost a delay in delivery, not a hole in the history — but never at the price
// of the host's memory, which is what the bound is for.

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { createResultSpool } = require('../src/resultSpool');

test('a failed submit is kept and goes out with the next one, oldest first', async () => {
  const spool = createResultSpool({ max: 10 });
  const sent = [];
  let up = false;
  const submit = async (items) => {
    if (!up) throw new Error('ECONNREFUSED');
    sent.push(items[0]);
  };

  await assert.rejects(() => spool.deliver('traffic', ['a'], submit));
  await assert.rejects(() => spool.deliver('traffic', ['b'], submit));
  assert.equal(spool.pending('traffic'), 2, 'both readings are still held');

  up = true;
  const out = await spool.deliver('traffic', ['c'], submit);
  assert.deepEqual(sent, ['a', 'b', 'c'], 'delivered in the order they were measured');
  assert.equal(out.spooled, 0);
  assert.equal(spool.size, 0);
});

test('the spool stops at the first failure instead of turning one into six', async () => {
  const spool = createResultSpool({ max: 10 });
  let attempts = 0;
  const submit = async () => { attempts += 1; throw new Error('down'); };
  for (let i = 0; i < 4; i += 1) {
    await assert.rejects(() => spool.deliver('traffic', [i], submit));
  }
  assert.equal(attempts, 4, 'one attempt per deliver, not one per spooled batch');
  assert.equal(spool.pending('traffic'), 4);
});

test('past the bound the oldest measurements are dropped, and it says so', async () => {
  const spool = createResultSpool({ max: 3 });
  const submit = async () => { throw new Error('down'); };
  for (let i = 0; i < 6; i += 1) {
    await assert.rejects(() => spool.deliver('traffic', [i], submit));
  }
  assert.equal(spool.size, 3);
  assert.equal(spool.dropped, 3);
  const sent = [];
  await spool.flush('traffic', async (items) => sent.push(items[0]));
  assert.deepEqual(sent, [3, 4, 5], 'the newest three survived');
});

test('kinds do not overtake each other', async () => {
  const spool = createResultSpool({ max: 10 });
  const submit = async () => { throw new Error('down'); };
  await assert.rejects(() => spool.deliver('traffic', ['t1'], submit));
  await assert.rejects(() => spool.deliver('probe', ['p1'], submit));
  assert.equal(spool.pending('traffic'), 1);
  assert.equal(spool.pending('probe'), 1);
  const probes = [];
  await spool.flush('probe', async (items) => probes.push(items[0]));
  assert.deepEqual(probes, ['p1']);
  assert.equal(spool.pending('traffic'), 1, 'flushing probes left the traffic batch alone');
});

test('max 0 disables the spool: a failure is a failure, as it was before', async () => {
  const spool = createResultSpool({ max: 0 });
  await assert.rejects(() => spool.deliver('traffic', ['a'], async () => { throw new Error('down'); }));
  assert.equal(spool.size, 0);
  const sent = [];
  await spool.deliver('traffic', ['b'], async (items) => sent.push(items[0]));
  assert.deepEqual(sent, ['b']);
});

test('stats report what is waiting', async () => {
  const spool = createResultSpool({ max: 5 });
  await assert.rejects(() => spool.deliver('traffic', ['a'], async () => { throw new Error('down'); }));
  const stats = spool.stats();
  assert.equal(stats.batches, 1);
  assert.equal(stats.max, 5);
  assert.ok(stats.oldestAgeMs >= 0);
});
