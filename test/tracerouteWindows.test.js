'use strict';

// WINDOWS TRACEROUTE CAME BACK EMPTY, and the dashboard blamed a missing tool.
//
// tracert waits its own default (~4s) for each of three probes per hop. Twenty
// hops with a few silent routers is several minutes, the 60-second exec timeout
// killed it, a killed run has no output to parse, and zero hops was reported as
// "the agent is likely missing the traceroute command" — on a host where
// tracert was working perfectly.
//
// Two things fix it and both are pinned here: bound the per-hop wait, and size
// the run's own timeout from the same numbers instead of a flat minute.

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { traceroute, parseTraceroute } = require('../src/probes/traceroute');
const { tracerouteCommands, TRACE_WAIT_MS } = require('../src/probes/ipFamily');

test('tracert is given a per-probe wait, so a silent hop cannot cost four seconds', async () => {
  const [cmd] = tracerouteCommands({ platform: 'win32', family: 4, host: 'example.com', maxHops: 20, queries: 3 });
  assert.equal(cmd.bin, 'tracert');
  const w = cmd.args.indexOf('-w');
  assert.ok(w >= 0, '-w is passed');
  assert.equal(cmd.args[w + 1], String(TRACE_WAIT_MS));
  // And the same amount the unix branch waits, so neither platform is the slow one.
  const [unix] = tracerouteCommands({ platform: 'linux', family: 4, host: 'example.com', maxHops: 20, queries: 3 });
  assert.equal(unix.args[unix.args.indexOf('-w') + 1], String(TRACE_WAIT_MS / 1000));
});

test('the run is allowed the time its own arguments imply', async () => {
  // The failing case: 20 hops x 3 probes x 2s = 120s of legitimate waiting,
  // against a timeout of 60.
  let seen = null;
  const exec = (bin, args, opts, cb) => { seen = opts; cb(null, ''); };
  await traceroute({ host: 'example.com', maxHops: 20 }, { reverse: null, exec, platform: 'win32' });
  assert.ok(seen.timeout > 120000, `timeout ${seen.timeout} must cover 20x3x2s`);
  assert.ok(seen.timeout <= 180000, 'and still be bounded');
});

test('a short trace does not get a long timeout', async () => {
  let seen = null;
  const exec = (bin, args, opts, cb) => { seen = opts; cb(null, ''); };
  await traceroute({ host: 'example.com', maxHops: 5, queries: 1 }, { reverse: null, exec, platform: 'linux' });
  assert.ok(seen.timeout < 60000, `a 5-hop trace asked for ${seen.timeout}ms`);
});

test('real tracert output parses into hops', async () => {
  // Verbatim shape from Windows: the address comes LAST on the line, the
  // timings are "1 ms" with a space, and a dead hop is asterisks.
  const out = [
    '',
    'Tracing route to example.com [93.184.216.34]',
    'over a maximum of 20 hops:',
    '',
    '  1     1 ms     1 ms     1 ms  192.168.1.1',
    '  2     8 ms     9 ms     8 ms  10.20.0.1',
    '  3     *        *        *     Request timed out.',
    '  4    24 ms    23 ms    24 ms  93.184.216.34',
    '',
    'Trace complete.',
  ].join('\r\n');

  const hops = parseTraceroute(out, 3);
  assert.equal(hops.length, 4);
  assert.equal(hops[0].ip, '192.168.1.1');
  assert.equal(hops[0].rttMs, 1);
  assert.equal(hops[2].ip, null, 'a silent hop has no address');
  assert.equal(hops[2].lossPct, 100);
  assert.equal(hops[3].ip, '93.184.216.34');
  assert.equal(hops[3].rttMs, 23.67, 'the median of 24, 23, 24');
});

test('CRLF is the whole bug: every hop but the last used to vanish', async () => {
  // The regression, isolated. Splitting on \n alone leaves a trailing \r on
  // every line but the last; `.` does not match \r in JavaScript, so `(.*)$`
  // could not reach the end and the line matched nothing. Real tracert output
  // ends with "Trace complete.", so in practice EVERY hop was dropped.
  const hop = '  1     1 ms     1 ms     1 ms  192.168.1.1';
  assert.equal(parseTraceroute(hop, 3).length, 1, 'no line ending at all');
  assert.equal(parseTraceroute(`${hop}\r`, 3).length, 1, 'trailing CR');
  assert.equal(parseTraceroute(`${hop}\r\nTrace complete.\r\n`, 3).length, 1, 'CRLF, hop not last');
  assert.equal(parseTraceroute(`${hop}\n`, 3).length, 1, 'plain LF, unchanged');
});

test('a killed run says it timed out, not that the tool is missing', async () => {
  // The two are different problems with different fixes, and the operator was
  // shown the wrong one.
  const exec = (bin, args, opts, cb) => {
    const err = new Error('killed');
    err.killed = true;
    cb(err, '');
  };
  const res = await traceroute({ host: 'example.com' }, { reverse: null, exec, platform: 'win32' });
  assert.equal(res.ok, false);
  assert.match(res.error, /timed out/);
  assert.doesNotMatch(res.error, /not installed/);
});

test('a genuinely missing tracert still says so', async () => {
  const exec = (bin, args, opts, cb) => {
    const err = new Error('spawn ENOENT');
    err.code = 'ENOENT';
    cb(err, '');
  };
  const res = await traceroute({ host: 'example.com' }, { reverse: null, exec, platform: 'win32' });
  assert.equal(res.ok, false);
  assert.match(res.error, /tracert not installed/);
});
