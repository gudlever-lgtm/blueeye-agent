'use strict';

// A traceroute that produced no hops has to say WHY, in words an operator can
// act on. It used to report the command line back at them: Node puts
// "Command failed: <the whole command>" on the first line of the exec error,
// and that first line was all this read — so "Unable to resolve target system
// name www.example.sg." never reached the dashboard.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');

const { traceroute, failureReason } = require('../src/probes/traceroute');
const { tcptraceroute } = require('../src/probes/tcptraceroute');

// An exec that fails the way execFile does: err.message repeats the command,
// and the tool's own words are on stdout or stderr.
function failingExec({ stdout = '', stderr = '', code = 'X' } = {}) {
  return (bin, args, _opts, cb) => {
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    const err = Object.assign(new Error(`Command failed: ${bin} ${args.join(' ')}\n${stderr}`), { code });
    setImmediate(() => cb(err, stdout, stderr));
    return child;
  };
}

test('a name that does not resolve says so, on either platform', async () => {
  // Windows tracert writes this to stdout.
  const win = await traceroute({ host: 'www.example.sg' }, {
    platform: 'win32', reverse: null,
    exec: failingExec({ stdout: 'Unable to resolve target system name www.example.sg.\r\n' }),
  });
  assert.equal(win.ok, false);
  assert.equal(win.error, 'could not resolve the target name');
  assert.ok(!/Command failed|tracert -4/.test(win.error), 'the command line is not an explanation');

  // unix traceroute writes it to stderr.
  const nix = await traceroute({ host: 'example.invalid' }, {
    platform: 'linux', reverse: null,
    exec: failingExec({ stderr: 'traceroute: unknown host example.invalid\n' }),
  });
  assert.equal(nix.error, 'could not resolve the target name');
});

test('a raw-socket refusal, an unreachable network and bad options each get their own reason', async () => {
  const run = async (o) => (await traceroute({ host: 'x.test' }, { platform: 'linux', reverse: null, exec: failingExec(o) })).error;
  assert.match(await run({ stderr: 'traceroute: socket: Operation not permitted' }), /needs root/);
  assert.match(await run({ stderr: 'connect: Network is unreachable' }), /network is unreachable/);
  assert.match(await run({ stderr: 'traceroute: invalid option -- \'Z\'' }), /refused these options/);
});

test('anything else is the tool\'s own words, never the command line', async () => {
  const res = await traceroute({ host: 'x.test' }, {
    platform: 'win32', reverse: null,
    exec: failingExec({ stdout: 'Tracing route to x.test over a maximum of 20 hops\r\n\r\nsomething odd happened\r\n' }),
  });
  assert.equal(res.error, 'something odd happened', 'the banner lines are not the complaint');
});

test('a silent failure still names the tool rather than nothing', () => {
  assert.equal(failureReason({ bin: 'tracert', err: new Error('Command failed: tracert x') }), 'tracert produced no hops');
  assert.equal(failureReason({ bin: 'tracert', missing: true }), 'tracert not installed');
  assert.equal(failureReason({ bin: 'traceroute', err: Object.assign(new Error('x'), { killed: true }) }), 'traceroute timed out');
});

test('the reason never leaks the command line, whatever the tool said', async () => {
  for (const o of [{}, { stderr: 'Command failed: tracert -4 -d -w 2000 -h 20 www.example.sg' }]) {
    const res = await traceroute({ host: 'www.example.sg' }, { platform: 'win32', reverse: null, exec: failingExec(o) });
    assert.ok(!/-w 2000|-h 20/.test(res.error), `leaked the command line: ${res.error}`);
  }
});

test('tcptraceroute explains a failure the same way', async () => {
  const res = await tcptraceroute({ host: 'example.invalid', port: 443 }, {
    reverse: null, exec: failingExec({ stderr: 'tcptraceroute: unknown host example.invalid' }),
  });
  assert.equal(res.ok, false);
  assert.equal(res.error, 'could not resolve the target name');
});

test('a run that DID produce hops is never called a failure, whatever the exit code', async () => {
  const out = ' 1  192.168.1.1  0.5 ms  0.4 ms  0.4 ms\n 2  10.0.0.1  2.0 ms  2.1 ms  2.2 ms\n';
  const res = await traceroute({ host: 'x.test' }, {
    platform: 'linux', reverse: null, exec: failingExec({ stdout: out, stderr: 'traceroute: some warning' }),
  });
  assert.equal(res.ok, true, 'traceroute exits non-zero routinely while printing a usable report');
  assert.equal(res.hopCount, 2);
  assert.equal(res.error, undefined);
});
