'use strict';

// GATE · PROTOCOL.md is pinned to the code.
//
// PROTOCOL.md is the ONLY written definition of the agent↔server wire
// contract — the server has no copy, and the two repos ship on different
// schedules, so it is what someone reads before changing either side.
//
// It carried a line saying "as implemented in agent v0.9.1" while the agent was
// at v0.32.1, and in those twenty-three releases six commands had been added
// without being documented: rekey, evidence, run-discovery, poll-snmp, burst
// and stop-burst. Nothing noticed, because nothing was looking.
//
// This looks. The command table has to list exactly the commands
// src/command.js recognises — no more, no less. A new recogniser without a
// table row fails; a table row for a command that was removed fails too.
//
// It is deliberately NOT a prose check: nobody can test whether a paragraph is
// still true, but "these are the commands" is a list, and a list can be pinned.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..');
const doc = fs.readFileSync(path.join(ROOT, 'PROTOCOL.md'), 'utf8');
const commandSrc = fs.readFileSync(path.join(ROOT, 'src', 'command.js'), 'utf8');

// Rather than parse the regexes (brittle — the first attempt read `run[\s_-]?test`
// as the command "run"), ASK THE REAL RECOGNISERS. Every exported function in
// src/command.js is a recogniser (a gate test in validation.test.js enforces
// that), so a documented name is valid iff exactly one of them accepts it.
const recognisers = require('../../src/command');

// A command object carrying every payload field any recogniser requires, so a
// name is judged on the NAME and not on a missing field. isRunProbeCommand
// needs `probe`, isInstallToolCommand needs `tool`, and so on.
const FULL_PAYLOAD = {
  probe: { type: 'ping', host: 'x' },
  tool: 'traceroute',
  publicKey: '-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----',
  discovery: { cidrs: [] },
  target: '10.0.0.1',
  items: ['agent.state'],
  testId: 4,
};

const recogniserNames = Object.keys(recognisers).filter((k) => k.startsWith('is'));

// Which recogniser(s) accept this command name.
function acceptedBy(name) {
  return recogniserNames.filter((k) => {
    try { return recognisers[k]({ ...FULL_PAYLOAD, name }) === true; } catch { return false; }
  });
}

// The command column of the table in §2.1 ONLY — the file has several other
// tables (probe types, frames, the authenticity rules) whose first column also
// looks like `code`.
function documentedCommands() {
  const from = doc.indexOf('Command vocabulary');
  const to = doc.indexOf('Anything unrecognised is logged');
  assert.ok(from > 0 && to > from, 'the §2.1 command table could not be located');
  const table = doc.slice(from, to);
  return [...table.matchAll(/^\| `([a-z-]+)`(?: \(alias(?:es)?: [^)]*\))? \|/gm)].map((r) => r[1]);
}

test('every command src/command.js recognises has a row in the PROTOCOL.md table', () => {
  const documented = documentedCommands();
  assert.ok(recogniserNames.length >= 10, `only ${recogniserNames.length} recognisers — has src/command.js changed shape?`);

  // Each recogniser must be reachable from at least one documented name.
  const covered = new Set();
  for (const name of documented) for (const r of acceptedBy(name)) covered.add(r);
  const undocumented = recogniserNames.filter((r) => !covered.has(r));

  assert.deepEqual(
    undocumented, [],
    'These recognisers accept no command documented in PROTOCOL.md §2.1.\n' +
    'PROTOCOL.md is the only written definition of this contract and the server\n' +
    'team reads it before changing their side. Add a row: command, the extra\n' +
    'fields the server sends, what the agent does, and which frames it replies with.'
  );
});

test('every command in the PROTOCOL.md table is actually implemented', () => {
  const phantom = documentedCommands().filter((c) => acceptedBy(c).length === 0);
  assert.deepEqual(
    phantom, [],
    'PROTOCOL.md documents commands src/command.js does not recognise.\n' +
    'A contract that promises something the code refuses is worse than a gap.'
  );
});

test('no documented command is accepted by two recognisers — an ambiguous verb has no defined behaviour', () => {
  const ambiguous = documentedCommands()
    .map((c) => [c, acceptedBy(c)])
    .filter(([, rs]) => rs.length > 1)
    .map(([c, rs]) => `${c} → ${rs.join(', ')}`);
  assert.deepEqual(ambiguous, []);
});

test('the document no longer pins itself to one stale agent version', () => {
  assert.doesNotMatch(
    doc, /as implemented\s+in agent `v[\d.]+`/,
    'The "as implemented in agent vX" line is how this document went 23 releases\n' +
    'out of date. The tests in this file are what keeps it current instead.'
  );
});

test('the command-authenticity rules are documented, including the rekey exception', () => {
  // These are the rules most likely to surprise someone on the server side:
  // that unsigned privileged commands are accepted by default, and that rekey
  // deliberately is not.
  assert.match(doc, /commandSignature/, 'the signature field is not documented');
  assert.match(doc, /BLUEEYE_REQUIRE_SIGNED_COMMANDS/, 'the strict-mode flag is not documented');
  assert.match(doc, /BLUEEYE_ALLOW_UNSIGNED_REKEY/, 'the rekey break-glass flag is not documented');
  assert.match(doc, /issuedAt/, 'the replay window is not documented');
});

test('the agent.error categories listed are the ones the runtime actually emits', () => {
  const runtime = fs.readFileSync(path.join(ROOT, 'src', 'runtime.js'), 'utf8');
  const emitted = [...runtime.matchAll(/reportError\('([a-z-]+)'/g)].map((m) => m[1]);
  const unique = [...new Set(emitted)].sort();
  assert.ok(unique.length > 0, 'no reportError categories found — has the helper been renamed?');

  const missing = unique.filter((c) => !doc.includes(`\`${c}\``));
  assert.deepEqual(
    missing, [],
    'These agent.error categories are emitted but not listed in PROTOCOL.md §2.2.\n' +
    'The server dedupes audit rows per (agent, category, code), so the category\n' +
    'vocabulary is part of the contract, not an implementation detail.'
  );
});
