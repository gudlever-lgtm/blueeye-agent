'use strict';

const RUN_TEST = /^run[\s_-]?test$/i;
const RUN_PROBE = /^run[\s_-]?probe$/i;
const PING = /^ping$/i;
const UPDATE = /^(update|self[\s_-]?update|upgrade)$/i;
const SPEEDTEST = /^speed[\s_-]?test$/i;

function verbOf(command) {
  if (typeof command === 'string') return command.trim();
  if (command && typeof command === 'object') {
    const v = command.name || command.action || command.type || command.command;
    return typeof v === 'string' ? v.trim() : '';
  }
  return '';
}

// Recognises a "run test" command. The server sends commands as
// { type: 'command', command: <X> }; X may be a string ("run test") or an
// object carrying name/action/type (e.g. { name: 'run-test', id: 7 }).
function isRunTestCommand(command) {
  return RUN_TEST.test(verbOf(command));
}

// Recognises a "run probe" command: { name: 'run-probe', probe: { type, ... } }.
function isRunProbeCommand(command) {
  return RUN_PROBE.test(verbOf(command)) && !!command && typeof command.probe === 'object' && command.probe !== null;
}

// Recognises a "ping" liveness command: { name: 'ping', id } — the agent replies
// with an ack carrying its version/sources so the server can confirm the link.
function isPingCommand(command) {
  return PING.test(verbOf(command));
}

// Recognises a self-update command: { name: 'update', id, sha256 } — rebuild from
// the server's source bundle and restart (systemd-managed agents only).
function isUpdateCommand(command) {
  return UPDATE.test(verbOf(command));
}

// Recognises a speed-test command: { name: 'speedtest', bytes? } — download then
// upload a sized blob to/from the server and report the achieved Mbps.
function isSpeedtestCommand(command) {
  return SPEEDTEST.test(verbOf(command));
}

module.exports = { isRunTestCommand, isRunProbeCommand, isPingCommand, isUpdateCommand, isSpeedtestCommand };
