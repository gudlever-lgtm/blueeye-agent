'use strict';

const RUN_TEST = /^run[\s_-]?test$/i;
const RUN_PROBE = /^run[\s_-]?probe$/i;

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

module.exports = { isRunTestCommand, isRunProbeCommand };
