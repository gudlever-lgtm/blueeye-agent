'use strict';

const RUN_TEST = /^run[\s_-]?test$/i;

// Recognises a "run test" command. The server sends commands as
// { type: 'command', command: <X> }; X may be a string ("run test") or an
// object carrying name/action/type (e.g. { name: 'run-test', id: 7 }).
function isRunTestCommand(command) {
  if (typeof command === 'string') return RUN_TEST.test(command.trim());
  if (command && typeof command === 'object') {
    const verb = command.name || command.action || command.type || command.command;
    return typeof verb === 'string' && RUN_TEST.test(verb.trim());
  }
  return false;
}

module.exports = { isRunTestCommand };
