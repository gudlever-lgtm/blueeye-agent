'use strict';

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };

// A tiny dependency-free, level-aware logger. `sink` is injectable so tests can
// silence or capture output.
function createLogger({ level = 'info', sink = console } = {}) {
  const threshold = LEVELS[level] ?? LEVELS.info;

  function log(lvl, message) {
    if (LEVELS[lvl] < threshold) return;
    const line = `${new Date().toISOString()} [${lvl.toUpperCase()}] ${message}`;
    if (lvl === 'error') sink.error(line);
    else if (lvl === 'warn') sink.warn(line);
    else sink.log(line);
  }

  return {
    debug: (m) => log('debug', m),
    info: (m) => log('info', m),
    warn: (m) => log('warn', m),
    error: (m) => log('error', m),
  };
}

// A logger that discards everything (handy for tests).
const silentLogger = { debug() {}, info() {}, warn() {}, error() {} };

module.exports = { createLogger, silentLogger };
