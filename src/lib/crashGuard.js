'use strict';

// Last-resort process guards.
//
// Node has defaults for both of these, and both defaults are wrong for an
// long-running agent that is supposed to keep reporting:
//
//   * an UNHANDLED REJECTION terminates the process from Node 15 on. Almost
//     every promise in this server belongs to something best-effort — an audit
//     write, an integration fan-out, a notification — and the code is written
//     that way on purpose ("a recording failure must never affect the
//     connection lifecycle"). One missed `.catch()` on a path like that should
//     cost a log line, not the monitoring.
//
//   * an UNCAUGHT EXCEPTION prints to stderr and exits with no ordering at all:
//     no graceful shutdown, so the MySQL pool and both WebSocket servers are
//     dropped mid-flight and every connected agent sees an abrupt close rather
//     than a clean one.
//
// So the two are treated differently, which is the whole point of installing
// them at all:
//
//   unhandledRejection -> LOG AND CONTINUE. The rejection is reported with its
//     stack so it is fixable, but a stray promise does not take the server down.
//
//   uncaughtException  -> LOG AND SHUT DOWN. After one of these the process
//     state is genuinely unknown, so staying up risks serving wrong answers.
//     We run the caller's graceful shutdown (draining connections, closing the
//     pool) behind a hard timeout and exit non-zero, which is what lets systemd
//     or Docker restart us into a known-good state.
//
// Without these, the two reachable paths that motivated this module are a
// process exit: the `upgrade` handler in src/ws/agentSocket.js (a socket that
// resets during async token verification) and any handler that rejects inside
// an `async` event listener.

const silent = { warn() {}, error() {} };

// How long the graceful shutdown gets after an uncaught exception before we
// stop waiting for it. Deliberately shorter than the SIGTERM path's own
// timeout: we are already in an unknown state, so lingering has no upside.
const FATAL_SHUTDOWN_TIMEOUT_MS = 5000;

// `onFatal` is the process's graceful-shutdown routine (or null). It is called
// at most once, may be sync or async, and may not be trusted to return — we
// exit on the timeout regardless. Returns a detach() for tests, which must be
// able to install and remove these without leaking listeners between cases.
function installCrashGuards({ logger = silent, onFatal = null, exit = (code) => process.exit(code), proc = process, timeoutMs = FATAL_SHUTDOWN_TIMEOUT_MS } = {}) {
  let fatalHandled = false;

  const onRejection = (reason) => {
    const err = reason instanceof Error ? reason : new Error(`non-Error rejection: ${String(reason)}`);
    // error(), not warn(): this is a bug every time, even though it is not
    // fatal. It reads as "something in this server forgot a .catch()".
    logger.error('Unhandled promise rejection (the server keeps running; this is a bug — fix the missing .catch()):', err);
  };

  const onException = (err) => {
    // A second exception while we are already tearing down must not restart the
    // teardown or re-enter the caller's shutdown; just go.
    if (fatalHandled) return exit(1);
    fatalHandled = true;
    logger.error('Uncaught exception — shutting down:', err);
    const done = () => exit(1);
    const timer = setTimeout(done, timeoutMs);
    if (timer.unref) timer.unref();
    if (typeof onFatal !== 'function') return done();
    try {
      Promise.resolve(onFatal(err)).then(done, (e) => {
        logger.error('Graceful shutdown failed after an uncaught exception:', e);
        done();
      });
    } catch (e) {
      logger.error('Graceful shutdown threw after an uncaught exception:', e);
      done();
    }
    return undefined;
  };

  proc.on('unhandledRejection', onRejection);
  proc.on('uncaughtException', onException);

  return function detach() {
    proc.removeListener('unhandledRejection', onRejection);
    proc.removeListener('uncaughtException', onException);
  };
}

module.exports = { installCrashGuards, FATAL_SHUTDOWN_TIMEOUT_MS };
