'use strict';

// Maps a Node network error to a failure phase for the structured `detail`
// ({ phase, step, errno }) the server consumes and maps to a Danish diagnosis.
//   dns      — name resolution failed
//   connect  — TCP connect refused/timed out/unreachable before a socket
//   tls      — certificate / TLS handshake failure
//   timeout  — the step's own timeout fired (handled by the caller, not here)
function phaseForError(err) {
  const code = err && (err.code || err.errno) ? String(err.code || err.errno) : '';
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN' || code === 'EAI_NODATA' || code === 'ENODATA') return 'dns';
  if (/CERT|_SSL|TLS|DEPTH_ZERO|UNABLE_TO_VERIFY|SELF_SIGNED|ERR_TLS/i.test(code)) return 'tls';
  if (code === 'ECONNREFUSED' || code === 'ETIMEDOUT' || code === 'EHOSTUNREACH'
      || code === 'ENETUNREACH' || code === 'ECONNRESET' || code === 'EPIPE') return 'connect';
  return 'connect';
}

module.exports = { phaseForError };
