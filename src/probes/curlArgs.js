'use strict';

// Argument-construction guards for the curl-driven probes (curl / transaction).
//
// curl gives a leading '@' a FILE meaning in several options: `-H @file` reads
// the request headers from a local file and `--data @file` reads the request
// body from one. A transaction step's `header` and `data` come from the SERVER,
// so an unguarded '@' turns a probe into "read an arbitrary local file and POST
// it to a server-chosen URL" — and the agent usually runs as root, so that is
// every file on the host. execFile closes shell injection, not this: the file
// read is curl's OWN option parsing, downstream of argv.
//
// So the agent enforces its own shape here (same model as the install-tool and
// evidence allowlists — the server's validation is not what we rely on):
//   - a request body always goes through --data-raw, the variant that never
//     opens a file, so the value is sent verbatim as bytes;
//   - a header must look like a real `Name: value` field before it is passed on.

// RFC 7230 token characters for the name, then ':', then a value with no CR/LF
// (which would otherwise split the request). '@' and '/' are not token
// characters, so an '@file' argument can never satisfy this.
const HEADER_RE = /^[A-Za-z0-9!#$%&'*+.^_`|~-]+:[^\r\n]*$/;
const MAX_HEADER_LEN = 256;

// Returns the trimmed header when it is a well-formed `Name: value` field, or
// null when it is anything else — an '@file' read, a CRLF-split attempt, or
// curl's `Name;` (send-empty-header) shorthand.
function safeHeader(raw) {
  const h = String(raw == null ? '' : raw).trim();
  if (!h || h.length > MAX_HEADER_LEN) return null;
  return HEADER_RE.test(h) ? h : null;
}

// The argv pair carrying a request body. --data-raw is --data WITHOUT the
// '@file' meaning; keep using it rather than sanitising the value, so there is
// no escaping rule to get wrong later.
function dataArgs(raw) {
  return ['--data-raw', String(raw)];
}

module.exports = { safeHeader, dataArgs, HEADER_RE, MAX_HEADER_LEN };
