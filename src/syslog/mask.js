'use strict';

// Redacts credentials out of a syslog message BEFORE it leaves the agent, so a
// secret a device logged never reaches the server's database, its backups or an
// operator's screen. Masking here rather than on ingest is deliberate: the
// narrowest place to hold the unmasked text is the process that received it.
//
// The keyword list is the same one blueeye-server/src/config/mask.js applies to
// device configuration, for the same reason — over-masking is cheaper than a
// leak. What is NOT shared is that module's maskIps(): in a device config an IP
// literal is incidental, but in a syslog line it is the whole message
// ("OSPF neighbor 10.14.0.9 ... FULL to DOWN"). Masking it would leave a line
// that says a neighbour went down and refuses to say which. Private-address
// policy is unaffected: nothing here is geolocated.

const SECRET_KEYWORD_RE =
  /(\b(?:password|passwd|pwd|secret|community|pre-shared-key|pre-shared|psk|credential|private-key|key-string|auth-key|wpa-psk|token|bearer|api[-_]?key)\b\s*[:= ]?\s*)(\S+)/gi;

// A bare "Authorization: <value>" header echoed into a log line. Unlike the
// keyword rule above this runs to end of line, because the value is a SCHEME
// plus a credential ("Basic dXNlcjpwdw==") and masking only the first token
// would leave the credential itself in plain sight. Same reasoning as the
// to-EOL rule in blueeye-server/src/config/mask.js.
const AUTH_HEADER_RE = /(\bauthorization\s*:\s*).+$/gim;

// Something shaped like a JWT or a long opaque credential sitting on its own.
const LONG_TOKEN_RE = /\b(?:[A-Za-z0-9_-]{12,}\.){2}[A-Za-z0-9_-]{12,}\b/g;

// Masks one message. Returns the input unchanged when it holds nothing secret,
// so the common case allocates nothing new beyond the regex scan.
function maskSyslogMessage(text) {
  if (typeof text !== 'string' || !text) return text;
  return text
    .replace(SECRET_KEYWORD_RE, '$1[redacted]')
    .replace(AUTH_HEADER_RE, '$1[redacted]')
    .replace(LONG_TOKEN_RE, '[redacted]');
}

module.exports = { maskSyslogMessage };
