'use strict';

const tls = require('tls');
const { clampInt, round, fail, safeHost } = require('./stats');

// TLS / certificate probe: what certificate does this port present, is it
// trusted, and how long is it good for?
//
// The http probe already reads an expiry as a side effect of fetching a URL,
// which covers a web server and nothing else. A certificate lives on any port —
// SMTP on 465, IMAP on 993, a database, an LDAP directory, a management
// interface — and the expiry is only one of the ways it fails. This probe asks
// the question directly, and reports the four answers apart:
//
//   * EXPIRY — days left, which is the one that gets diarised
//   * TRUST  — does the chain validate against the host's trust store
//   * NAME   — is the certificate actually for the host we asked for
//   * VERSION/CIPHER — what was negotiated, for the audit that asks
//
// The connection is opened with `rejectUnauthorized: false` DELIBERATELY. The
// point is to REPORT an untrusted or mismatched certificate, and a connection
// that refuses to complete cannot tell you which of the two it was — it would
// turn every certificate fault into the same blank failure. Nothing is sent and
// nothing is read: the socket is closed the moment the handshake is inspected.
//
// Privacy: metadata only. Subject, issuer, validity dates, the SAN list and the
// negotiated parameters — never traffic.
async function tlsProbe(spec, { connect = tls.connect, now = () => Date.now() } = {}) {
  const host = safeHost(spec && (spec.host || spec.target));
  const port = spec && spec.port != null ? Number(spec.port) : 443;
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
    return fail('tls', `${(spec && (spec.host || spec.target)) || ''}:${(spec && spec.port) ?? ''}`, 'invalid host/port');
  }
  const timeoutMs = clampInt(spec && spec.timeoutMs, 10000, 100, 60000);
  // SNI: which name to ask for. Defaults to the host, which is what a client
  // does; an explicit servername is how you check the certificate a particular
  // virtual host presents on a shared address.
  const servername = safeHost(spec && spec.servername) || (isIpLiteral(host) ? undefined : host);
  // The IDENTITY of the result. Two probes of one address that ask for two
  // different names are two questions — one virtual host can be fine while
  // the next serves the wrong certificate — and with `host:port` alone their
  // results shared a key on the server, so each overwrote the other's verdict
  // and finding. An explicit name that differs from the host is therefore
  // part of the target (`name@host:port`); the ordinary probe, whose SNI IS
  // its host, keeps the plain `host:port` it always had.
  const target = servername && servername.toLowerCase() !== host.toLowerCase()
    ? `${servername}@${host}:${port}`
    : `${host}:${port}`;

  const t0 = now();
  let result;
  try {
    result = await handshake({ connect, host, port, servername, timeoutMs });
  } catch (err) {
    return fail('tls', target, `tls handshake failed: ${String((err && (err.code || err.message)) || err)}`);
  }
  const rttMs = round(now() - t0);
  const { cert, authorized, authorizationError, protocol, cipher } = result;

  if (!cert || !cert.valid_to) {
    return { ...fail('tls', target, 'no certificate presented'), rttMs };
  }

  const validTo = Date.parse(cert.valid_to);
  const validFrom = Date.parse(cert.valid_from);
  const expiryDays = Number.isFinite(validTo) ? round((validTo - now()) / 86400000) : null;
  const expired = expiryDays != null && expiryDays <= 0;
  const notYetValid = Number.isFinite(validFrom) && validFrom > now();
  // Node's own reason, kept verbatim: its codes name the fault precisely
  // (CERT_HAS_EXPIRED, SELF_SIGNED_CERT_IN_CHAIN,
  // UNABLE_TO_VERIFY_LEAF_SIGNATURE, ERR_TLS_CERT_ALTNAME_INVALID) and a
  // paraphrase would lose that.
  const authError = authorized ? null : String(authorizationError || 'not authorized');
  // `authorized` is ONE flag for TWO checks. Node verifies the chain first and
  // only then the name, so ERR_TLS_CERT_ALTNAME_INVALID means the chain PASSED
  // and the name did not. Reading it as "not trusted" reported a certificate
  // for the wrong virtual host as an untrusted chain — the wrong fix (install
  // an intermediate) for a fault whose fix is to reissue or re-point the name.
  const nameRejected = !authorized && isNameError(authorizationError);
  const chainTrusted = Boolean(authorized) || nameRejected;
  const trustError = chainTrusted ? null : authError;
  const names = altNames(cert);
  // A hostname mismatch is checked separately from trust, because a chain can
  // be perfectly valid and still be for somebody else's name.
  //
  // The name checked is the one that was ASKED for: the SNI name when there is
  // one — which is the point of pointing this probe at an IP with an explicit
  // servername — and otherwise the host. An IP with no servername has no name
  // to check, and reports `null` rather than a verdict it did not reach (node
  // compares the bare IP with the certificate's IP entries, which almost no
  // certificate carries — that is not a fault in the certificate).
  const checkName = servername || (isIpLiteral(host) ? null : host);
  let nameMatches = checkName ? matchesHost(checkName, cert, names) : null;
  // Node checked this same name and said no: its verdict stands over ours
  // (it knows forms this matcher does not, such as a CN-only certificate
  // alongside IP-only SANs).
  if (checkName && nameRejected) nameMatches = false;

  const ok = chainTrusted && !expired && !notYetValid && nameMatches !== false;
  const detail = describe({ expiryDays, expired, notYetValid, trustError, nameMatches, host: checkName || host, cert, protocol });

  return {
    type: 'tls',
    target,
    ok,
    attempts: 1,
    success: ok ? 1 : 0,
    rttMs,
    minMs: rttMs,
    maxMs: rttMs,
    jitterMs: 0,
    // Loss is a reachability word and this is not a reachability probe: the
    // handshake completed either way, so reporting 100% loss for an expired
    // certificate would put a perfectly reachable host in the outage numbers.
    lossPct: 0,
    certExpiryDays: expiryDays,
    detail,
    tls: {
      protocol: protocol || null,
      cipher: (cipher && cipher.name) || null,
      // Kept as node reports them, for servers that read only these two: a
      // name mismatch is still `authorized: false` with its own code.
      authorized: Boolean(authorized),
      authorizationError: authError,
      // The two checks behind `authorized`, apart (agent 0.40+): did the chain
      // validate, and is the certificate for the name asked for.
      chainTrusted,
      hostnameMatches: nameMatches,
      // The SNI name sent (null for an IP probed without one) — what a
      // mismatch finding names.
      servername: servername || null,
      expiryDays,
      expired,
      notYetValid,
      validFrom: Number.isFinite(validFrom) ? new Date(validFrom).toISOString() : null,
      validTo: Number.isFinite(validTo) ? new Date(validTo).toISOString() : null,
      subject: nameOf(cert.subject),
      issuer: nameOf(cert.issuer),
      altNames: names.slice(0, 16),
      serialNumber: cert.serialNumber ? String(cert.serialNumber).slice(0, 64) : null,
      fingerprint256: cert.fingerprint256 ? String(cert.fingerprint256).slice(0, 128) : null,
      chainLength: chainLength(cert),
      selfSigned: isSelfSigned(cert),
    },
  };
}

function handshake({ connect, host, port, servername, timeoutMs }) {
  return new Promise((resolve, reject) => {
    let socket;
    let done = false;
    const finish = (fn, arg) => {
      if (done) return;
      done = true;
      if (socket) { try { socket.destroy(); } catch { /* ignore */ } }
      fn(arg);
    };
    try {
      socket = connect({
        host,
        port,
        servername,
        timeout: timeoutMs,
        // See the module comment: reporting WHY a certificate is unacceptable
        // is the job, and a refused handshake cannot say which fault it was.
        rejectUnauthorized: false,
      }, () => {
        finish(resolve, {
          cert: socket.getPeerCertificate ? socket.getPeerCertificate(true) : null,
          authorized: socket.authorized,
          authorizationError: socket.authorizationError,
          protocol: socket.getProtocol ? socket.getProtocol() : null,
          cipher: socket.getCipher ? socket.getCipher() : null,
        });
      });
    } catch (err) { reject(err); return; }
    socket.once('error', (err) => finish(reject, err));
    socket.once('timeout', () => finish(reject, new Error('tls timeout')));
  });
}

// One line an operator can act on, worst fault first.
function describe({ expiryDays, expired, notYetValid, trustError, nameMatches, host, cert, protocol }) {
  const issuer = nameOf(cert.issuer);
  const parts = [];
  if (expired) parts.push(`certificate EXPIRED ${Math.abs(expiryDays)}d ago`);
  else if (notYetValid) parts.push('certificate is not valid yet');
  else if (expiryDays != null) parts.push(`expires in ${expiryDays}d`);
  if (nameMatches === false) parts.push(`name mismatch — not valid for ${host}`);
  if (trustError) parts.push(`chain not trusted: ${trustError}`);
  if (issuer) parts.push(`issuer ${issuer}`);
  if (protocol) parts.push(protocol);
  return parts.join(' · ') || null;
}

const nameOf = (o) => (o && (o.CN || o.O || o.OU)) || null;

function altNames(cert) {
  if (!cert || !cert.subjectaltname) return [];
  return String(cert.subjectaltname)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

// RFC 6125 in the shape a certificate actually uses: the SAN list decides, and
// a single leading wildcard matches one label. The subject CN is only consulted
// when there is no SAN at all, which is how every current client behaves.
function matchesHost(host, cert, names) {
  const want = String(host || '').toLowerCase().replace(/\.$/, '');
  if (!want) return null;
  const candidates = names.length
    ? names.filter((n) => /^DNS:/i.test(n)).map((n) => n.slice(4).trim().toLowerCase())
    : [String(nameOf(cert.subject) || '').toLowerCase()].filter(Boolean);
  if (!candidates.length) return null;
  return candidates.some((c) => matchName(want, c));
}

function matchName(host, pattern) {
  if (!pattern) return false;
  if (pattern === host) return true;
  if (!pattern.startsWith('*.')) return false;
  const suffix = pattern.slice(1); // ".example.com"
  if (!host.endsWith(suffix)) return false;
  // A wildcard covers exactly one label: *.example.com is not a.b.example.com.
  return host.slice(0, host.length - suffix.length).indexOf('.') === -1;
}

function chainLength(cert) {
  let n = 0;
  let c = cert;
  const seen = new Set();
  while (c && !seen.has(c)) {
    seen.add(c);
    n += 1;
    // A self-signed root points at itself, which would otherwise loop.
    c = c.issuerCertificate && c.issuerCertificate !== c ? c.issuerCertificate : null;
    if (n > 12) break;
  }
  return n;
}

const isSelfSigned = (cert) => Boolean(cert && cert.issuerCertificate === cert);
// Node's hostname-check failure: the code on current releases, the message
// text on the oldest ones.
const isNameError = (e) => /ERR_TLS_CERT_ALTNAME_INVALID|does not match certificate's altnames/i.test(String(e || ''));
const isIpLiteral = (h) => require('net').isIP(String(h || '')) !== 0;

module.exports = { tlsProbe, matchName };
