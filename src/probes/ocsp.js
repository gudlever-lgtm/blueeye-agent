'use strict';

const crypto = require('crypto');
const der = require('./der');

// OCSP — "has this certificate been revoked?", which is the one certificate
// question a handshake never answers.
//
// Expiry, trust and name all fall out of the certificate in front of you.
// Revocation does not: a revoked certificate is still signed, still in date and
// still for the right name, and the only thing that knows it is dead is the
// issuer. A key that leaked last week presents exactly like a healthy one, so
// without this check the probe reports a compromised service as `ok`.
//
// TWO WAYS TO ASK, in this order:
//
//   * THE STAPLE (default). The handshake asks for the status with it
//     (`requestOCSP: true`) and a well-run server hands back a response the CA
//     already signed. It costs no extra connection, no extra latency and tells
//     the CA nothing about who is watching — so it is on by default.
//   * THE RESPONDER (`ocsp: 'fetch'`). No staple, so ask the issuer's OCSP
//     responder from the certificate's AIA extension directly. This is an
//     outbound HTTP request per check, to an address the inspected certificate
//     chooses, so it is OPT-IN rather than the default.
//
// WHAT IS VERIFIED. A revocation answer is only worth as much as its signature:
// anything on the path could otherwise reply "good" for a revoked certificate.
// So the response is verified against the chain's own issuer key — directly
// when the issuer signed it, or through the delegated responder certificate the
// response carries (which must itself be signed by that issuer, be in date and
// carry the OCSP-signing EKU). `signatureVerified` is tri-state: true, false
// (checked and wrong — never believed), null (no key or no supported algorithm
// to check it with). A `good` that could not be verified is reported as
// `unverified`, never as good.
//
// Privacy: an OCSP exchange carries a serial number and two hashes. No name, no
// traffic, nothing about the agent.

const OID = {
  sha1: '1.3.14.3.2.26',
  basicResponse: '1.3.6.1.5.5.7.48.1.1',
  nonce: '1.3.6.1.5.5.7.48.1.2',
  ocspSigning: '1.3.6.1.5.5.7.3.9',
};

// Signature algorithm OID → the hash crypto.verify() wants. The key object
// decides RSA vs ECDSA, so only the digest has to be named here; Ed25519 takes
// no digest at all (null), which is what crypto.verify() expects for it.
const SIG_HASH = {
  '1.2.840.113549.1.1.5': 'sha1', // sha1WithRSA
  '1.2.840.113549.1.1.11': 'sha256',
  '1.2.840.113549.1.1.12': 'sha384',
  '1.2.840.113549.1.1.13': 'sha512',
  '1.2.840.10045.4.3.1': 'sha224', // ecdsa-with-SHA224
  '1.2.840.10045.4.3.2': 'sha256',
  '1.2.840.10045.4.3.3': 'sha384',
  '1.2.840.10045.4.3.4': 'sha512',
  '1.3.101.112': null, // Ed25519
};

// RFC 5280 CRLReason, by the number a RevokedInfo carries.
const REVOCATION_REASONS = [
  'unspecified', 'keyCompromise', 'cACompromise', 'affiliationChanged', 'superseded',
  'cessationOfOperation', 'certificateHold', null, 'removeFromCRL', 'privilegeWithdrawn', 'aACompromise',
];

const RESPONSE_STATUS = ['successful', 'malformedRequest', 'internalError', 'tryLater', null, 'sigRequired', 'unauthorized'];

const MAX_RESPONSE_BYTES = 64 * 1024;

// ------------------------------------------------------------------ certificate

// The three fields of a CertID, from the certificate in hand and its issuer.
// The issuer NAME hash comes from the subject certificate's own issuer field —
// byte for byte what the issuer signed — rather than from the issuer
// certificate's subject, so a re-encoded chain cannot change it.
function certIdOf(cert) {
  const raw = cert && cert.raw;
  const issuerRaw = cert && cert.issuerCertificate && cert.issuerCertificate !== cert
    ? cert.issuerCertificate.raw : null;
  if (!Buffer.isBuffer(raw)) throw new Error('no certificate DER');
  if (!Buffer.isBuffer(issuerRaw)) throw new Error('no issuer certificate');
  const subject = tbsFields(raw);
  const issuer = tbsFields(issuerRaw);
  const spki = der.children(issuer.spki.content);
  const bits = spki[1];
  if (!bits || bits.tag !== der.TAG.BIT_STRING || bits.content.length < 2) throw new Error('no issuer public key');
  return {
    nameHash: sha1(subject.issuer.raw),
    // The BIT STRING's first byte counts unused bits; the key is what follows.
    keyHash: sha1(bits.content.subarray(1)),
    serial: subject.serial.raw,
    serialBytes: subject.serial.content,
  };
}

// The TBSCertificate fields this module reads. The optional [0] version shifts
// everything after it, which is the one thing worth getting right here.
function tbsFields(certDer) {
  const top = der.children(der.read(certDer).content);
  const f = der.children(top[0].content);
  const i = f[0] && f[0].tag === der.ctx(0) ? 1 : 0;
  const out = { serial: f[i], issuer: f[i + 2], subject: f[i + 4], spki: f[i + 5] };
  if (!out.serial || !out.issuer || !out.spki) throw new Error('unexpected certificate shape');
  return out;
}

const sha1 = (b) => crypto.createHash('sha1').update(b).digest();

// The OCSP responder the certificate names. node parses the AIA extension for
// us, under a key whose exact spelling has varied, so both are read.
function responderUrls(cert) {
  const info = (cert && cert.infoAccess) || {};
  const out = [];
  for (const key of Object.keys(info)) {
    if (!/^OCSP\b/i.test(key)) continue;
    for (const v of [].concat(info[key] || [])) {
      const url = String(v || '').trim();
      if (url) out.push(url);
    }
  }
  return out;
}

// ------------------------------------------------------------------ request

function buildRequest(certId, nonce = null) {
  const id = der.seq(
    der.seq(der.oid(OID.sha1), der.nullValue()),
    der.octetString(certId.nameHash),
    der.octetString(certId.keyHash),
    certId.serial,
  );
  const parts = [der.seq(der.seq(id))];
  if (nonce) {
    // Extension ::= SEQUENCE { extnID, extnValue OCTET STRING }, and the nonce's
    // extnValue is itself a DER OCTET STRING — hence the double wrap.
    parts.push(der.explicit(2, der.seq(der.seq(der.oid(OID.nonce), der.octetString(der.octetString(nonce))))));
  }
  return der.seq(der.seq(...parts));
}

// ------------------------------------------------------------------ response

function parseResponse(buf) {
  const kids = der.children(der.read(buf).content);
  const statusTlv = kids[0];
  if (!statusTlv || statusTlv.tag !== der.TAG.ENUMERATED) throw new Error('not an OCSP response');
  const responseStatus = statusTlv.content[0];
  if (responseStatus !== 0) {
    return { responseStatus, statusText: RESPONSE_STATUS[responseStatus] || `status ${responseStatus}` };
  }
  const bytes = kids[1];
  if (!bytes || bytes.tag !== der.ctx(0)) throw new Error('successful response with no responseBytes');
  const rb = der.children(bytes.content)[0];
  const [typeOid, respOctet] = der.children(rb.content);
  const type = der.decodeOid(typeOid.content);
  if (type !== OID.basicResponse) throw new Error(`unsupported response type ${type}`);

  const basic = der.children(der.read(respOctet.content).content);
  const tbs = basic[0];
  const sigAlg = der.decodeOid(der.children(basic[1].content)[0].content);
  const sigBits = basic[2];
  if (!sigBits || sigBits.tag !== der.TAG.BIT_STRING || !sigBits.content.length) throw new Error('no signature');
  const certsTlv = basic[3];
  const certs = certsTlv && certsTlv.tag === der.ctx(0)
    ? der.children(der.read(certsTlv.content).content).map((c) => Buffer.from(c.raw))
    : [];

  const rd = der.children(tbs.content);
  let i = rd[0] && rd[0].tag === der.ctx(0) ? 1 : 0;
  i += 1; // responderID — identity is settled by the signature, not by this.
  const producedAt = der.generalizedTime(rd[i].content);
  i += 1;
  const singles = der.children(rd[i].content).map(singleResponse);
  i += 1;
  const extensions = rd[i] && rd[i].tag === der.ctx(1) ? der.children(der.read(rd[i].content).content) : [];

  return {
    responseStatus: 0,
    statusText: 'successful',
    tbs: Buffer.from(tbs.raw),
    sigAlg,
    signature: Buffer.from(sigBits.content.subarray(1)),
    certs,
    producedAt,
    singles,
    nonce: nonceOf(extensions),
  };
}

function singleResponse(tlv) {
  const f = der.children(tlv.content);
  const id = der.children(f[0].content);
  const st = f[1];
  let status = 'unknown';
  let revokedAt = null;
  let reason = null;
  if (st.tag === der.ctx(0, false) || st.tag === der.ctx(0)) {
    status = 'good';
  } else if (st.tag === der.ctx(1)) {
    status = 'revoked';
    const ri = der.children(st.content);
    revokedAt = ri[0] ? der.generalizedTime(ri[0].content) : null;
    if (ri[1] && ri[1].tag === der.ctx(0)) {
      const code = der.read(ri[1].content).content[0];
      reason = REVOCATION_REASONS[code] || `reason ${code}`;
    }
  }
  let nextUpdate = null;
  for (const x of f.slice(3)) {
    if (x.tag === der.ctx(0)) nextUpdate = der.generalizedTime(der.read(x.content).content);
  }
  return {
    status,
    revokedAt,
    reason,
    thisUpdate: f[2] ? der.generalizedTime(f[2].content) : null,
    nextUpdate,
    hashAlg: id[0] ? der.decodeOid(der.children(id[0].content)[0].content) : null,
    nameHash: id[1] ? Buffer.from(id[1].content) : null,
    keyHash: id[2] ? Buffer.from(id[2].content) : null,
    serialBytes: id[3] ? Buffer.from(id[3].content) : null,
  };
}

function nonceOf(extensions) {
  for (const ext of extensions) {
    const f = der.children(ext.content);
    if (der.decodeOid(f[0].content) !== OID.nonce) continue;
    const value = f[f.length - 1];
    try { return Buffer.from(der.read(value.content).content); } catch { return Buffer.from(value.content); }
  }
  return null;
}

// The SingleResponse that answers about THIS certificate. A responder may
// answer about several, and believing the first one would read another
// certificate's verdict as this one's. The serial always has to match; the two
// hashes are compared as well when the response used the SHA-1 CertID we asked
// for.
function matchSingle(singles, certId) {
  return singles.find((s) => {
    if (!s.serialBytes || !s.serialBytes.equals(certId.serialBytes)) return false;
    if (s.hashAlg && s.hashAlg !== OID.sha1) return true;
    return Boolean(s.nameHash && s.keyHash && s.nameHash.equals(certId.nameHash) && s.keyHash.equals(certId.keyHash));
  }) || null;
}

// ------------------------------------------------------------------ signature

// true / false / null — see the module comment. `false` means the response was
// checked against a key that should have signed it and did not, which makes
// every verdict in it worthless.
function verifySignature(parsed, issuerKey, now) {
  if (!issuerKey) return { verified: null, note: 'no issuer key to verify against' };
  if (!(parsed.sigAlg in SIG_HASH)) return { verified: null, note: `unsupported signature algorithm ${parsed.sigAlg}` };
  const hash = SIG_HASH[parsed.sigAlg];
  let signerKey = issuerKey;
  if (parsed.certs.length) {
    const delegate = responderKey(parsed.certs[0], issuerKey, now);
    if (!delegate.key) return { verified: false, note: delegate.note };
    signerKey = delegate.key;
  }
  try {
    const verified = crypto.verify(hash, parsed.tbs, signerKey, parsed.signature);
    return { verified, note: verified ? null : 'signature does not match' };
  } catch (err) {
    return { verified: null, note: `cannot verify: ${String((err && err.message) || err)}` };
  }
}

// A delegated responder is only a responder if the issuer said so: its
// certificate must be signed by that issuer, be in date, and carry the
// OCSP-signing EKU. Skipping any of those would let any certificate the issuer
// ever signed speak for every certificate it signed.
function responderKey(certDer, issuerKey, now) {
  let x;
  try { x = new crypto.X509Certificate(certDer); } catch (err) { return { key: null, note: `unreadable responder certificate: ${String((err && err.message) || err)}` }; }
  try { if (!x.verify(issuerKey)) return { key: null, note: 'responder certificate was not signed by the issuer' }; } catch { return { key: null, note: 'responder certificate was not signed by the issuer' }; }
  const from = Date.parse(x.validFrom);
  const to = Date.parse(x.validTo);
  if (Number.isFinite(from) && from > now) return { key: null, note: 'responder certificate is not valid yet' };
  if (Number.isFinite(to) && to < now) return { key: null, note: 'responder certificate has expired' };
  // node reports the EXTENDED key usage OIDs here. A responder certificate
  // without the list at all is not one.
  const eku = Array.isArray(x.keyUsage) ? x.keyUsage : null;
  if (!eku || !eku.includes(OID.ocspSigning)) return { key: null, note: 'responder certificate may not sign OCSP responses' };
  return { key: x.publicKey, note: null };
}

// ------------------------------------------------------------------ transport

// POST the request to the responder. Deliberately plain: no redirects (a
// redirect from an OCSP responder is not a thing), a hard byte cap, and only
// http/https on the two ports a responder uses — because the URL comes out of
// the certificate being inspected, which is the one input here an attacker
// picks. `fetch` is injected, so no test touches the network.
async function httpFetch(url, body, timeoutMs) {
  const target = new URL(url);
  if (target.protocol !== 'http:' && target.protocol !== 'https:') throw new Error(`unsupported responder scheme ${target.protocol}`);
  if (target.username || target.password) throw new Error('responder url carries credentials');
  const port = target.port ? Number(target.port) : (target.protocol === 'http:' ? 80 : 443);
  if (port !== 80 && port !== 443) throw new Error(`refusing responder port ${port}`);
  const lib = require(target.protocol === 'http:' ? 'http' : 'https');
  return new Promise((resolve, reject) => {
    const req = lib.request({
      protocol: target.protocol,
      hostname: target.hostname,
      port,
      path: `${target.pathname}${target.search}`,
      method: 'POST',
      timeout: timeoutMs,
      headers: {
        'content-type': 'application/ocsp-request',
        accept: 'application/ocsp-response',
        'content-length': body.length,
      },
    }, (res) => {
      if (res.statusCode !== 200) { res.resume(); reject(new Error(`responder answered HTTP ${res.statusCode}`)); return; }
      const chunks = [];
      let size = 0;
      res.on('data', (c) => {
        size += c.length;
        if (size > MAX_RESPONSE_BYTES) { req.destroy(new Error('responder answer too large')); return; }
        chunks.push(c);
      });
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error('responder timeout')));
    req.on('error', reject);
    req.end(body);
  });
}

// ------------------------------------------------------------------ the check

// 'off' | 'staple' (default) | 'fetch'. Anything else is read as the default,
// because a typo in a probe spec should not silently turn the check off.
function ocspMode(value) {
  if (value === false || value === 'off' || value === 'none') return 'off';
  if (value === true || value === 'fetch' || value === 'aia' || value === 'always') return 'fetch';
  return 'staple';
}

const unchecked = (extra) => ({
  checked: false,
  source: null,
  status: 'unchecked',
  revoked: false,
  revokedAt: null,
  reason: null,
  responder: null,
  signatureVerified: null,
  signatureNote: null,
  producedAt: null,
  thisUpdate: null,
  nextUpdate: null,
  stale: false,
  error: null,
  ...extra,
});

async function checkRevocation({
  cert,
  staple = null,
  mode = 'staple',
  timeoutMs = 5000,
  fetch = httpFetch,
  now = () => Date.now(),
} = {}) {
  if (mode === 'off') return unchecked({ status: 'off' });
  let certId;
  try {
    certId = certIdOf(cert);
  } catch (err) {
    // A self-signed certificate has no issuer to ask, which is a fact about the
    // certificate rather than a failure of the check.
    return unchecked({ error: String((err && err.message) || err) });
  }

  const issuerKey = issuerPublicKey(cert);
  if (staple) {
    const verdict = evaluate(staple, { certId, issuerKey, now: now(), source: 'staple' });
    if (verdict.status !== 'error' || mode !== 'fetch') return verdict;
  }
  if (mode !== 'fetch') {
    return unchecked({ error: staple ? 'stapled response unusable' : 'no stapled response (ocsp: "fetch" asks the responder)' });
  }

  const [responder] = responderUrls(cert);
  if (!responder) return unchecked({ error: 'certificate names no OCSP responder' });
  const nonce = crypto.randomBytes(16);
  let body;
  try {
    body = await fetch(responder, buildRequest(certId, nonce), timeoutMs);
  } catch (err) {
    return unchecked({ status: 'error', source: 'ocsp', responder, error: String((err && (err.message || err.code)) || err) });
  }
  return evaluate(body, { certId, issuerKey, now: now(), source: 'ocsp', responder, nonce });
}

function evaluate(body, { certId, issuerKey = null, now, source, responder = null, nonce = null }) {
  let parsed;
  try {
    parsed = parseResponse(Buffer.isBuffer(body) ? body : Buffer.from(body));
  } catch (err) {
    return unchecked({ status: 'error', source, responder, error: `unreadable OCSP response: ${String((err && err.message) || err)}` });
  }
  if (parsed.responseStatus !== 0) {
    return unchecked({ status: 'error', source, responder, error: `responder said ${parsed.statusText}` });
  }
  // A nonce we sent and got back wrong is a replayed or substituted response.
  if (nonce && parsed.nonce && !parsed.nonce.equals(nonce)) {
    return unchecked({ status: 'error', source, responder, error: 'response nonce does not match the request' });
  }
  const single = matchSingle(parsed.singles, certId);
  if (!single) {
    return unchecked({ status: 'error', source, responder, error: 'response does not answer about this certificate' });
  }
  const sig = verifySignature(parsed, issuerKey, now);
  // Checked and wrong: nothing in the response may be believed, in either
  // direction — a forged "revoked" is a false alarm just as a forged "good"
  // hides a real one.
  if (sig.verified === false) {
    return unchecked({ status: 'error', source, responder, signatureVerified: false, signatureNote: sig.note, error: `OCSP response signature is not valid: ${sig.note}` });
  }
  const stale = single.nextUpdate != null && single.nextUpdate < now;
  // `good` on an unverifiable signature is reported as exactly that. Revoked is
  // reported as revoked either way: the agent does not get to decide that a
  // revocation it cannot cryptographically confirm did not happen.
  const status = single.status === 'good' && sig.verified !== true ? 'unverified' : single.status;
  return {
    checked: true,
    source,
    status,
    revoked: single.status === 'revoked',
    revokedAt: single.revokedAt != null ? new Date(single.revokedAt).toISOString() : null,
    reason: single.reason,
    responder,
    signatureVerified: sig.verified,
    signatureNote: sig.note,
    producedAt: parsed.producedAt != null ? new Date(parsed.producedAt).toISOString() : null,
    thisUpdate: single.thisUpdate != null ? new Date(single.thisUpdate).toISOString() : null,
    nextUpdate: single.nextUpdate != null ? new Date(single.nextUpdate).toISOString() : null,
    stale,
    error: null,
  };
}

// The issuer's public key, as a KeyObject. Built from the issuer certificate
// node already handed over with the chain, so the verification costs no extra
// fetch and extends no extra trust: a response is believed because the key that
// issued the certificate signed it.
function issuerPublicKey(cert) {
  const raw = cert && cert.issuerCertificate && cert.issuerCertificate !== cert ? cert.issuerCertificate.raw : null;
  if (!Buffer.isBuffer(raw)) return null;
  try { return new crypto.X509Certificate(raw).publicKey; } catch { return null; }
}

module.exports = {
  checkRevocation, evaluate, ocspMode, buildRequest, parseResponse, certIdOf, responderUrls,
  verifySignature, issuerPublicKey, matchSingle, httpFetch, OID,
};
