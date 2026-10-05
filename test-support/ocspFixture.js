'use strict';

// A static CA / leaf / OCSP-responder set, and an OCSP response builder, for
// the revocation tests.
//
// Generated once with openssl (EC P-256, valid until 2036) and checked in for
// the same reason test-support/selfsigned.js is: the revocation path has to be
// exercised against REAL DER — a real chain, a real signature, a real
// delegated-responder certificate — and a test that cannot arrange one ends up
// testing only the shape of its own fakes. Never used in production.
//
// `ocspResponse()` builds what a responder would send, so a test can say
// "revoked, signed by the CA" or "good, signed by something that may not sign"
// and watch the probe's verdict.

const crypto = require('crypto');
const der = require('../src/probes/der');

const PEM = {
  caCert: "-----BEGIN CERTIFICATE-----\nMIIBizCCATGgAwIBAgIUbRyy3Tx43st/yPD6/u3sEpQKCqUwCgYIKoZIzj0EAwIw\nGzEZMBcGA1UEAwwQQmx1ZUV5ZXMgVGVzdCBDQTAeFw0yNjEwMDUxNTM5MzVaFw0z\nNjEwMDIxNTM5MzVaMBsxGTAXBgNVBAMMEEJsdWVFeWVzIFRlc3QgQ0EwWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAASU1ejb0Rk6nAegbB9AQl+RfL2aurLZRqaIE7z4\nODLVo4BG4qqOeZORv/u4mMQhulefgIoTg6UjIuqvWJI7aD1Io1MwUTAdBgNVHQ4E\nFgQUg/cHWb8aRLyLj5591dyMCqim64AwHwYDVR0jBBgwFoAUg/cHWb8aRLyLj559\n1dyMCqim64AwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEAjJ2Q\nJ/0jSEI+BLEqn90CK+k1q+9hiyrlVRZNmU5DckcCIA4Vp3ZXgy8hjF0hcFmovlf8\nTEwTsoRHMNy7Z3PlXX5S\n-----END CERTIFICATE-----\n",
  caKey: "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVHUHj6ATbTtJqc3D\nYnvDIumvPtO0HJBgZ53f7rxH222hRANCAASU1ejb0Rk6nAegbB9AQl+RfL2aurLZ\nRqaIE7z4ODLVo4BG4qqOeZORv/u4mMQhulefgIoTg6UjIuqvWJI7aD1I\n-----END PRIVATE KEY-----\n",
  leafCert: "-----BEGIN CERTIFICATE-----\nMIIB1TCCAXugAwIBAgIEChssPTAKBggqhkjOPQQDAjAbMRkwFwYDVQQDDBBCbHVl\nRXllcyBUZXN0IENBMB4XDTI2MTAwNTE1MzkzNVoXDTM2MTAwMjE1MzkzNVowFjEU\nMBIGA1UEAwwLZXhhbXBsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATC\nc22kMtOXdYdNu/zCOm49Ba93NH71q7jhBhrwMJYLJz7QKUg+YhMXbY0HYRmuFobo\n2omQ9JOghJa8bakAPKtco4GxMIGuMCcGA1UdEQQgMB6CC2V4YW1wbGUuY29tgg93\nd3cuZXhhbXBsZS5jb20wOAYIKwYBBQUHAQEELDAqMCgGCCsGAQUFBzABhhxodHRw\nOi8vb2NzcC5leGFtcGxlLWNhLnRlc3QvMAkGA1UdEwQCMAAwHQYDVR0OBBYEFKnL\nz8rSOYSl0ytk+kqk6qPmLXpaMB8GA1UdIwQYMBaAFIP3B1m/GkS8i4+efdXcjAqo\npuuAMAoGCCqGSM49BAMCA0gAMEUCIE6NeaHWnlt7l6VuELTILsrp5jEXfEd4xeNX\nfjxeAtLiAiEA3UpgXeitMvXKHk0Ug57fjKTkkEbiFvf2V49ywwA+CG8=\n-----END CERTIFICATE-----\n",
  leafKey: "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgeXd05jfk6b9T1PcE\nBkmEOH+J4GjVhWXGJQs9JcjvuV2hRANCAATCc22kMtOXdYdNu/zCOm49Ba93NH71\nq7jhBhrwMJYLJz7QKUg+YhMXbY0HYRmuFobo2omQ9JOghJa8bakAPKtc\n-----END PRIVATE KEY-----\n",
  responderCert: "-----BEGIN CERTIFICATE-----\nMIIBhDCCASugAwIBAgIBdzAKBggqhkjOPQQDAjAbMRkwFwYDVQQDDBBCbHVlRXll\ncyBUZXN0IENBMB4XDTI2MTAwNTE1MzkzNVoXDTM2MTAwMjE1MzkzNVowGTEXMBUG\nA1UEAwwOT0NTUCBSZXNwb25kZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARW\nwDaLS0qSi3lVJlmKUeCD6pV12AGtl/T8C6zZLIQWMsuBQZpyDYPa4/Ea/hjePArM\nIMKwqmbjNuEMCBwtG8R4o2IwYDATBgNVHSUEDDAKBggrBgEFBQcDCTAJBgNVHRME\nAjAAMB0GA1UdDgQWBBSFHi7EakUci/TGtutU/FWisBuwJjAfBgNVHSMEGDAWgBSD\n9wdZvxpEvIuPnn3V3IwKqKbrgDAKBggqhkjOPQQDAgNHADBEAiA4zgMPB1f4j7dP\nKlP+rtMqvNaOm2klhDvcWXbbKXBG/wIgfb5p08xd5KPEQAbNh1yKa8xhEwwRdoqH\n2hQanEVVKBw=\n-----END CERTIFICATE-----\n",
  responderKey: "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg8T2N9PDjF8y1xkpJ\niADMlj9H7/SYnLxoRdnmyx0rh5qhRANCAARWwDaLS0qSi3lVJlmKUeCD6pV12AGt\nl/T8C6zZLIQWMsuBQZpyDYPa4/Ea/hjePArMIMKwqmbjNuEMCBwtG8R4\n-----END PRIVATE KEY-----\n",
  rogueCert: "-----BEGIN CERTIFICATE-----\nMIIBETCBuQIBeDAKBggqhkjOPQQDAjAbMRkwFwYDVQQDDBBCbHVlRXllcyBUZXN0\nIENBMB4XDTI2MTAwNTE1MzkzNVoXDTM2MTAwMjE1MzkzNVowEDEOMAwGA1UEAwwF\nUm9ndWUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATn7kyqOgK3mP+FhzTEPzxT\nXPQauFtHm+yItZDO0iR0kTF19zJeL/UgR73b5BjULKze6bVRzwyiV8uNdQfGDU8r\nMAoGCCqGSM49BAMCA0cAMEQCIFvcNU7JaIZ8nD85FODDOI8pRu0x6R+EQAxiRTR0\n4K3eAiBdd5UJwxkV4GaXDfoE8lXj0P7RtYKqgnWHmVgmSl+XFw==\n-----END CERTIFICATE-----\n",
  rogueKey: "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgdAATtX9CorO8og/r\nlZ3Ycj09yI1o1wJHrJTZSVRFlJ6hRANCAATn7kyqOgK3mP+FhzTEPzxTXPQauFtH\nm+yItZDO0iR0kTF19zJeL/UgR73b5BjULKze6bVRzwyiV8uNdQfGDU8r\n-----END PRIVATE KEY-----\n",};

const SHA256_ECDSA = '1.2.840.10045.4.3.2';
const BASIC_RESPONSE = '1.3.6.1.5.5.7.48.1.1';
const NONCE = '1.3.6.1.5.5.7.48.1.2';
const SHA1 = '1.3.14.3.2.26';

const derOf = (pem) => new crypto.X509Certificate(pem).raw;

// 'YYYYMMDDHHMMSSZ' — the only form DER allows, and the only one the parser
// accepts: no separators, no fractional seconds.
const generalizedTime = (ms) => der.tlv(0x18, Buffer.from(
  new Date(ms).toISOString().replace(/[-:T]/g, '').replace(/\.\d{3}Z$/, 'Z'), 'latin1'));
const bitString = (b) => der.tlv(0x03, Buffer.concat([Buffer.from([0x00]), b]));

// The CertID the responder answers with. Built the same way the probe builds
// its request (issuer name hash + issuer key hash + serial), so a test can also
// hand back a DELIBERATELY wrong one and see it refused.
function certId({ leaf = PEM.leafCert, issuer = PEM.caCert } = {}) {
  const { certIdOf } = require('../src/probes/ocsp');
  const id = certIdOf(peerCert({ leaf, issuer }));
  return der.seq(
    der.seq(der.oid(SHA1), der.nullValue()),
    der.octetString(id.nameHash),
    der.octetString(id.keyHash),
    id.serial,
  );
}

// What node's getPeerCertificate(true) hands over, for the fields this probe
// reads: the DER, the issuer's DER, and the parsed AIA.
function peerCert({ leaf = PEM.leafCert, issuer = PEM.caCert, infoAccess } = {}) {
  const x = new crypto.X509Certificate(leaf);
  const cert = {
    raw: x.raw,
    subject: { CN: 'example.com' },
    issuer: { CN: 'BlueEyes Test CA' },
    valid_from: new Date(x.validFrom).toUTCString(),
    valid_to: new Date(x.validTo).toUTCString(),
    subjectaltname: 'DNS:example.com, DNS:www.example.com',
    serialNumber: x.serialNumber,
    fingerprint256: x.fingerprint256,
    infoAccess: infoAccess !== undefined ? infoAccess : { 'OCSP - URI': ['http://ocsp.example-ca.test/'] },
  };
  cert.issuerCertificate = issuer ? { raw: derOf(issuer), subject: { CN: 'BlueEyes Test CA' }, issuer: { CN: 'BlueEyes Test CA' } } : null;
  if (!issuer) cert.issuerCertificate = cert; // self-signed: nobody to ask
  return cert;
}

// A complete OCSP response, DER, as a responder would send it.
//
//   status      'good' | 'revoked' | 'unknown'
//   signWith    the PEM private key that signs it (default: the CA's)
//   certs       responder certificates to embed (default: none — the CA signed)
//   responseStatus  a non-zero OCSP responseStatus (tryLater, …) instead
function ocspResponse({
  status = 'good',
  signWith = PEM.caKey,
  certs = [],
  id = certId(),
  now = Date.now(),
  thisUpdate = null,
  nextUpdate = null,
  revokedAt = null,
  reason = null,
  nonce = null,
  responseStatus = 0,
  corruptSignature = false,
} = {}) {
  if (responseStatus !== 0) {
    return der.seq(der.tlv(0x0a, Buffer.from([responseStatus])));
  }
  let certStatus;
  if (status === 'good') certStatus = Buffer.from([0x80, 0x00]);
  else if (status === 'unknown') certStatus = Buffer.from([0x82, 0x00]);
  else {
    const parts = [generalizedTime(revokedAt == null ? now - 86400000 : revokedAt)];
    if (reason != null) parts.push(der.explicit(0, der.tlv(0x0a, Buffer.from([reason]))));
    certStatus = der.tlv(0xa1, Buffer.concat(parts));
  }
  const single = der.seq(
    id,
    certStatus,
    generalizedTime(thisUpdate == null ? now - 3600000 : thisUpdate),
    der.explicit(0, generalizedTime(nextUpdate == null ? now + 86400000 : nextUpdate)),
  );
  const parts = [
    der.explicit(2, der.octetString(crypto.createHash('sha1').update('responder').digest())),
    generalizedTime(now),
    der.seq(single),
  ];
  if (nonce) parts.push(der.explicit(1, der.seq(der.seq(der.oid(NONCE), der.octetString(der.octetString(nonce))))));
  const tbs = der.seq(...parts);
  let signature = crypto.sign('sha256', tbs, crypto.createPrivateKey(signWith));
  if (corruptSignature) { signature = Buffer.from(signature); signature[signature.length - 1] ^= 0xff; }
  const basic = der.seq(
    tbs,
    der.seq(der.oid(SHA256_ECDSA)),
    bitString(signature),
    ...(certs.length ? [der.explicit(0, der.seq(...certs.map((pem) => derOf(pem))))] : []),
  );
  return der.seq(
    der.tlv(0x0a, Buffer.from([0x00])),
    der.explicit(0, der.seq(der.oid(BASIC_RESPONSE), der.octetString(basic))),
  );
}

module.exports = { PEM, peerCert, certId, ocspResponse, derOf, generalizedTime };
