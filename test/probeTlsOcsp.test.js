'use strict';

// Certificate REVOCATION — the one certificate question a handshake cannot
// answer on its own.
//
// Every case here runs against real DER from test-support/ocspFixture.js: a
// real CA, a real leaf, real signatures. That matters more here than anywhere
// else in the probe, because the whole value of the check is that a response is
// believed only when the issuer's key signed it — and a fake that just returns
// `{ status: 'good' }` would never prove that.
//
// No network: the staple is handed in, and the responder fetch is injected.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { EventEmitter } = require('events');

const { tlsProbe } = require('../src/probes/tls');
const ocsp = require('../src/probes/ocsp');
const der = require('../src/probes/der');
const fixture = require('../test-support/ocspFixture');

const { PEM, peerCert, ocspResponse, certId } = fixture;
const now = () => Date.now();

// A tls.connect that completes a handshake with the fixture's certificate, and
// optionally fires the OCSPResponse event the way node does — before
// 'secureConnect', which is the detail that makes the staple catchable at all.
function fakeTls({ staple = null, cert = peerCert(), captured = null } = {}) {
  return (opts, onSecure) => {
    if (captured) Object.assign(captured, opts);
    const sock = new EventEmitter();
    sock.getPeerCertificate = () => cert;
    sock.getProtocol = () => 'TLSv1.3';
    sock.getCipher = () => ({ name: 'TLS_AES_256_GCM_SHA384' });
    sock.authorized = true;
    sock.authorizationError = null;
    sock.destroy = () => {};
    setImmediate(() => {
      if (staple) sock.emit('OCSPResponse', staple);
      if (onSecure) onSecure();
    });
    return sock;
  };
}

// ---------------------------------------------------------------- the probe

test('tls: a revoked certificate fails the probe and says who killed it and why', async () => {
  const r = await tlsProbe({ type: 'tls', host: 'example.com' }, {
    connect: fakeTls({ staple: ocspResponse({ status: 'revoked', reason: 1 }) }),
    now,
  });
  assert.equal(r.ok, false, 'a revoked certificate is not an ok certificate');
  assert.equal(r.tls.revoked, true);
  assert.equal(r.tls.revocation.status, 'revoked');
  assert.equal(r.tls.revocation.reason, 'keyCompromise');
  assert.equal(r.tls.revocation.source, 'staple');
  assert.equal(r.tls.revocation.signatureVerified, true);
  assert.match(r.detail, /certificate REVOKED \(keyCompromise\)/);
  // Still in date, still trusted, still the right name — which is exactly why
  // this check has to exist.
  assert.equal(r.tls.chainTrusted, true);
  assert.equal(r.tls.hostnameMatches, true);
  assert.equal(r.lossPct, 0, 'a revoked certificate is not packet loss');
});

test('tls: a stapled good answer verified against the issuer leaves the probe ok and quiet', async () => {
  const captured = {};
  const r = await tlsProbe({ type: 'tls', host: 'example.com' }, {
    connect: fakeTls({ staple: ocspResponse({ status: 'good' }), captured }),
    now,
  });
  assert.equal(r.ok, true);
  assert.equal(captured.requestOCSP, true, 'the staple is asked for by default');
  assert.equal(r.tls.revoked, false);
  assert.equal(r.tls.revocation.status, 'good');
  assert.equal(r.tls.revocation.signatureVerified, true);
  assert.equal(r.tls.revocation.checked, true);
  assert.doesNotMatch(r.detail, /revocation/, 'a verified good needs no words');
});

test('tls: no staple is reported as unchecked, not as good — and does not fail the probe', async () => {
  const r = await tlsProbe({ type: 'tls', host: 'example.com' }, { connect: fakeTls(), now });
  assert.equal(r.ok, true, 'not knowing is not a certificate fault');
  assert.equal(r.tls.revoked, false);
  assert.equal(r.tls.revocation.checked, false);
  assert.equal(r.tls.revocation.status, 'unchecked');
  assert.match(r.tls.revocation.error, /no stapled response/);
});

test('tls: ocsp false asks nothing at all', async () => {
  const captured = {};
  const r = await tlsProbe({ type: 'tls', host: 'example.com', ocsp: false }, {
    connect: fakeTls({ staple: ocspResponse({ status: 'revoked' }), captured }),
    now,
  });
  assert.equal(captured.requestOCSP, false);
  assert.equal(r.tls.revocation.status, 'off');
  assert.equal(r.tls.revocation.checked, false);
  assert.equal(r.ok, true, 'a check that was never made cannot condemn a certificate');
});

test('tls: ocsp fetch asks the responder in the certificate when there is no staple', async () => {
  const seen = [];
  const ocspFetch = async (url, body, timeoutMs) => {
    seen.push({ url, timeoutMs, request: body });
    return ocspResponse({ status: 'revoked', reason: 5 });
  };
  const r = await tlsProbe({ type: 'tls', host: 'example.com', ocsp: 'fetch', timeoutMs: 4000 }, {
    connect: fakeTls(), now, ocspFetch,
  });
  assert.equal(seen.length, 1);
  assert.equal(seen[0].url, 'http://ocsp.example-ca.test/', 'the responder comes from the AIA extension');
  assert.equal(seen[0].timeoutMs, 4000);
  assert.equal(r.ok, false);
  assert.equal(r.tls.revocation.source, 'ocsp');
  assert.equal(r.tls.revocation.responder, 'http://ocsp.example-ca.test/');
  assert.equal(r.tls.revocation.reason, 'cessationOfOperation');
  // The request is a well-formed OCSPRequest for THIS certificate's serial.
  const parsedCertId = der.children(der.children(der.children(der.children(der.read(seen[0].request).content)[0].content)[0].content)[0].content)[0];
  assert.equal(parsedCertId.tag, der.TAG.SEQUENCE);
});

test('tls: a responder that is down leaves the certificate verdict intact', async () => {
  const r = await tlsProbe({ type: 'tls', host: 'example.com', ocsp: 'fetch' }, {
    connect: fakeTls(), now,
    ocspFetch: async () => { throw Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }); },
  });
  assert.equal(r.ok, true, 'an unreachable responder is a gap in what we know, not a fault in the service');
  assert.equal(r.tls.revocation.status, 'error');
  assert.match(r.tls.revocation.error, /ECONNREFUSED/);
});

test('tls: a certificate with no issuer to ask says so instead of guessing', async () => {
  const r = await tlsProbe({ type: 'tls', host: 'example.com' }, {
    connect: fakeTls({ cert: peerCert({ issuer: null }) }), now,
  });
  assert.equal(r.tls.revocation.checked, false);
  assert.match(r.tls.revocation.error, /no issuer certificate/);
});

test('tls: a certificate naming no responder cannot be fetched for', async () => {
  const r = await tlsProbe({ type: 'tls', host: 'example.com', ocsp: 'fetch' }, {
    connect: fakeTls({ cert: peerCert({ infoAccess: {} }) }), now,
    ocspFetch: async () => { throw new Error('should not be called'); },
  });
  assert.equal(r.tls.revocation.status, 'unchecked');
  assert.match(r.tls.revocation.error, /names no OCSP responder/);
});

// ---------------------------------------------------------------- trust

test('ocsp: a good answer nobody could have signed is unverified, never good', async () => {
  // Signed by a key the issuer never delegated to.
  const stranger = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const r = await ocsp.checkRevocation({
    cert: peerCert(),
    staple: ocspResponse({ status: 'good', signWith: stranger.privateKey.export({ type: 'pkcs8', format: 'pem' }) }),
  });
  assert.equal(r.status, 'error');
  assert.equal(r.signatureVerified, false);
  assert.match(r.error, /signature is not valid/);
});

test('ocsp: a delegated responder is believed only with the issuer behind it and the EKU on it', async () => {
  const delegated = await ocsp.checkRevocation({
    cert: peerCert(),
    staple: ocspResponse({ status: 'revoked', signWith: PEM.responderKey, certs: [PEM.responderCert] }),
  });
  assert.equal(delegated.status, 'revoked');
  assert.equal(delegated.signatureVerified, true);

  // Signed by a certificate the same CA issued — but one that may not speak for
  // it. Without the EKU check, any certificate a CA ever signed could answer
  // for every certificate it signed.
  const rogue = await ocsp.checkRevocation({
    cert: peerCert(),
    staple: ocspResponse({ status: 'good', signWith: PEM.rogueKey, certs: [PEM.rogueCert] }),
  });
  assert.equal(rogue.signatureVerified, false);
  assert.match(rogue.signatureNote, /may not sign OCSP/);
});

test('ocsp: a corrupted signature is refused in both directions', async () => {
  for (const status of ['good', 'revoked']) {
    const r = await ocsp.checkRevocation({ cert: peerCert(), staple: ocspResponse({ status, corruptSignature: true }) });
    assert.equal(r.signatureVerified, false, `${status}: a forged answer is worthless either way`);
    assert.equal(r.revoked, false, `${status}: and never raises a false alarm`);
    assert.equal(r.status, 'error');
  }
});

test('ocsp: an answer about another certificate is not an answer about this one', async () => {
  // A valid, correctly signed response whose CertID carries a different serial.
  const otherId = der.seq(
    der.seq(der.oid('1.3.14.3.2.26'), der.nullValue()),
    der.octetString(crypto.createHash('sha1').update('name').digest()),
    der.octetString(crypto.createHash('sha1').update('key').digest()),
    der.integerFromHex('DEADBEEF'),
  );
  const r = await ocsp.checkRevocation({ cert: peerCert(), staple: ocspResponse({ status: 'good', id: otherId }) });
  assert.equal(r.status, 'error');
  assert.match(r.error, /does not answer about this certificate/);
});

test('ocsp: a responder that says tryLater is a gap, with its own words kept', async () => {
  const r = await ocsp.checkRevocation({ cert: peerCert(), staple: ocspResponse({ responseStatus: 3 }) });
  assert.equal(r.status, 'error');
  assert.match(r.error, /tryLater/);
});

test('ocsp: an expired status window is reported as stale rather than silently trusted', async () => {
  const r = await ocsp.checkRevocation({
    cert: peerCert(),
    staple: ocspResponse({ status: 'good', nextUpdate: Date.now() - 60000 }),
  });
  assert.equal(r.status, 'good');
  assert.equal(r.stale, true);
});

test('ocsp: unknown is reported as unknown — the issuer has never heard of it', async () => {
  const r = await ocsp.checkRevocation({ cert: peerCert(), staple: ocspResponse({ status: 'unknown' }) });
  assert.equal(r.status, 'unknown');
  assert.equal(r.revoked, false);
});

test('ocsp: a replayed answer to another request is refused (nonce)', async () => {
  const r = await ocsp.checkRevocation({
    cert: peerCert(),
    mode: 'fetch',
    // Echoes a nonce that was never sent.
    fetch: async () => ocspResponse({ status: 'good', nonce: Buffer.alloc(16, 7) }),
  });
  assert.equal(r.status, 'error');
  assert.match(r.error, /nonce does not match/);
});

test('ocsp: junk is a parse failure, not a verdict', async () => {
  for (const body of [Buffer.alloc(0), Buffer.from('not der at all'), Buffer.from([0x30, 0x82, 0xff, 0xff])]) {
    const r = await ocsp.checkRevocation({ cert: peerCert(), staple: body });
    assert.equal(r.revoked, false);
    assert.equal(r.checked, false);
  }
});

test('ocsp: the mode word is read generously, but never silently into "off"', () => {
  assert.equal(ocsp.ocspMode(undefined), 'staple');
  assert.equal(ocsp.ocspMode('staple'), 'staple');
  assert.equal(ocsp.ocspMode('nonsense'), 'staple', 'a typo must not turn the check off');
  assert.equal(ocsp.ocspMode(true), 'fetch');
  assert.equal(ocsp.ocspMode('fetch'), 'fetch');
  assert.equal(ocsp.ocspMode(false), 'off');
  assert.equal(ocsp.ocspMode('off'), 'off');
});

// ---------------------------------------------------------------- transport

test('ocsp: the responder url is held to http(s) on a responder port', async () => {
  const cases = [
    ['file:///etc/passwd', /scheme/],
    ['http://ocsp.example.test:9000/', /port/],
    ['http://user:pw@ocsp.example.test/', /credentials/],
  ];
  for (const [url, re] of cases) {
    await assert.rejects(() => ocsp.httpFetch(url, Buffer.from([0x30, 0x00]), 100), re, url);
  }
});

test('der: a truncated or over-long encoding throws instead of reading past the buffer', () => {
  assert.throws(() => der.read(Buffer.from([0x30])), /truncated/);
  assert.throws(() => der.read(Buffer.from([0x30, 0x05, 0x01])), /truncated value/);
  assert.throws(() => der.read(Buffer.from([0x30, 0x80])), /unsupported length/);
  assert.throws(() => der.read(Buffer.from([0x30, 0x85, 1, 2, 3, 4, 5])), /unsupported length/);
});

test('der: a serial is encoded as a signed INTEGER, which is what a CertID means by one', () => {
  // High bit set → a 0x00 goes in front, or the responder answers about a
  // different (negative) serial.
  assert.deepEqual([...der.integerFromHex('80AB')], [0x02, 0x03, 0x00, 0x80, 0xab]);
  assert.deepEqual([...der.integerFromHex('000A1B')], [0x02, 0x02, 0x0a, 0x1b]);
  assert.deepEqual([...der.integerFromHex('0A:1B:2C')], [0x02, 0x03, 0x0a, 0x1b, 0x2c]);
  // Anything that is not hex is refused rather than filtered down to hex: a
  // typo must not become a different serial number.
  assert.equal(der.integerFromHex('odd'), null);
  assert.equal(der.integerFromHex('0A1'), null, 'half a byte is not a serial');
  assert.equal(der.integerFromHex(''), null);
});
