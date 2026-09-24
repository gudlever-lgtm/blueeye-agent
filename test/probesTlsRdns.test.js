'use strict';

// The TLS/certificate and reverse-DNS probes.
//
// Both are pure Node (tls + dns), so every case here runs with an injected
// connector or resolver and no network — including the certificate faults,
// which are the point of the TLS probe and the hardest thing to arrange
// against a real host.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('events');

const { tlsProbe, matchName } = require('../src/probes/tls');
const { rdnsProbe } = require('../src/probes/rdns');
const { runProbe, PROBE_TYPES } = require('../src/probes');

const DAY = 86400000;
const NOW = Date.UTC(2026, 5, 1, 12, 0, 0);
const at = (days) => new Date(NOW + days * DAY).toUTCString();

// A certificate as node's getPeerCertificate(true) hands it over.
function cert({ days = 90, cn = 'example.com', san = 'DNS:example.com, DNS:www.example.com', issuer = 'Example CA', selfSigned = false } = {}) {
  const c = {
    subject: { CN: cn },
    issuer: { O: issuer, CN: issuer },
    valid_from: at(-30),
    valid_to: at(days),
    subjectaltname: san,
    serialNumber: '0A1B2C',
    fingerprint256: 'AA:BB:CC',
  };
  c.issuerCertificate = selfSigned ? c : { subject: { CN: issuer }, issuer: { CN: 'Root' }, issuerCertificate: null };
  return c;
}

// A fake tls.connect that completes a handshake with the given peer state.
function fakeTls({ peer, authorized = true, authorizationError = null, protocol = 'TLSv1.3', cipher = 'TLS_AES_256_GCM_SHA384', fail = null, captured = null } = {}) {
  return (opts, onSecure) => {
    if (captured) Object.assign(captured, opts);
    const sock = new EventEmitter();
    sock.getPeerCertificate = () => peer;
    sock.getProtocol = () => protocol;
    sock.getCipher = () => ({ name: cipher });
    sock.authorized = authorized;
    sock.authorizationError = authorizationError;
    sock.destroy = () => {};
    setImmediate(() => {
      if (fail) sock.emit('error', fail);
      else if (onSecure) onSecure();
    });
    return sock;
  };
}

const now = () => NOW;

// ---------------------------------------------------------------- tls
test('tls: a good certificate reports what was negotiated and how long it is good for', async () => {
  const captured = {};
  const r = await tlsProbe({ type: 'tls', host: 'example.com', port: 443 }, { connect: fakeTls({ peer: cert({ days: 90 }), captured }), now });
  assert.equal(r.ok, true);
  assert.equal(r.type, 'tls');
  assert.equal(r.target, 'example.com:443');
  assert.equal(r.certExpiryDays, 90);
  assert.equal(r.tls.protocol, 'TLSv1.3');
  assert.equal(r.tls.cipher, 'TLS_AES_256_GCM_SHA384');
  assert.equal(r.tls.authorized, true);
  assert.equal(r.tls.hostnameMatches, true);
  assert.equal(r.tls.issuer, 'Example CA');
  assert.equal(r.tls.subject, 'example.com');
  assert.deepEqual(r.tls.altNames, ['DNS:example.com', 'DNS:www.example.com']);
  assert.equal(r.tls.chainLength, 2);
  assert.match(r.detail, /expires in 90d/);
  // SNI is what a client would send.
  assert.equal(captured.servername, 'example.com');
  // The handshake succeeded, so this is not a reachability failure.
  assert.equal(r.lossPct, 0);
});

test('tls: an expired certificate is a failure that says how long ago', async () => {
  const r = await tlsProbe({ type: 'tls', host: 'example.com' }, { connect: fakeTls({ peer: cert({ days: -5 }), authorized: false, authorizationError: 'CERT_HAS_EXPIRED' }), now });
  assert.equal(r.ok, false);
  assert.equal(r.tls.expired, true);
  assert.equal(r.certExpiryDays, -5);
  assert.match(r.detail, /EXPIRED 5d ago/);
  // The chain's own code is kept verbatim — it names the fault precisely.
  assert.equal(r.tls.authorizationError, 'CERT_HAS_EXPIRED');
  assert.equal(r.lossPct, 0, 'a certificate fault is not packet loss');
});

test('tls: an untrusted chain and a name mismatch are told apart', async () => {
  const selfSigned = await tlsProbe({ type: 'tls', host: 'example.com' }, {
    connect: fakeTls({ peer: cert({ selfSigned: true, issuer: 'example.com' }), authorized: false, authorizationError: 'DEPTH_ZERO_SELF_SIGNED_CERT' }),
    now,
  });
  assert.equal(selfSigned.ok, false);
  assert.equal(selfSigned.tls.selfSigned, true);
  assert.equal(selfSigned.tls.hostnameMatches, true, 'the name is right — it is the trust that is wrong');
  assert.match(selfSigned.detail, /chain not trusted: DEPTH_ZERO_SELF_SIGNED_CERT/);

  // A perfectly valid chain, for somebody else's name.
  const wrongName = await tlsProbe({ type: 'tls', host: 'mail.example.dk' }, {
    connect: fakeTls({ peer: cert({ cn: 'example.com', san: 'DNS:example.com' }) }),
    now,
  });
  assert.equal(wrongName.ok, false);
  assert.equal(wrongName.tls.authorized, true, 'the chain is fine');
  assert.equal(wrongName.tls.hostnameMatches, false);
  assert.match(wrongName.detail, /name mismatch — not valid for mail\.example\.dk/);
});

test('tls: a wildcard covers one label and no more', () => {
  assert.equal(matchName('mail.example.com', '*.example.com'), true);
  assert.equal(matchName('a.b.example.com', '*.example.com'), false, 'a wildcard is not a suffix match');
  assert.equal(matchName('example.com', '*.example.com'), false);
  assert.equal(matchName('example.com', 'example.com'), true);
  assert.equal(matchName('example.com', ''), false);
});

test('tls: an explicit servername checks the certificate that name is served', async () => {
  const captured = {};
  const r = await tlsProbe({ type: 'tls', host: '10.0.0.5', port: 8443, servername: 'mail.example.com' }, {
    connect: fakeTls({ peer: cert({ cn: 'mail.example.com', san: 'DNS:mail.example.com' }), captured }),
    now,
  });
  assert.equal(captured.servername, 'mail.example.com');
  // Deliberately changed (agent 0.40): the explicit name is part of the
  // target, so a second probe of 10.0.0.5:8443 for another name is a second
  // result on the server rather than an overwrite of this one.
  assert.equal(r.target, 'mail.example.com@10.0.0.5:8443');
  assert.equal(r.tls.servername, 'mail.example.com');
  assert.equal(r.tls.hostnameMatches, true, 'the name checked is the SNI name, not the IP');
  assert.equal(r.ok, true);
});

test('tls: two names on one address are two targets; the ordinary probe keeps host:port', async () => {
  const good = await tlsProbe({ type: 'tls', host: '10.0.0.5', port: 8443, servername: 'mail.example.com' }, {
    connect: fakeTls({ peer: cert({ cn: 'mail.example.com', san: 'DNS:mail.example.com' }) }), now,
  });
  const wrong = await tlsProbe({ type: 'tls', host: '10.0.0.5', port: 8443, servername: 'wrong.example.com' }, {
    connect: fakeTls({ peer: cert({ cn: 'mail.example.com', san: 'DNS:mail.example.com' }), authorized: false, authorizationError: 'ERR_TLS_CERT_ALTNAME_INVALID' }), now,
  });
  assert.notEqual(good.target, wrong.target, 'a valid and a mismatched name on one port must not share a key');
  assert.equal(wrong.target, 'wrong.example.com@10.0.0.5:8443');
  // No explicit name, or one that is the host itself: unchanged.
  const plain = await tlsProbe({ type: 'tls', host: 'example.com', port: 443 }, { connect: fakeTls({ peer: cert() }), now });
  assert.equal(plain.target, 'example.com:443');
  assert.equal(plain.tls.servername, 'example.com');
  const same = await tlsProbe({ type: 'tls', host: 'Example.com', port: 443, servername: 'example.com' }, { connect: fakeTls({ peer: cert() }), now });
  assert.equal(same.target, 'Example.com:443');
  const ip = await tlsProbe({ type: 'tls', host: '10.0.0.5' }, { connect: fakeTls({ peer: cert() }), now });
  assert.equal(ip.target, '10.0.0.5:443');
  assert.equal(ip.tls.servername, null);
});

test('tls: node\'s ALTNAME error is a name mismatch on a trusted chain, not an untrusted chain', async () => {
  // Node verifies the chain BEFORE the hostname, so this code only ever means
  // "the chain validated; the name did not". E2E: reported as "chain not
  // trusted: ERR_TLS_CERT_ALTNAME_INVALID".
  const r = await tlsProbe({ type: 'tls', host: '203.0.113.2', port: 8443, servername: 'wrong.example.com' }, {
    connect: fakeTls({ peer: cert({ cn: 'right.example.com', san: 'DNS:right.example.com' }), authorized: false, authorizationError: 'ERR_TLS_CERT_ALTNAME_INVALID' }),
    now,
  });
  assert.equal(r.ok, false);
  assert.equal(r.tls.chainTrusted, true, 'the chain is fine');
  assert.equal(r.tls.hostnameMatches, false);
  // Backward-compatible fields, as node reported them.
  assert.equal(r.tls.authorized, false);
  assert.equal(r.tls.authorizationError, 'ERR_TLS_CERT_ALTNAME_INVALID');
  assert.equal(r.tls.servername, 'wrong.example.com');
  assert.match(r.detail, /name mismatch — not valid for wrong\.example\.com/);
  assert.doesNotMatch(r.detail, /chain not trusted/);

  // Node's verdict stands even where this matcher would have said yes.
  const cnOnly = await tlsProbe({ type: 'tls', host: 'example.com' }, {
    connect: fakeTls({ peer: cert(), authorized: false, authorizationError: 'ERR_TLS_CERT_ALTNAME_INVALID' }),
    now,
  });
  assert.equal(cnOnly.tls.hostnameMatches, false);
  assert.equal(cnOnly.tls.chainTrusted, true);

  // An IP with no name asked for: node compared the bare IP with the
  // certificate's IP entries. That is no fault of the certificate, and the
  // probe does not fail on it.
  const bareIp = await tlsProbe({ type: 'tls', host: '203.0.113.2', port: 8443 }, {
    connect: fakeTls({ peer: cert(), authorized: false, authorizationError: 'ERR_TLS_CERT_ALTNAME_INVALID' }),
    now,
  });
  assert.equal(bareIp.tls.chainTrusted, true);
  assert.equal(bareIp.tls.hostnameMatches, null);
  assert.equal(bareIp.ok, true);
  assert.doesNotMatch(bareIp.detail, /chain not trusted/);
});

test('tls: a genuinely untrusted chain is still chainTrusted:false', async () => {
  const r = await tlsProbe({ type: 'tls', host: 'example.com' }, {
    connect: fakeTls({ peer: cert({ selfSigned: true }), authorized: false, authorizationError: 'DEPTH_ZERO_SELF_SIGNED_CERT' }),
    now,
  });
  assert.equal(r.tls.chainTrusted, false);
  assert.equal(r.ok, false);
  const good = await tlsProbe({ type: 'tls', host: 'example.com' }, { connect: fakeTls({ peer: cert() }), now });
  assert.equal(good.tls.chainTrusted, true);
});

test('tls: an IP target is not name-checked, because there is no name to check', async () => {
  const captured = {};
  const r = await tlsProbe({ type: 'tls', host: '10.0.0.5' }, { connect: fakeTls({ peer: cert(), captured }), now });
  assert.equal(r.tls.hostnameMatches, null);
  assert.equal(captured.servername, undefined, 'SNI with an IP literal is not valid');
});

test('tls: a refused or hung handshake fails with the reason, and never throws', async () => {
  const refused = await tlsProbe({ type: 'tls', host: 'example.com' }, { connect: fakeTls({ fail: Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }) }), now });
  assert.equal(refused.ok, false);
  assert.match(refused.error, /ECONNREFUSED/);

  const noCert = await tlsProbe({ type: 'tls', host: 'example.com' }, { connect: fakeTls({ peer: {} }), now });
  assert.equal(noCert.ok, false);
  assert.match(noCert.error, /no certificate/);

  for (const bad of [{}, { host: '' }, { host: '-rf' }, { host: 'example.com', port: 0 }, { host: 'example.com', port: 99999 }]) {
    // eslint-disable-next-line no-await-in-loop
    const r = await tlsProbe({ type: 'tls', ...bad }, { connect: fakeTls({ peer: cert() }), now });
    assert.equal(r.ok, false, JSON.stringify(bad));
    assert.match(r.error, /invalid host\/port/, JSON.stringify(bad));
  }
});

// ---------------------------------------------------------------- rdns
const resolvers = ({ address = '93.184.216.34', names = ['host.example.com'], back = ['93.184.216.34'], reverseErr = null, lookupErr = null, backErr = null } = {}) => ({
  lookup: async () => { if (lookupErr) throw lookupErr; return { address }; },
  reverse: async () => { if (reverseErr) throw reverseErr; return names; },
  resolve4: async () => { if (backErr) throw backErr; return back; },
  resolve6: async () => { if (backErr) throw backErr; return back; },
  now,
});

test('rdns: a forward-confirmed PTR is the good answer, and says so', async () => {
  const r = await rdnsProbe({ type: 'rdns', host: 'example.com' }, resolvers());
  assert.equal(r.ok, true);
  assert.equal(r.type, 'rdns');
  assert.equal(r.target, 'example.com');
  assert.equal(r.address, '93.184.216.34');
  assert.deepEqual(r.ptrNames, ['host.example.com']);
  assert.equal(r.forwardConfirmed, true);
  assert.match(r.detail, /host\.example\.com \(forward-confirmed\)/);
});

test('rdns: a PTR that does not lead back is reported as exactly that', async () => {
  // The fault that looks fine until somebody checks it — which is what a
  // receiving mail server does.
  const r = await rdnsProbe({ type: 'rdns', host: '93.184.216.34' }, resolvers({ back: ['10.9.9.9'] }));
  assert.equal(r.ok, true, 'there IS a PTR — the check that failed is the confirmation');
  assert.equal(r.forwardConfirmed, false);
  assert.match(r.detail, /does not resolve back to 93\.184\.216\.34/);
});

test('rdns: no PTR at all is the answer, not a broken probe', async () => {
  const r = await rdnsProbe({ type: 'rdns', host: '10.0.0.7' }, resolvers({ reverseErr: Object.assign(new Error('nope'), { code: 'ENOTFOUND' }) }));
  assert.equal(r.ok, false);
  assert.equal(r.forwardConfirmed, false);
  assert.deepEqual(r.ptrNames, []);
  assert.match(r.error, /no PTR record/);
});

test('rdns: an IP target skips the forward lookup, a name does not', async () => {
  let looked = 0;
  const deps = { ...resolvers(), lookup: async () => { looked += 1; return { address: '93.184.216.34' }; } };
  await rdnsProbe({ type: 'rdns', host: '93.184.216.34' }, deps);
  assert.equal(looked, 0, 'an address does not need resolving first');
  await rdnsProbe({ type: 'rdns', host: 'example.com' }, deps);
  assert.equal(looked, 1);
});

test('rdns: a name that does not resolve fails with that reason, not with a reverse error', async () => {
  const r = await rdnsProbe({ type: 'rdns', host: 'nope.example' }, resolvers({ lookupErr: Object.assign(new Error('x'), { code: 'ENOTFOUND' }) }));
  assert.equal(r.ok, false);
  assert.match(r.error, /forward lookup failed: ENOTFOUND/);
  assert.equal(r.address, null);
  for (const bad of [{}, { host: '   ' }]) {
    // eslint-disable-next-line no-await-in-loop
    const bad2 = await rdnsProbe({ type: 'rdns', ...bad }, resolvers());
    assert.equal(bad2.ok, false);
  }
});

test('rdns: a confirmation lookup that fails does not claim the PTR is confirmed', async () => {
  const r = await rdnsProbe({ type: 'rdns', host: '93.184.216.34' }, resolvers({ backErr: Object.assign(new Error('x'), { code: 'ESERVFAIL' }) }));
  assert.equal(r.forwardConfirmed, false);
  assert.match(r.detail, /ESERVFAIL/);
});

// ---------------------------------------------------------------- dispatcher
test('both are dispatchable by type, and an unknown type still cannot crash the agent', async () => {
  assert.ok(PROBE_TYPES.includes('tls'));
  assert.ok(PROBE_TYPES.includes('rdns'));
  const r = await runProbe({ type: 'tls', host: 'example.com' }, { tls: { connect: fakeTls({ peer: cert() }), now } });
  assert.equal(r.type, 'tls');
  assert.ok(r.ts, 'every result is stamped');
  const unknown = await runProbe({ type: 'nope', host: 'x' });
  assert.equal(unknown.ok, false);
});
