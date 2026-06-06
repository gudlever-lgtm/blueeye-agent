#!/usr/bin/env node
'use strict';

// Signs a built agent release tarball with the Ed25519 RELEASE key, producing the
// manifest + detached signature that blueeye-server verifies on upload and the
// agent verifies before installing. Uses the SAME primitive as blueeye-licens
// (Node crypto Ed25519 over canonical JSON) and the SAME key tooling
// (blueeye-licens scripts/generate-signing-key.js) — but a SEPARATE release key.
//
// Usage:
//   AGENT_RELEASE_SIGNING_KEY=<base64 PKCS8 PEM> \
//     node scripts/sign-release.js <tarball> [version]
//
// Writes <tarball>.manifest.json and <tarball>.sig (base64) next to the tarball,
// and prints the upload command. The PRIVATE key never leaves the build host.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { canonicalize } = require('../src/release/canonicalize');

function die(msg) {
  process.stderr.write(`sign-release: ${msg}\n`);
  process.exit(1);
}

const tarballPath = process.argv[2];
const versionArg = process.argv[3];
if (!tarballPath) die('usage: node scripts/sign-release.js <tarball> [version]');

const keyB64 = process.env.AGENT_RELEASE_SIGNING_KEY;
if (!keyB64) die('set AGENT_RELEASE_SIGNING_KEY (base64 PKCS8 PEM from generate-signing-key.js)');

let privateKey;
try {
  const pem = Buffer.from(keyB64, 'base64').toString('utf8');
  privateKey = crypto.createPrivateKey({ key: pem, format: 'pem' });
} catch (err) {
  die(`invalid AGENT_RELEASE_SIGNING_KEY: ${err.message}`);
}

let buf;
try {
  buf = fs.readFileSync(tarballPath);
} catch (err) {
  die(`cannot read ${tarballPath}: ${err.message}`);
}
const sha256 = crypto.createHash('sha256').update(buf).digest('hex');

let version = versionArg;
if (!version) {
  try { version = require('../package.json').version; } catch { /* none */ }
}
if (!version) die('could not determine version (pass it as the 2nd argument)');

// The signed bytes: a small, canonical manifest binding version + hash + size.
const manifest = { version, sha256, size: buf.length, created_at: new Date().toISOString() };
const signature = crypto.sign(null, Buffer.from(canonicalize(manifest)), privateKey).toString('base64');

const manifestPath = `${tarballPath}.manifest.json`;
const sigPath = `${tarballPath}.sig`;
fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
fs.writeFileSync(sigPath, `${signature}\n`);

const manifestB64 = Buffer.from(JSON.stringify(manifest)).toString('base64');
process.stdout.write(`Signed ${path.basename(tarballPath)}
  version  : ${version}
  sha256   : ${sha256}
  size     : ${buf.length}
  manifest : ${manifestPath}
  signature: ${sigPath}

Upload to the server (admin JWT required) — the server verifies the signature:
  curl -fSS -X POST "$SERVER/agents/releases" \\
    -H "Authorization: Bearer $ADMIN_JWT" \\
    -H "Content-Type: application/octet-stream" \\
    -H "X-Release-Version: ${version}" \\
    -H "X-Release-Signature: ${signature}" \\
    -H "X-Release-Manifest: ${manifestB64}" \\
    --data-binary @${tarballPath}
`);
