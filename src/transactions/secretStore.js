'use strict';

const crypto = require('crypto');

// AES-256-GCM box for transaction-test secrets, keyed by a value DERIVED from the
// agent's token (scrypt). Secrets are only ever persisted to disk ENCRYPTED; the
// plaintext lives in memory. Self-describing token format:
//   v1.gcm.<ivB64url>.<tagB64url>.<ciphertextB64url>
// A missing key or a tampered/garbled token decrypts to '' (fail-safe, never
// throws) — the caller simply gets no secret rather than a crash.

const KEY_LEN = 32;
const IV_LEN = 12;
const SALT = Buffer.from('blueeye-agent/tx-secrets/v1', 'utf8');

function deriveKey(token) {
  if (typeof token !== 'string' || token.length === 0) return null;
  return crypto.scryptSync(token, SALT, KEY_LEN);
}

function createSecretStore(token) {
  const key = deriveKey(token);

  function encrypt(plain) {
    if (plain === null || plain === undefined || plain === '' || !key) return '';
    const iv = crypto.randomBytes(IV_LEN);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ct = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return ['v1', 'gcm', iv.toString('base64url'), tag.toString('base64url'), ct.toString('base64url')].join('.');
  }

  function decrypt(token2) {
    if (!token2 || !key) return '';
    const p = String(token2).split('.');
    if (p.length !== 5 || p[0] !== 'v1' || p[1] !== 'gcm') return '';
    try {
      const iv = Buffer.from(p[2], 'base64url');
      const tag = Buffer.from(p[3], 'base64url');
      const ct = Buffer.from(p[4], 'base64url');
      const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
      d.setAuthTag(tag);
      return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
    } catch {
      return '';
    }
  }

  function encryptJson(obj) { return encrypt(JSON.stringify(obj == null ? {} : obj)); }
  function decryptJson(token2) { const s = decrypt(token2); if (!s) return {}; try { return JSON.parse(s); } catch { return {}; } }

  return { encrypt, decrypt, encryptJson, decryptJson };
}

module.exports = { createSecretStore, deriveKey };
