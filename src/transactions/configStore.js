'use strict';

const fs = require('fs');
const path = require('path');

// Persists the pushed transaction config to a local JSON file so tests keep
// running after an agent restart WITHOUT server contact. Secrets are stored
// ENCRYPTED (via the injected secretStore); the plaintext only ever lives in
// memory. On load, secrets are decrypted back into memory. Best-effort: an I/O
// error never throws (it just logs) so a bad file can't stop the agent.
function createConfigStore({ filePath, secretStore, logger = null }) {
  function warn(msg) { if (logger && typeof logger.warn === 'function') logger.warn(msg); }

  // Serialises tests with secrets encrypted into config_secrets (plaintext
  // `secrets` removed).
  function save(tests) {
    const serial = (Array.isArray(tests) ? tests : []).map((t) => {
      const { secrets, ...rest } = t;
      return { ...rest, config_secrets: secretStore.encryptJson(secrets || {}) };
    });
    try {
      fs.mkdirSync(path.dirname(filePath), { recursive: true });
      fs.writeFileSync(filePath, JSON.stringify({ version: 1, tests: serial }), { mode: 0o600 });
    } catch (err) {
      warn(`transaction config save failed: ${err.message}`);
    }
  }

  // Loads persisted tests, decrypting config_secrets back into `secrets`.
  function load() {
    try {
      if (!fs.existsSync(filePath)) return [];
      const raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      const tests = Array.isArray(raw.tests) ? raw.tests : [];
      return tests.map((t) => {
        const { config_secrets, ...rest } = t;
        return { ...rest, secrets: secretStore.decryptJson(config_secrets) };
      });
    } catch (err) {
      warn(`transaction config load failed: ${err.message}`);
      return [];
    }
  }

  return { save, load };
}

module.exports = { createConfigStore };
