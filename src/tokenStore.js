'use strict';

const fs = require('fs');
const path = require('path');

// Reads the stored credentials, or null if none / unreadable.
function readToken(tokenPath) {
  try {
    if (!fs.existsSync(tokenPath)) return null;
    const data = JSON.parse(fs.readFileSync(tokenPath, 'utf8'));
    if (data && typeof data.token === 'string' && data.token.length > 0) {
      return { agentId: data.agentId ?? null, token: data.token };
    }
    return null;
  } catch {
    return null;
  }
}

// Persists the token with restrictive (owner-only) permissions. chmod is applied
// explicitly because writeFile's mode only takes effect when creating the file.
function saveToken(tokenPath, { agentId, token }) {
  fs.mkdirSync(path.dirname(tokenPath), { recursive: true });
  const body = `${JSON.stringify({ agentId, token }, null, 2)}\n`;
  fs.writeFileSync(tokenPath, body, { mode: 0o600 });
  fs.chmodSync(tokenPath, 0o600);
}

module.exports = { readToken, saveToken };
