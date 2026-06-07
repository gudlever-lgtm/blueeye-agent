# Releasing the agent (signed, server-distributed)

The agent is **built on the server side and shipped to hosts as a signed
`tar.gz`** over the existing server connection — no Docker, no registry, no new
network access. The server verifies the Ed25519 signature on upload; the agent
verifies it again before installing. This document is the reproducible flow.

## 0. One-time: the release signing key

Generate a **dedicated** Ed25519 key pair (separate from the licence key, same
tool):

```bash
node blueeye-licens/scripts/generate-signing-key.js
```

- Keep the printed **private** key (`AGENT_RELEASE_SIGNING_KEY`, base64 PKCS8 PEM)
  on the build host / CI secret store. It NEVER ships.
- Provision the **public** key (SPKI PEM, or base64-of-PEM) to:
  - the server: `AGENT_RELEASE_PUBLIC_KEY` (used by `POST /agents/releases`), and
  - the agent: `BLUEEYE_RELEASE_PUBLIC_KEY` (a systemd drop-in; the installer sets
    it). It can also be embedded in `src/release/publicKey.js`.

Both sides fail **closed** without it: the server refuses uploads (503), the
agent refuses signed updates.

## 1. Build + sign

```bash
AGENT_RELEASE_SIGNING_KEY=<base64-pkcs8-pem> ./scripts/build-release.sh 0.3.0
```

Produces `dist/blueeye-agent-0.3.0.tgz` (+ `.manifest.json` + `.sig`) and prints
the upload command. The manifest is the signed bytes:
`{ version, sha256, size, created_at }`.

## 2. Upload to the server (verified on upload)

The script prints this; `$ADMIN_JWT` is an admin session token:

```bash
curl -fSS -X POST "$SERVER/agents/releases" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/octet-stream" \
  -H "X-Release-Version: 0.3.0" \
  -H "X-Release-Signature: <base64-sig>" \
  -H "X-Release-Manifest: <base64-json-manifest>" \
  --data-binary @dist/blueeye-agent-0.3.0.tgz
```

The server verifies the Ed25519 signature **and** that the tarball's sha256
matches the signed manifest before storing it. It then serves it at
`GET /enroll/agent-release(.tgz)` and reports it as the current agent version.

## 3. Push to agents

Dashboard → **Agents → Update** (admin), or `POST /agents/:id/update`. The server
sends `{ version, sha256, signature, auditId }`; the agent downloads
`/enroll/agent-release.tgz`, **verifies the signature + sha256 + version before
extracting**, swaps atomically, restarts, and reports completion (the audit row
flips to `completed`). Every action is in `GET /agents/:id/audit` and
`GET /audit?user=`.

## 4. Install on a fresh host (systemd, not Docker)

```bash
BLUEEYE_SERVER_URL=https://server.example \
BLUEEYE_ENROLLMENT_CODE=<one-time-code> \
BLUEEYE_RELEASE_PUBLIC_KEY=<base64-of-pem> \
sudo ./scripts/install-systemd.sh
```

Lays out `/opt/blueeye-agent/releases/<v>` + a `current` symlink and installs
`blueeye-agent.service` (running from `current`). The token lives at
`/var/lib/blueeye-agent/token`, the local trail at
`/var/log/blueeye-agent/actions.log` — both outside the swappable release dir.

> Existing agents must be re-installed **once** onto this layout before
> symlink-swap updates take over. Until then the agent still verifies signatures
> and updates in place.

## 5. Rollback

Each swap records the previous release. If a new release fails to come up:

```js
createSelfUpdater().rollback()   // repoints `current` to the previous release
```

(or repoint the `current` symlink to the prior `releases/<v>` and restart).

## Delete

Dashboard → **Agents → Delete** (admin) sends a `delete` command: the agent wipes
its token (overwrite + unlink) and runs `uninstall.sh` to remove its service and
files, reporting back so the server drops the agent record (tokens cascade).
Docker-managed agents decline (the host removes the container).
