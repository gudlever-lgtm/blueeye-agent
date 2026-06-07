# Releasing the agent (signed, server-distributed)

The agent is **built on the server side and shipped to hosts as a signed
`tar.gz`** over the existing server connection — no Docker, no registry, no new
network access. The server verifies the Ed25519 signature on upload; the agent
verifies it again before installing.

## 0. The release signing key

The signing key is the trust anchor for secure agent management. Provision it ONE of
two ways:

**A) Recommended — generate it in the dashboard (server-managed).**
An admin opens **Settings → Agent key** and clicks *Generate*. The key pair is
created on the server; the private key is stored encrypted and **never leaves it**,
and the server **signs the agent source bundle itself** — no build host, no manual
upload. The public key is served at `GET /enroll/agent-release-key` and pinned by the
installers. The key is write-once and can be deleted (which disables onboarding +
upgrades until regenerated). With this path **you can skip sections 1–2**: a signed
release is published automatically at startup and whenever you generate the key.

**B) Advanced — external build host (off-server signing).**
Generate a **dedicated** Ed25519 key pair (separate from the licence key, same tool):

```bash
node blueeye-licens/scripts/generate-signing-key.js
```

- Keep the printed **private** key (`AGENT_RELEASE_SIGNING_KEY`, base64 PKCS8 PEM)
  on the build host / CI secret store. It NEVER ships.
- Provision the **public** key (SPKI PEM, or base64-of-PEM) to the server as
  `AGENT_RELEASE_PUBLIC_KEY` (used by `POST /agents/releases`); the agent fetches +
  pins it from `GET /enroll/agent-release-key`. Then follow sections 1–3.

Both sides fail **closed** without a key: the server refuses uploads (503) and the
agent refuses signed updates.

## 1. Build + sign (advanced — path B only)

```bash
AGENT_RELEASE_SIGNING_KEY=<base64-pkcs8-pem> ./scripts/build-release.sh 0.3.0
```

Produces `dist/blueeye-agent-0.3.0.tgz` (+ `.manifest.json` + `.sig`) and prints
the upload command. The manifest is the signed bytes:
`{ version, sha256, size, created_at }`.

## 2. Upload to the server (advanced — path B only; verified on upload)

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

## 4. Install on a fresh host

The customer one-liner (`curl -sSL <server>/enroll/<code>/install.sh | sh`) and the
manual installer below produce the **same versioned layout**, so install / upgrade /
uninstall behave identically. The release public key is fetched from the server
automatically — you normally don't pass it:

```bash
BLUEEYE_SERVER_URL=https://server.example \
BLUEEYE_ENROLLMENT_CODE=<one-time-code> \
sudo ./scripts/install-systemd.sh
```

Lays out `/opt/blueeye-agent/releases/<v>` + a `current` symlink and installs
`blueeye-agent.service` (running from `current`). The token lives at
`/var/lib/blueeye-agent/token`, the local trail at
`/var/log/blueeye-agent/actions.log` — both outside the swappable release dir, so
updates never touch them. (Override the trust anchor per-host with
`BLUEEYE_RELEASE_PUBLIC_KEY` if you don't serve it from the server.)

> Agents installed the OLD flat way must be re-installed **once** onto this layout
> before symlink-swap updates take over. Until then the agent still verifies
> signatures and updates in place.

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
