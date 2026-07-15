# RoleGit

RoleGit adds cryptographic file permissions to Git repositories. GitHub collaborators can clone
the same repository while only authorized GitHub users and teams can decrypt protected files.

This is an early TypeScript 7 prototype. It includes encrypted vault objects, GitHub device-flow
interfaces, server-side authorization, and fixed-duration sessions.

> [!WARNING]
> The centralized authorization service is an experimental prototype for validating the current
> security model. It is not production-ready and will be superseded by local-first Community mode.
> See [`docs/security.md`](docs/security.md) and do not use this baseline with real secrets.

## Requirements

- Node.js 22 or newer
- Git
- The official [RoleGit GitHub App](https://github.com/apps/rolegit-auth) for real login

```bash
npm install
npm run build
npm link
```

## Repository Setup

```bash
rolegit init --server http://127.0.0.1:8787
rolegit protect .env
```

`.enclist` is tracked and maps protected plaintext paths to opaque encrypted objects:

```json
{
  "version": 1,
  "vaultId": "generated-uuid",
  "authServer": "http://127.0.0.1:8787",
  "files": {
    ".env": {
      "object": ".rolegit/vault/opaque-digest.json"
    }
  }
}
```

`rolegit protect` refuses already tracked files and adds the plaintext path to `.gitignore`.
Copy the generated vault ID and protected paths into an authorization-service policy based on
[`server-policy.example.json`](server-policy.example.json). That server-side policy is the access
authority; changing `.enclist` cannot grant decryption permission.

## Local End-to-End Development

Generate a development key-encryption key:

```bash
export ROLEGIT_KEK="$(node -e 'process.stdout.write(require("node:crypto").randomBytes(32).toString("base64url"))')"
export ROLEGIT_GITHUB_APP_KEY="$HOME/.config/rolegit/rolegit-auth.private-key.pem"
export ROLEGIT_DEV_AUTH=1
rolegit serve --policy ./server-policy.json
```

In another terminal, use a numeric user ID explicitly configured in the server policy:

```bash
rolegit login --development-user 12345678
rolegit seal
git add .enclist .gitignore .rolegit/vault
git commit -m "Add encrypted environment"
```

After cloning on another machine:

```bash
rolegit login --development-user 12345678
rolegit unlock
# .env now exists locally (mode 0600 on POSIX systems)
rolegit status
rolegit lock
```

Development authentication is deliberately unsafe and only binds to the loopback service.

## Development Policy

`develop` is the integration branch and the base for all pull requests. `main` is release-oriented;
changes reach it through the release process rather than direct development work. All changes must
land through a pull request.

## GitHub Login

Install the [RoleGit GitHub App](https://github.com/apps/rolegit-auth/installations/new), leave
`ROLEGIT_DEV_AUTH` unset, and run:

```bash
rolegit login
```

RoleGit prints GitHub's verification URL and device code. The service resolves the authenticated
user's immutable numeric ID and checks configured team membership before every key operation.
Sessions default to 60 minutes and cannot be silently refreshed.

The official app's public identity is built into RoleGit. Self-hosted services can override its
public Device Flow client ID with `githubClientId` in their server policy. Client secrets and app
private keys are never distributed with the CLI.

The authorization service can use `ROLEGIT_GITHUB_APP_KEY` to obtain repository-scoped installation
tokens. This lets it verify organization-team membership independently instead of trusting a
client-supplied result. The private key belongs only on the authorization service.

## Daily Workflow

```bash
rolegit login
rolegit unlock

# Edit and run the project normally.
$EDITOR .env

rolegit seal .env
git add .rolegit/vault
git commit -m "Update encrypted environment"
git push

rolegit lock
```

An expiry watcher removes unchanged materialized files after the session that unlocked them expires.
`rolegit lock` performs the same cleanup immediately, attempts to invalidate the server session, and
always clears the local session token when its repository/server association is available, even when
no files are unlocked. It reports remote logout failures; the remote token then remains valid only
until its fixed expiry. RoleGit preserves any materialized path that was modified or replaced after
the latest successful `unlock` or `seal`, reports the path, and relinquishes its cleanup lease rather
than risking data loss. A new login cannot replace an active local session; run `rolegit lock` first.

## Current Scope

- Exact protected paths; Git-ignore-style patterns are planned.
- Server state and sessions are in memory and disappear on restart.
- The key-encryption key comes from `ROLEGIT_KEK`; production KMS integration is not implemented.
- On POSIX systems, session tokens and materialized files are created with mode `0600`. Node's
  numeric modes do not configure Windows ACLs; use a private Windows profile and appropriate ACLs.
  OS keychain storage is planned.
- The authorization service binds to loopback; production TLS and deployment are not implemented.
- There is no encrypted merge-conflict workflow yet.
