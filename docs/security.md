# Security Model

RoleGit separates repository access from secret-decryption access. Git stores only encrypted
vault objects. The authorization service holds the key-encryption key and releases short-lived
data keys only after checking the current user's server-side access policy.

## Protected

- Secret contents at rest in Git and on GitHub.
- File data keys, which are freshly generated for every sealed version.
- Swapping an encrypted object to another vault or protected path.
- Unauthorized local policy changes, because access rules live with the authorization service.
- Accidental staging of configured plaintext paths during normal RoleGit use.

## Not Protected

- Secret filenames listed in `.enclist`, repository timing, or encrypted object sizes.
- Data copied by someone while they were authorized.
- Plaintext retained by editors, processes, backups, swap, crash dumps, or malware.
- Rollback to an older valid encrypted Git revision.
- A compromised authorization service or key-encryption key.
- Bypassing expiration after an authorized user has deliberately copied a plaintext secret.
- A malicious same-user process racing filesystem checks while RoleGit reads or materializes files.

The detached expiry watcher is defense in depth, not a guaranteed erasure mechanism. It removes
materialized files when the local session expires while the machine is running. The next unlock
also removes stale materialized files before refusing an expired session.

## Cryptography

Version 1 uses AES-256-GCM with a fresh 96-bit nonce and fresh 256-bit data key for every save.
The authorization service wraps each data key under a 256-bit key-encryption key using a separate
nonce and authenticated context. Complete files are buffered and limited to 10 MiB so no
plaintext is emitted before authentication succeeds.

RoleGit uses Node's native `crypto` implementation. It does not implement cryptographic
primitives itself.

For team authorization, the service uses the GitHub App private key to obtain an installation
token scoped to the repository named in its trusted server policy. The CLI never receives the app
private key or installation token.

Even when an owner installs RoleGit on all repositories, each short-lived installation token is
restricted to the one repository involved in the authorization request.

## Development Authentication

`ROLEGIT_DEV_AUTH=1` enables an intentionally insecure login path for users explicitly listed in
the server policy. It exists only for local end-to-end development and must never be enabled on a
network-accessible or production authorization service.
