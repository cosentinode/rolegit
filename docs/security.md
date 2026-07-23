# Current Prototype Security Model

This document covers the current v1 experimental, self-hosted-only prototype. It is not the target
Community or Team architecture and is not offered as a public RoleGit SaaS service. The planned mode
boundaries are defined in
[ADR 0001](adr/0001-product-modes-and-trust-boundaries.md).

In the target Community and Team modes, a customer-controlled policy root authorizes recipient
snapshots. Community's Git/customer synchronization path and Team's coordinator remain trusted for
signed-metadata freshness until the transparency and consistency protocol defined by ADR 0001 is
implemented; a stale or split view can delay revocation for future seals. Neither distribution path
receives plaintext or decryption key material. This is separate from the decrypt-capable prototype
boundary documented here. A removed recipient can still decrypt an older Git object whose DEK was
wrapped to that recipient; re-encrypting current content does not revoke copies retained in history.
The recipient policy authenticates recipient state, not sealing identities. No sealer signature and
verification contract is specified yet, so those target modes trust repository write controls and Git
provenance for content authenticity: a repository writer or split view can forge attacker-chosen
replacement content that valid recipients can decrypt without recovering the displaced plaintext.

The prototype separates repository access from secret-decryption access. Git stores only encrypted
vault objects. For each sealed version, the customer-run authorization service generates a fresh data
key (DEK), returns the plaintext DEK after checking the current user's server-side access policy, and
the client persists the wrapped DEK with the ciphertext. A later authorized unwrap returns that same
DEK. Authorization sessions have a fixed duration, but persisted wrapped DEKs and DEKs already
released to clients do not acquire that session expiry. Because the service holds the key-encryption
key and can unwrap DEKs, it is inside the confidentiality trust boundary and must be treated as
decrypt-capable. The client and service clear their immediate plaintext key buffers after use, but
that does not impose a cryptographic key lifetime or erase other retained copies.

This boundary assumes the client reached the intended customer-run service, but the prototype does
not authenticate that deployment independently of repository content. `.enclist.authServer` is
Git-tracked, and any repository writer or Git host presenting a split view can replace it. Parsing
requires HTTPS except on loopback, but TLS validation authenticates the configured network endpoint;
it does not pin that endpoint to the intended customer service identity. GitHub Device Flow likewise
authenticates a user to the selected service, not the selected service to the client.

On a fresh checkout or a subsequent login after the old session is inactive, the client trusts the
tracked endpoint for login responses, DEK generation, and unwrap. A replacement service can issue a
DEK and wrapped key it controls, so it can later decrypt or forge versions sealed with that key if it
can read the committed ciphertext. It cannot derive the DEK for an older object sealed through the
expected service merely from that object's wrapped key; redirecting an unwrap instead causes denial
or authenticated-decryption failure. Machine-local server/session and lease associations block a
transparent replacement while they are active, and `lock` retains previously used server associations,
but these are continuity and cleanup controls rather than initial service-identity pinning.

Administrators must distribute the expected canonical endpoint through a trusted channel outside Git,
and users must verify the exact `.enclist.authServer` value before every prototype login. An unexpected
change must be treated as a security event. The legitimate service policy controls only requests that
reach it and is not the sole authority for future seals while tracked configuration can redirect the
key service. Authenticated endpoint pinning or removal of this path is tracked in
[issue #55](https://github.com/cosentinode/rolegit/issues/55).

## Protected

- Secret contents in objects sealed through the expected service, against Git storage alone.
- File data keys generated and wrapped by the expected service for every sealed version.
- Swapping an encrypted object to another vault or protected path.
- Unauthorized vault or protected-path changes when the request reaches the expected service policy.
- Accidental staging of configured plaintext paths during normal RoleGit use.

## Not Protected

- Secret filenames listed in `.enclist`, repository timing, or encrypted object sizes.
- Data copied by someone while they were authorized.
- Plaintext DEKs obtained during an authorized session; session expiry only blocks a later unwrap.
- Plaintext retained by editors, processes, backups, swap, crash dumps, or malware.
- Rollback to an older valid encrypted Git revision.
- A compromised authorization service or key-encryption key.
- Customer service identity bootstrap: a repository writer or Git split view can redirect
  `.enclist.authServer` when no active local association blocks a new login.
- Confidentiality or authenticity of future versions sealed with a replacement service's DEK, or
  availability when unwrap requests for existing objects are redirected.
- Bypassing expiration after an authorized user has deliberately copied a plaintext secret.
- A malicious same-user process racing filesystem checks while RoleGit reads, writes, or removes
  files. RoleGit rejects symlinked path components immediately before sensitive operations, but
  Node does not provide an atomic repository-contained path open, so check/use races remain.

The detached expiry watcher is defense in depth, not a guaranteed erasure mechanism. It removes
unchanged materialized files when the local session expires while the machine is running. The next
unlock reconciles an expired lease before refusing the expired session: unchanged files are removed,
while modified or replaced paths are preserved and reported. Repository metadata and leases bind the
checkout UUID to its device/inode identity, so a copied UUID cannot consume a moved checkout's lease;
ambiguous move discovery fails closed. Every lease has a unique generation, and serialized cleanup
error updates can clear or replace only their own generation, so overlapping stale watchers cannot
erase a newer failure. Cleanup writes a terminal tombstone for the completed generation; a watcher
can record an error only while that exact generation is still active, so a process starting after
successful lock is a no-op. Repeated unlock attempts retain the current watched generation, including
when partial materialization rolls back and the command reports failure. Checkout identity is also
recovered from machine-local device/inode registry metadata when the private Git marker is missing or
the active Git directory changes; multiple registry identities for one instance fail closed.

Before plaintext creation on POSIX, RoleGit fsyncs the reserved lease file, atomically renames it, and
fsyncs the state directory. Plaintext creation and removal likewise fsync their containing directory,
so cleanup ownership is committed first across abrupt process or power loss. Node does not expose a
portable Windows directory-flush primitive; Windows keeps file-handle fsync plus strict state-before-
plaintext ordering, but its power-loss durability for directory entries depends on the filesystem.
Automatic cleanup also rewrites the durable lease after every successful path removal and before
attempting the next path. Partial failures therefore retain only paths that were not removed, and a
later retry cannot use retired digest ownership to delete a newly recreated file.

On POSIX systems, RoleGit creates local sessions, leases, and materialized files with owner-only
mode bits. Node's numeric mode options do not enforce an equivalent private ACL on Windows; Windows
users must protect their profile and RoleGit home with appropriate account ACLs.

## Cryptography

Version 1 uses AES-256-GCM with a fresh 96-bit nonce and fresh 256-bit data key for every save.
The authorization service wraps each data key under a 256-bit key-encryption key using a separate
nonce and authenticated context. Complete files are buffered and limited to 10 MiB so no
plaintext is emitted before authentication succeeds.

Current v1 encrypted-object, `.enclist`, and server-policy readers reject unsupported versions and
validate recognized fields, but ignore unknown JSON object fields. This is a prototype exception, not
a safe-extensibility guarantee: producers must not encode security semantics in unknown fields, and
consumers must not rely on unknown fields surviving a read/write cycle. Future stable protocol rules
are defined in [ADR 0002](adr/0002-branches-protocols-and-repository-ownership.md).

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
