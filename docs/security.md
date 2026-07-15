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
