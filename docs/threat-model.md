# RoleGit Threat Model

## Status and Boundaries

This threat model covers the implemented centralized prototype and the planned Community, Team, and
Enterprise modes. It summarizes the accepted trust boundaries in
[ADR 0001](adr/0001-product-modes-and-trust-boundaries.md) and the public-contract rules in
[ADR 0002](adr/0002-branches-protocols-and-repository-ownership.md). If this summary conflicts with an
accepted ADR, the ADR controls. Future-mode sections describe design requirements, not implemented or
released guarantees.

The [current prototype security model](security.md) records implementation-specific controls and
limitations. Vulnerabilities should be handled under the repository [security policy](../SECURITY.md).

## Assets and Security Objectives

- **Customer plaintext:** protected file contents should be disclosed only to actors authorized by
  the applicable mode, subject to retained-copy and local-compromise limits below.
- **Key material:** plaintext DEKs, device and recovery private keys, policy-root and policy-signing
  private keys, KEKs, KMS keys, GitHub App private keys, and access/session tokens require
  confidentiality and appropriate lifetime controls.
- **Policy and recipient integrity:** repository, vault, path, recipient, sequence, expiration, and
  predecessor bindings must not be silently changed or rolled back beyond the documented freshness
  limits.
- **Content integrity and provenance:** authenticated encryption detects modification without a DEK,
  but current recipient designs do not authenticate who sealed a new valid object. Repository write
  controls, review, and Git provenance remain security assets.
- **Local state:** materialized plaintext, sessions, leases, checkout identity, configuration, and
  cleanup records must not cross repository or user boundaries.
- **Availability and recoverability:** authorized users need ciphertext, policy state, keys or an
  available unwrap authority, while corruption and destructive cleanup must fail safely.
- **Metadata and public contracts:** metadata should not be misrepresented as secret, and schemas,
  algorithms, APIs, test vectors, and trust-boundary claims must remain auditable and versioned.

## Attackers and Capabilities

The model considers:

- a Git reader, repository writer, malicious collaborator, or Git host able to retain history,
  rewrite tracked configuration, or present stale and split views;
- a removed or currently authorized user who retains keys, DEKs, plaintext, clones, backups, or
  screenshots;
- a network attacker, malicious endpoint, or compromised centralized prototype service;
- a compromised GitHub account, GitHub OAuth or API service, organization or team administrator,
  GitHub App, App private key, or installation token able to falsify identity or membership results;
- a malicious or compromised Team coordinator that can observe, withhold, replay, or equivocate over
  metadata but, by design, has no plaintext or decryption key material;
- a compromised customer KMS, provider-side agent, self-hosted broker, policy signer, administrator,
  or recovery authority;
- an untrusted dependency, build input, package, or CI/release actor; and
- malware or another process running as the user, including an actor able to race filesystem checks.

Attackers may combine capabilities. For example, a repository writer may collude with a replacement
prototype service or isolate a client behind a stale metadata view.

## Assumptions

- Node's native cryptography and selected future audited libraries correctly implement their stated
  primitives; RoleGit does not defend against broken primitives or a compromised runtime.
- Authorized devices, customer policy roots, recovery processes, and any selected customer key
  provider are provisioned through authenticated customer-controlled channels and secured by the
  customer.
- The operating system enforces the intended user and process boundary. POSIX mode bits and Windows
  ACLs do not protect against the same user, administrators, kernel compromise, or malware.
- Repository access control and review protect content provenance until a versioned sealer
  authentication protocol exists. Git storage alone is not trusted with plaintext or keys.
- Clients can detect signed-state rollback or equivocation they have already observed, but Community
  and Team do not have a global latest-state guarantee until a transparency and freshness protocol is
  specified and implemented.
- Backups, editors, shells, CI systems, crash dumps, swap, and user workflows that receive plaintext
  are inside the customer's operational boundary.

## GitHub Identity and Membership

The current prototype trusts GitHub's device OAuth flow and API to bind the user's OAuth token to the
correct immutable numeric user ID. The authorization service retains that OAuth token in memory for
the RoleGit session. Direct user rules authorize the stored numeric ID. Team rules revalidate the
token's current identity and trust GitHub's active team-membership result, using either that user token
or a repository-scoped installation token obtained with the configured GitHub App private key. The
server policy's repository name and configured user and team rules are also trusted authorization
inputs. Development authentication bypasses GitHub entirely and is intentionally trusted only for
local testing.

A stolen user OAuth token or compromised GitHub account can impersonate that user until the token or
RoleGit session is revoked or expires. A malicious organization or team administrator, or a
compromised GitHub membership service, can add an attacker to an authorized team or hide a legitimate
member. A compromised App private key or installation token can falsify or expose the membership
queries available to its granted repository and organization permissions; compromise of the
prototype service also exposes retained user OAuth tokens. These failures can cause unauthorized DEK
generation or unwrap, disclose GitHub identity and membership metadata, or deny access. RoleGit does
not independently attest GitHub identities or reconstruct organization membership.

Planned Community mode does not make GitHub identity or membership an independent decryption
authority: any GitHub-derived directory or membership result is untrusted until incorporated into
recipient state signed by the customer policy authority. Planned Team may fetch and coordinate those
results, so GitHub and membership administrators can affect proposals, metadata confidentiality,
availability, and freshness, but accepted recipient authority still comes from the customer signature
chain. Enterprise deployments inherit that rule when using GitHub-derived inputs; a customer may
instead select and assume responsibility for another identity provider and membership authority.

## Metadata Leakage

Encryption does not hide the repository or account involved, protected filenames listed in
`.enclist`, ciphertext and object sizes, change frequency, timing, access failures, or Git history and
topology. Public recipient keys, key identifiers, wrapped keys, policy digests, signed mutations,
device directories, and recipient-set changes may reveal organization structure or membership.

The current prototype additionally sends the vault identifier, protected path, wrapped key, user
identity, and request timing to the selected authorization service. Team may observe account and
repository identifiers, device public keys, policy digests, signed mutations, membership results,
timing, transparency data, and privacy-reviewed billing or audit events. Enterprise metadata exposure
depends on the selected Team coordination, provider, and self-hosted profile. Encryption and the term
"zero-knowledge coordination" do not mean metadata anonymity or cryptographic zero-knowledge proofs.
Retention and privacy rules for future services require separate specifications.

## Local Compromise

An authorized client necessarily handles plaintext and usually a plaintext DEK. A malicious same-user
process, debugger, administrator, compromised runtime, or malware can read materialized files and
process memory, intercept keystrokes, race filesystem checks, copy session tokens, or modify data
before sealing. RoleGit's restrictive files, key-buffer clearing, symlink checks, leases, expiry
watcher, and `lock` command reduce accidental exposure; they do not create a secure enclave or
guaranteed erasure boundary. Node does not provide an atomic portable repository-contained path open,
and Windows ACL and directory-flush behavior requires additional customer controls described in the
[prototype model](security.md).

Do not place real secrets in tests, fixtures, examples, logs, issues, or pull requests. Synthetic
canaries test that user-facing output does not reveal plaintext, a KEK, or a session token, but they do
not prove that every crash, dependency, operating-system, or service log is free of secrets.

## Historical Revisions and User Copies

Recipient snapshots govern new seals; they do not revoke ciphertext already produced. A removed
recipient who retains an authorized private key can decrypt older objects wrapped to that key. A
sealing device can decrypt a version if it retained the DEK it generated or obtained. Session, token,
or policy expiry blocks later service requests but does not expire plaintext or a DEK already released.

Re-sealing the current file with a new DEK does not remove older ciphertext and wrapped keys from Git
history, clones, forks, mirrors, caches, or backups. History rewriting and key rotation can reduce
repository-side exposure only within infrastructure the customer controls. No mode can recall data,
keys, screenshots, exports, or other copies retained by a user or system that previously had access.

## Current Centralized Prototype

The implemented v1 service is experimental and self-hosted only. It holds a KEK, generates or unwraps
plaintext DEKs after its policy check, and returns those DEKs to clients. The client and service are
therefore decrypt-capable. The Git host is not decrypt-capable as a passive ciphertext store, but it
remains in the configuration and provenance boundary.

`.enclist.authServer` is tracked in Git and is not pinned to a customer service identity. On a fresh
checkout or later login without an active local association, a writer or split-view Git host can
redirect the client to a colluding service. The replacement can control and later decrypt or forge
future versions sealed with its DEK if it obtains their ciphertext. It cannot unwrap an older object
created through the expected service merely from that object's wrapped key, but it can deny service or
cause authenticated-decryption failure. Users must verify the expected endpoint through an
authenticated channel outside Git before every prototype login. A durable fix is tracked in
[issue #55](https://github.com/cosentinode/rolegit/issues/55).

Other material limits include in-memory service state, a process environment KEK, loopback-only
binding, development authentication, no production TLS/deployment controls, permissive unknown fields
in recognized v1 JSON objects, and best-effort local cleanup. The prototype must not be deployed with
real secrets.

## Planned Community Mode

Community is local first. A customer-controlled repository policy root authorizes signing keys and
recipient snapshots. Encryption and decryption occur on authorized devices; device and recovery
private keys remain in local or customer custody. RoleGit Cloud is absent from normal content and key
paths, and Git stores ciphertext and public recipient information.

Clients must validate the root chain, repository and vault binding, expiration, sequence, predecessor,
and recipient-directory digest, and persist their highest accepted checkpoint. Those checks detect
rollback or equivocation already observed by a client. A stale mirror, delayed synchronization, or
split Git view can nevertheless withhold a newer still-valid state, causing a sealer to include a
recently revoked recipient in a future version. Git/customer synchronization is therefore inside the
authorization-freshness boundary even though it has no decryption keys.

Recipient policy does not yet authorize a sealing identity. A repository writer can generate a new
DEK and valid encrypted replacement for legitimate recipients without recovering displaced plaintext.
Until sealer authentication is specified, review and Git provenance protect content authenticity.
Historical recipient and retained-sealer limits continue to apply.

## Planned Team Mode

Team adds optional RoleGit-operated metadata coordination to Community. It may distribute public
device directories, signed mutations, policy digests, membership results, rekey proposals,
transparency data, and privacy-reviewed billing or audit metadata. Its APIs must reject plaintext,
plaintext DEKs, and private device, recovery, or policy keys. Membership and directory entries are
untrusted inputs until covered by the customer-authorized signature chain.

The Team service can deny availability, observe the documented metadata, withhold updates, or replay a
still-valid state to an isolated client. Until the transparency and consistency protocol is specified,
it remains in the authorization-freshness boundary and can delay revocation, but it cannot decrypt by
itself. Team coordination does not authenticate sealers or remove Community's Git provenance,
historical revision, or local-device risks. A claim that Team learns no metadata, can recover
customer keys, or can guarantee globally latest policy would violate the accepted architecture.

## Planned Enterprise Modes

Enterprise offers customer-controlled alternatives; it is not one undifferentiated trust boundary.

**Customer key provider.** An authorized client or client-side agent uses a customer KMS, HSM, Vault,
or provider-side agent to generate, wrap, or unwrap DEKs. The provider boundary controls unwrap and is
treated as decrypt-capable. Remote wrapping sends a plaintext DEK into that boundary; authenticated
public-key local wrapping does not, but possession of the public wrapping key does not authorize or
authenticate a sealer. Provider policy can deny a future unwrap but cannot recall a DEK a client or
agent generated, received, or retained. Optional RoleGit Team coordination remains metadata only.

**Content-blind self-hosted coordinator.** The customer-operated coordinator has the same metadata and
freshness boundary as Team. Customer policy roots and recipient private keys remain on authorized
devices. The coordinator cannot decrypt by itself, while repository provenance, stale-state,
historical recipient, and retained-DEK risks remain.

**Customer key-broker self-hosting.** The customer broker and its KMS/KEK generate and unwrap plaintext
DEKs and are decrypt-capable. Clients that receive or retain a DEK are also decrypt-capable. The
customer owns service authentication, authorization, hardening, audit, availability, backup,
rotation, and incident response; RoleGit Cloud is absent from the deployment and key path.

Enterprise deployment does not eliminate local compromise, metadata leakage, malicious repository
writers, retained history, or user copies. Provider and self-hosted interfaces must remain consistent
with the public versioned contracts rather than privately changing key custody.

## Non-Goals

- **DRM:** RoleGit does not control how an authorized user views, records, exports, or redistributes
  plaintext.
- **Retroactive forgetting:** revocation cannot erase prior Git revisions or recall plaintext, DEKs,
  keys, backups, screenshots, or copies already obtained.
- **Malware resistance:** RoleGit does not protect plaintext or keys from malware, administrators,
  kernel compromise, debuggers, or malicious processes running as the user.
- **Metadata anonymity:** encrypted content does not hide all repository, identity, path, size, timing,
  membership, billing, or audit metadata.
- **Unconditional availability:** loss of private keys, policy authority, a required provider, or all
  recovery paths can make data permanently unavailable.
- **Cryptographic author identity today:** AEAD integrity does not prove who sealed a valid object;
  sealer authentication is a future protocol concern.
