# ADR 0001: Product Modes and Trust Boundaries

- Status: Accepted
- Date: 2026-07-17

## Context

RoleGit is moving from a centralized proof of concept to a local-first product. Across Community,
Team, and Enterprise offerings, a RoleGit-operated service must not receive plaintext or the private
key material needed to decrypt repository content. Enterprise customers may instead choose to place
key authority in infrastructure they control.

This ADR describes the target architecture. The implemented v1 authorization service is classified
separately under [Centralized Prototype](#centralized-prototype).

## Terminology

**Zero-knowledge coordination** means a coordination service does not receive plaintext, plaintext
data-encryption keys (DEKs), role-epoch private material, recovery private keys, or device private
keys. It may still observe documented metadata such as account and repository identifiers, device
public keys, policy digests, signed mutations, timing, and billing or audit events.

This is a product trust-boundary term. It does not claim that RoleGit uses cryptographic
zero-knowledge proofs, and it does not mean the service learns no metadata.

## Decision

Community is the default architecture and performs encryption and decryption on authorized user
devices. Team adds optional metadata-only coordination without entering the key-custody boundary.
Enterprise adds customer-controlled KMS and self-hosted choices. A RoleGit-operated Team service is
never a policy or decryption-key authority and does not receive the material needed to decrypt files;
it remains part of the authorization-freshness boundary until a global transparency and consistency
protocol is specified.

| Mode | Key authority | Confidentiality trust boundary | Actors able to decrypt protected files |
| --- | --- | --- | --- |
| Community local-first | A customer-controlled repository policy root authorizes policy-signing keys and recipient snapshots; recipient and recovery private keys unwrap DEKs | Customer policy-signing authority and authorized devices; Git remains outside key custody | Authorized recipient or recovery devices only |
| Team zero-knowledge coordination | The same customer-controlled policy root and recipient private keys as Community; Team membership results are inputs, not authority | Customer policy-signing authority and authorized devices; Team remains outside key custody but is trusted for availability and freshness of signed metadata until transparency is specified | Authorized recipient or recovery devices only; RoleGit Cloud has no decryption key material |
| Enterprise customer KMS | The customer's KMS policy and keys | Authorized clients plus the customer KMS security boundary | Authorized clients; the customer KMS is treated as decrypt-capable because it can unwrap DEKs |
| Enterprise content-blind self-hosted | The customer-controlled policy root and recipient private keys | Customer policy-signing authority and authorized devices; the customer-hosted coordinator has the same freshness limitation as Team | Authorized recipient or recovery devices only |
| Enterprise key-broker self-hosted | The customer's self-hosted broker and KMS/KEK | Authorized clients plus the entire customer-operated broker and KMS boundary | Authorized clients and the customer-controlled key boundary; no RoleGit-operated service |

Specific object schemas, algorithms, signature encodings, and KMS APIs belong in versioned protocol
specifications. They must preserve these boundaries and the following authority rules.

### Policy Authority and Client Verification

The authority is a customer-controlled repository policy-root signing key, not the policy document or
the coordination service. Its public key and an initial signed checkpoint are provisioned to each new
device through an authenticated out-of-band enrollment, an existing authorized device, or a
customer-controlled recovery process. Neither Git nor a coordinator may bootstrap or replace that
root by itself.

The root may authorize bounded policy-signing keys. Customer-signed policy state binds the repository
and vault identifiers, monotonic sequence, previous-state digest, expiration, authorized signing
keys, and recipient-directory digest. Public-key directories and GitHub membership results supplied
by a coordinator are untrusted inputs until covered by that customer-authorized signature chain.

Before sealing, clients must validate the root chain, repository and vault binding, expiration,
sequence, predecessor, and recipient-directory digest. They persist the highest accepted checkpoint
and fail closed on a lower sequence, a different digest at an already observed sequence, or an invalid
predecessor. The validated recipient snapshot exclusively determines which public keys receive the
new DEK.

These checks prevent the coordinator from forging recipients and detect rollback or equivocation a
client has observed, but they do not prove that every client has the globally latest signed state. A
coordinator can withhold an update or replay a still-valid state to an isolated or newly enrolled
device, potentially delaying revocation for future seals. Until a versioned transparency and
freshness protocol closes that gap, Team is outside the decryption-key boundary but remains trusted
for this authorization-freshness property. The service still cannot decrypt by itself.

### Community Local-First

Community requires no RoleGit service for normal protect, seal, unlock, or lock operations. Git stores
ciphertext and public recipient information. Private device and recovery keys stay in local or
customer-controlled custody.

```mermaid
flowchart LR
    R[Customer policy root] -->|signed policy and recipient snapshot| A[Authorized sealing device: decrypt-capable]
    O[Existing device or customer recovery] -->|authenticated root and checkpoint bootstrap| A
    A -->|verify state, encrypt locally, and wrap DEK to recipients| G[Git host: cannot decrypt]
    G -->|clone or pull encrypted object| B[Authorized recipient device: decrypt-capable]
    B -->|private key unwrap and local decrypt| P[Plaintext on authorized device]
    C[RoleGit Cloud: cannot decrypt; absent from content and key paths]
```

The authorized recipient device can decrypt. The Git host and RoleGit Cloud cannot.

### Team Zero-Knowledge Coordination

Team may distribute public device directories, signed directory mutations, policy digests, rekey
proposals, transparency data, membership results, and privacy-reviewed audit or billing metadata. Its
APIs must reject plaintext and private or plaintext key material. Membership results and directory
entries cannot authorize a recipient without a customer-authorized signature. Clients continue to
obtain encrypted objects from Git and decrypt locally.

```mermaid
flowchart LR
    R[Customer policy root] -->|signed policy and recipient snapshot| T[RoleGit Team: metadata only; cannot decrypt]
    O[Existing device or customer recovery] -->|authenticated root and checkpoint bootstrap| S[Authorized sealing device]
    T -->|signed state and untrusted membership inputs| S
    S -->|verify state, encrypt, and wrap new DEK to recipients| G[Git host: cannot decrypt]
    G -->|encrypted object and wrapped DEK| D[Authorized recipient device: decrypt-capable]
    D -->|private key unwrap and local decrypt| P[Plaintext on authorized device]
```

Only a device holding an authorized recipient or recovery private key can directly decrypt. RoleGit
Team, other RoleGit Cloud components, and the Git host receive no decryption key material. Team's
remaining metadata-freshness trust and delayed-revocation risk are defined above rather than hidden by
an unconditional confidentiality claim.

### Enterprise Customer KMS

An Enterprise client or customer agent may invoke the customer's KMS directly. RoleGit Cloud may
provide the same optional metadata coordination as Team, but it is not in the key path. KMS policy,
availability, audit, rotation, and revocation are customer responsibilities.

```mermaid
flowchart LR
    G[Git host: cannot decrypt] --> D[Authorized client or customer agent: decrypt-capable]
    D <-->|wrapped DEK and authenticated context| K[Customer KMS: key authority and decrypt-capable]
    D -->|local decrypt after authorized unwrap| P[Plaintext on customer device]
    D <-->|optional metadata only| T[RoleGit Team: cannot decrypt]
```

The authorized client can decrypt after KMS authorization. The customer KMS is treated as capable of
decryption because it controls DEK unwrapping. RoleGit Cloud and the Git host cannot decrypt.

### Enterprise Self-Hosted

Customers may self-host in either of two explicit, mutually exclusive deployment profiles. Neither is
combined with the separate customer-KMS profile above.

#### Content-Blind Coordinator

The service has the Team metadata boundary and the same customer-controlled policy-root,
verification, and freshness rules. Device or recovery private keys remain in client custody, and only
authorized devices can decrypt.

```mermaid
flowchart LR
    R[Customer policy root] -->|signed policy and recipient snapshot| C[Customer content-blind coordinator: cannot decrypt]
    C -->|signed metadata only| S[Authorized customer sealing device]
    S -->|verify state, encrypt, and wrap DEK to recipients| G[Git host: cannot decrypt]
    G -->|encrypted object and wrapped DEK| D[Authorized customer recipient device: decrypt-capable]
    D -->|private key unwrap and local decrypt| P[Plaintext on customer device]
    L[RoleGit Cloud: cannot decrypt; absent from deployment and key path]
```

#### Customer Key Broker

The customer-operated service and its KMS/KEK authorize and unwrap DEKs. The broker boundary is
therefore decrypt-capable and must be secured as customer key infrastructure.

```mermaid
flowchart LR
    G[Git host: cannot decrypt] -->|encrypted object and wrapped DEK| D[Authorized customer client: decrypt-capable]
    D <-->|wrapped DEK and authorized unwrap| B[Customer key broker and KMS: decrypt-capable]
    D -->|local decrypt| P[Plaintext on customer device]
    R[RoleGit Cloud: absent from deployment and key path]
```

In the content-blind profile, only authorized devices can decrypt, subject to the documented signed
metadata freshness boundary. In the key-broker profile, authorized devices and the customer-controlled
broker/KMS boundary are decrypt-capable. RoleGit Cloud receives no decryption key material in either
profile.

## Centralized Prototype

The current v1 authorization service is an **experimental, self-hosted-only prototype**. It holds a
KEK, unwraps DEKs after its policy check, and returns DEKs to clients. The service is therefore inside
the confidentiality boundary and must be considered capable of decrypting if it obtains ciphertext.
It binds to loopback by default and lacks production deployment controls.

This prototype is not the Community default, not the Team architecture, and not a public RoleGit SaaS
offering. It exists to validate workflow and security assumptions until the local-first format and
recipient model replace or isolate it. It must not be deployed with real secrets.

```mermaid
flowchart LR
    G[Git host: cannot decrypt] --> D[Prototype client: decrypt-capable]
    D <-->|wrapped DEK and plaintext DEK| S[Customer-run experimental service: KEK holder and decrypt-capable]
    D -->|local decrypt| P[Plaintext on client]
    R[RoleGit Cloud: not a public SaaS for this prototype]
```

Both the authorized client and the self-hosted prototype service boundary are decrypt-capable. No
RoleGit-operated Cloud service is part of this prototype deployment.

## Consequences

- Community confidentiality does not depend on RoleGit service availability.
- Team can improve coordination but cannot perform server-side plaintext processing or key recovery;
  it remains trusted for signed-metadata freshness until the transparency protocol is specified.
- Enterprise customers that select KMS or key-broker modes intentionally expand the decrypt-capable
  boundary to customer-controlled infrastructure.
- Metadata privacy, retention, global consistency, transparency, and availability require separate
  specifications even when clients enforce the local rollback and fork checks required here.
- Product and protocol documentation must identify the key authority and trust boundary whenever a
  new mode or key path is proposed.
