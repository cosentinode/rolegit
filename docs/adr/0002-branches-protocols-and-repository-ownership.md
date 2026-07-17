# ADR 0002: Branches, Protocols, and Repository Ownership

- Status: Accepted
- Date: 2026-07-17

## Context

RoleGit's encrypted objects, repository metadata, coordination APIs, and customer KMS interfaces are
public contracts. Their compatibility and security claims must not depend on an unpublished hosted
implementation. The repository also needs a predictable path from development to stable releases.

## Decision

### Branch and Release Policy

- `develop` is the integration branch and the base for feature and maintenance pull requests.
- Once release automation is enabled, successful releases from `develop` use a prerelease channel such
  as npm `next`. They are not stable releases.
- `main` contains stable release history. Changes reach `main` through a reviewed release-promotion
  pull request from tested `develop` history, not through direct development.
- Direct pushes are not part of either branch workflow. CI, review, and release controls are enforced
  through pull requests.
- Stable tags and artifacts are produced from `main`; prerelease tags and artifacts are produced from
  `develop`. Release automation must not publish until package ownership and trusted publishing are
  deliberately configured.

### Protocol Versioning

Encrypted object formats, Git-tracked metadata schemas, coordination APIs, and KMS provider
interfaces each carry an explicit version independent of the CLI/npm package version.

- An incompatible wire or persisted-format change increments that contract's major or format
  version and defines migration and downgrade behavior.
- Additive fields are ignored only where the applicable schema explicitly marks that behavior safe.
  Security-critical readers otherwise fail closed on unsupported versions or semantics.
- Patch-level clarifications cannot weaken authenticated context, key authority, or trust boundaries.
- Released clients document the protocol versions they read and write. Compatibility is never inferred
  only from the RoleGit package version.
- Draft contract changes land on `develop` with specifications and fixtures. A contract becomes stable
  only when promoted and released from `main`.
- RoleGit-hosted and customer-hosted implementations use the same public contracts. There is no private
  RoleGit Cloud protocol dialect that can silently redefine key custody or compatibility.

### MIT Repository Ownership

This MIT-licensed repository is the canonical home for:

- the Community CLI and local-first implementation;
- architecture, security, and trust-boundary decisions;
- encrypted object and repository metadata specifications;
- public Team coordination and Enterprise KMS/self-hosting interfaces; and
- schemas, migrations, test vectors, and conformance fixtures needed for interoperability.

Public contract changes are proposed and reviewed here before release. A separately operated hosted
service may have deployment code outside this repository, but it cannot privately redefine these
contracts or the promise that RoleGit Cloud receives no plaintext or decryption key material in Team
mode. Customer-hosted implementations may replace service components while conforming to the same
contracts.

The MIT license applies to files in this repository. It does not transfer ownership of customer
repositories, ciphertext, metadata, policies, keys, or plaintext to RoleGit, and it does not imply
that customer deployments or separately distributed service implementations are MIT-licensed.

## Consequences

- Contributors target `develop`; release promotion to `main` is explicit and auditable.
- Persisted and network contracts evolve independently from product packaging.
- Security-sensitive unknown versions fail closed unless a specification proves safe extensibility.
- Open specifications and conformance assets remain sufficient for independent and self-hosted client
  implementations.
- Hosting and commercial packaging may vary without changing public compatibility or confidentiality
  claims.
