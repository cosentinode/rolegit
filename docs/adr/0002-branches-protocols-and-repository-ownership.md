# ADR 0002: Branches, Protocols, and Repository Ownership

- Status: Accepted
- Date: 2026-07-17

## Context

RoleGit's encrypted objects, repository metadata, coordination APIs, and customer KMS interfaces are
public contracts. Their compatibility and security claims must not depend on an unpublished hosted
implementation. The repository also needs a predictable path from development to stable releases.

## Decision

### Branch and Release Policy

The following bullets define the intended release policy, not the repository's complete current
enforcement state.

- `develop` is the integration branch and the base for feature and maintenance pull requests.
- Once release automation is enabled, successful releases from `develop` use a prerelease channel such
  as npm `next`. They are not stable releases.
- `main` contains stable release history and is the base for reviewed release-promotion pull requests
  from tested `develop` history, not direct development.
- Direct pushes are not part of either branch workflow. CI, review, and release controls are enforced
  through pull requests.
- Stable tags and artifacts are produced from `main`; prerelease tags and artifacts are produced from
  `develop`. Release automation must not publish until package ownership and trusted publishing are
  deliberately configured.

Currently, the repository's only CI workflow runs for pull requests whose base is `develop`. A
release-promotion pull request to `main` therefore receives no repository build, test, package
dry-run, or CLI checks, so stable promotion and publication are not yet gated as this policy intends.
[Issue #2](https://github.com/cosentinode/rolegit/issues/2) and
[PR #52](https://github.com/cosentinode/rolegit/pull/52) track CI for both bases and the unresolved
trusted-enforcement work. This documentation decision neither implements those workflows nor treats
them as complete. Until that work is resolved and verified, maintainers must not claim that a `main`
promotion satisfied the intended repository CI gate or publish a stable artifact on that basis.

### Protocol Versioning

Encrypted object formats, Git-tracked metadata schemas, coordination APIs, and KMS provider
interfaces each carry an explicit version independent of the CLI/npm package version.

The rules below govern future specified contracts and versions promoted as stable. The current v1
encrypted-object, `.enclist`, and server-policy readers are a prototype exception: they require
version 1 and validate recognized fields, but silently ignore unknown object fields, including unknown
encrypted-object and wrapped-key fields. No published v1 schema marks those additions as safe. This
behavior is not fail-closed extensibility, permission for producers to add fields, or a compatibility
promise. v1 producers must not place security semantics in unknown fields, and consumers must not rely
on those fields surviving a read/write cycle. Before a contract is declared stable, its schema must
explicitly define safe additive fields or its readers must reject unknown fields.

- An incompatible wire or persisted-format change increments that contract's major or format
  version and defines migration and downgrade behavior.
- In future specified contracts, additive fields are ignored only where the applicable schema
  explicitly marks that behavior safe. Security-critical readers otherwise fail closed on unsupported
  versions or semantics.
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

- Contributors target `develop`; the intended release promotion to `main` is explicit and auditable,
  but its repository CI gate remains pending under issue #2.
- Persisted and network contracts evolve independently from product packaging.
- Future specified contracts fail closed on unsupported versions or semantics unless their schema
  proves safe extensibility; current permissive v1 unknown-field handling remains a documented
  prototype exception, not stable protocol policy.
- Open specifications and conformance assets remain sufficient for independent and self-hosted client
  implementations.
- Hosting and commercial packaging may vary without changing public compatibility or confidentiality
  claims.
