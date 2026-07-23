# Security Policy

RoleGit is an early security-sensitive prototype. The current centralized authorization service is
experimental, self-hosted only, and must not be used with real secrets. The target Community, Team,
and Enterprise designs are not yet released security guarantees. See the
[threat model](docs/threat-model.md) and [current prototype security model](docs/security.md) before
evaluating or deploying the project.

## Reporting a Vulnerability

Do not include vulnerability details, exploit code, credentials, private keys, customer data, or
other secrets in a public issue or pull request.

Use GitHub's enabled private vulnerability reporting form at
[Report a vulnerability](https://github.com/cosentinode/rolegit/security/advisories/new). You must be
signed in to GitHub. Submit the affected source revision or locally built artifact, component and
mode, reproduction steps or a proof of concept, impact, prerequisites, and any suggested mitigation.
Do not send real customer secrets; use synthetic canaries.

The report and its discussion are a private repository security advisory rather than a public issue,
so the reporter identity, report existence, timestamps, affected revision, category, and technical
details are not exposed through public issues, notifications, search, or repository history. GitHub,
repository administrators and security managers, and people explicitly added to the advisory can
access advisory metadata and content. Use a reporting GitHub account whose identity you are willing
to disclose to those parties. This repository does not publish a separate security email address; do
not open a public issue or pull request to request private contact.

## Response Targets

These are good-faith targets for this volunteer prototype, not service-level guarantees:

- acknowledge a private report within 3 business days;
- provide an initial severity and scope assessment within 7 business days after receiving details;
- provide a status update at least every 14 calendar days while remediation is active; and
- coordinate disclosure timing with the reporter after a fix or mitigation is available.

Complex fixes, upstream dependencies, and maintainer availability may change remediation timing. We
will communicate delays rather than promise a universal time to resolution. Public disclosure should
wait until maintainers and the reporter agree on timing or 90 days after the project receives the
private technical report, whichever comes first, unless active exploitation or user safety requires a
different schedule.

## Scope

Reports are in scope when they affect RoleGit source or packaged artifacts, confidentiality or
integrity boundaries, cryptography or key handling, authorization, plaintext cleanup, persisted
formats, security-sensitive CI or release behavior, or claims made by the public Community, Team, and
Enterprise contracts in this repository.

RoleGit-specific misuse of GitHub, Node.js, npm, Git, or another dependency is in scope. A defect
solely in an upstream project should be reported under that project's policy; tell us privately if it
also requires a RoleGit mitigation. The documented limitations and non-goals in the
[threat model](docs/threat-model.md#non-goals) are not vulnerabilities by themselves, but a bypass of
a stated control or an undocumented expansion of a trust boundary is in scope.

## Supported Versions

RoleGit has no stable or production-supported release, and no RoleGit package is currently published
to npm. Security fixes are made only on the latest `develop` source revision and locally built
artifacts from that exact revision, then follow the repository's release process. The `0.1.0` value in
`package.json` is prototype metadata, not a published npm release. Older commits, older local
artifacts, forks, and modified deployments do not receive security updates. The current prototype and
all planned modes remain pre-production; this support statement does not make them suitable for real
secrets.

## Safe Harbor

We will not initiate legal action or request a platform investigation for good-faith research that:

- follows this policy and applicable law;
- uses only accounts, repositories, and data you own or have explicit permission to test;
- avoids privacy violations, service disruption, persistence, social engineering, and data
  destruction;
- accesses only the minimum data needed to demonstrate the issue and promptly deletes it; and
- gives us a reasonable opportunity to remediate before public disclosure.

Research outside these boundaries is not authorized by this policy. We cannot bind third parties,
law enforcement, infrastructure providers, or owners of systems you do not control. If uncertain,
request a private channel before testing.
