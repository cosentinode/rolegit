# Security Policy

RoleGit is an early security-sensitive prototype. The current centralized authorization service is
experimental, self-hosted only, and must not be used with real secrets. The target Community, Team,
and Enterprise designs are not yet released security guarantees. See the
[threat model](docs/threat-model.md) and [current prototype security model](docs/security.md) before
evaluating or deploying the project.

## Reporting a Vulnerability

Do not include vulnerability details, exploit code, credentials, private keys, customer data, or
other secrets in a public issue or pull request.

This repository does not currently publish a security email address, and GitHub private
vulnerability reporting is not currently enabled. To request a private reporting channel, open a
[security-labeled issue](https://github.com/cosentinode/rolegit/issues/new?labels=area%3Asecurity%2Csecurity-critical)
containing only:

- a request for private contact;
- the affected RoleGit version or commit; and
- a non-sensitive summary such as "possible confidentiality issue in the CLI."

A maintainer will arrange a private channel before asking for technical details. If no private
channel is arranged, do not post the details publicly. Once contact is established, include the
affected component and mode, reproduction steps or a proof of concept, impact, prerequisites, and
any suggested mitigation. Do not send real customer secrets; use synthetic canaries.

If GitHub later shows a **Report a vulnerability** button on this repository's Security page, use
that private route instead of opening an issue. This policy does not claim that feature is available
today.

## Response Targets

These are good-faith targets for this volunteer prototype, not service-level guarantees:

- acknowledge a private report or channel request within 3 business days;
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

RoleGit has no stable or production-supported release. Security fixes are made only on the latest
`develop` revision and then follow the repository's release process. Older commits, npm package
`0.1.0`, forks, and modified deployments do not receive security updates. The current prototype and
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
