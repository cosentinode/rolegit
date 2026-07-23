# Contributing to RoleGit

RoleGit is an early security-sensitive prototype. Keep pull requests focused and preserve the trust
boundaries in the [`threat model`](docs/threat-model.md), [`prototype security model`](docs/security.md),
and architecture decision records.

## Handle Secrets Safely

- Never use or commit real customer plaintext, credentials, access or session tokens, private keys,
  recovery material, or production configuration in code, tests, fixtures, examples, logs, issues, or
  pull requests.
- Use conspicuous synthetic canaries for tests. Keep assertions that prevent plaintext, KEKs, private
  keys, and tokens from appearing in user-facing output when changing logging or error paths.
- Review staged changes and generated/package output before committing. Treat build artifacts, debug
  logs, screenshots, and copied terminal output as possible disclosure paths.
- If a real secret enters Git, an issue, CI output, or another shared system, stop sharing it, notify a
  maintainer through the process in [`SECURITY.md`](SECURITY.md), and rotate or revoke it immediately.
  Deleting a branch, issue, or current file does not remove history or retained copies.

These rules address accidental contributor disclosure; they do not change the local-compromise,
historical-revision, or user-copy limits in the [threat model](docs/threat-model.md).

## Set Up a Clean Clone

Install Node.js 22 or newer and Git, then run:

```bash
git clone https://github.com/cosentinode/rolegit.git
cd rolegit
git switch develop
npm ci
npm run typecheck
npm run build
npm test
npm run package:check
npm run smoke
```

`npm ci` installs the exact development dependencies in `package-lock.json`. The commands above are
the same quality checks expected for a pull request.

## Branch and Pull Request Workflow

- Create feature, fix, documentation, and maintenance branches from the latest `develop`.
- Open focused pull requests back to `develop` and link the issue they resolve.
- Do not push directly to `main` or `develop`; all changes go through review and CI in a pull request.
- Treat `main` as stable release history, not a development branch.
- Promote a tested `develop` revision to `main` only through a reviewed release-promotion pull request.
- Do not publish stable packages or artifacts until package ownership and trusted publishing are
  deliberately configured.

CODEOWNERS currently requests review from the sole repository owner but does not enforce an approval.
GitHub does not allow a pull request author to approve their own change, so requiring code-owner
approval would deadlock owner-authored pull requests until an independent eligible reviewer is added.

This workflow implements the release policy in
[`ADR 0002`](docs/adr/0002-branches-protocols-and-repository-ownership.md). Required GitHub Actions
contexts are not yet trusted, unspoofable enforcement; do not describe them as such while
[issue #2](https://github.com/cosentinode/rolegit/issues/2) remains open.

## Commits and Pull Requests

Use [Conventional Commits](https://www.conventionalcommits.org/) for commit messages and pull request
titles:

```text
feat(cli): add a command
fix: reject an unsafe path
docs: clarify a trust boundary
```

Run `printf '%s\n' 'fix: example description' | npm run lint:commit` to check a message locally.
Pull requests must complete the repository template with an issue link, validation performed, risks,
and security effects. Call out changes to cryptography, authorization, key custody, persisted formats,
protocols, GitHub Actions, dependencies, or release behavior explicitly.

Before requesting review, run:

```bash
npm run typecheck
npm run build
npm test
npm run package:check
npm run smoke
npm run test:pr-title
```
