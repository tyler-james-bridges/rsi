# Public project and build-in-public repository decision

- Status: **accepted**
- Accepted: **2026-08-16**
- Scope: project identity, source-repository visibility, and repository controls
- Supersedes: repository-privacy portions of `DEC-Q024`, `DEC-Q028`, `DEC-Q077`,
  `DEC-Q078`, `DEC-Q090`, `DEC-Q176`, and `DEC-Q195`

## Decision

RSI is a public project developed in the public `tyler-james-bridges/rsi` GitHub
repository. Public project and source visibility are intentional and do not grant
any runtime, provider, credential, deployment, payment, wallet, order, or
transaction authority.

The public project identity covers its reviewed source, engineering documentation,
roadmap, issues, and sanitized progress evidence. It does not promise publication
of operational data, hidden evaluation material, credentials, provider responses,
or production diagnostics.

The public repository contains only reviewed source, documentation, synthetic or
licensed visible fixtures, and content-free verification evidence. Credentials,
provider responses, hidden evaluation cases, environment state, local databases,
signing material, and production diagnostics remain outside Git and follow their
existing custody and retention rules.

Public visibility is not an open-source license grant. No project license is chosen
by this decision; adding one requires a separate owner decision.

## Evidence before transition

- The built-in scanner passed the tracked tree and complete Git history.
- Checksum-verified Gitleaks passed the tracked tree and complete Git history.
- No credential, key, database, capture, archive, or generated session file is
  tracked.
- Existing commit-author metadata and canonical local-path references were reviewed
  and accepted for public disclosure; history is preserved rather than rewritten.
- The repository has a verification-only CI workflow with read-only repository
  permission and no configured production secret or deployment step.

## Required public controls

- The project and canonical GitHub repository MUST remain public unless a later
  explicit owner decision supersedes this decision.
- `main` MUST require pull requests plus the `quality` and `gitleaks-history` checks.
- Force pushes and branch deletion MUST remain disabled.
- GitHub private vulnerability reporting MUST be enabled and `SECURITY.md` MUST
  point to it.
- Secret scanning and other free public-repository analysis may supplement, but do
  not replace, the repository-owned local and history scanners.
- Every future source change remains subject to the same disclosure and release
  boundaries. Public development does not make operational data public.

## Applied controls

- GitHub reports repository visibility as `public`.
- `main` requires pull requests and strict successful `quality` plus
  `gitleaks-history` checks, including for the administrator.
- Force pushes and branch deletion are disabled; unresolved review conversations
  block merging.
- Private vulnerability reporting, public-repository secret scanning, and push
  protection are enabled.
- Hosted run
  [31994805712](https://github.com/tyler-james-bridges/rsi/actions/runs/31994805712)
  passed both required checks on the disclosure commit before the visibility
  transition.

## Irreversibility and rollback

Repository visibility can be changed later, but public commits may already have
been cloned or cached. Therefore this transition is treated as irreversible
disclosure. A later visibility change does not revoke already published source.
