# GitHub automation boundary

CI is verification-only. It has repository `contents: read`, persists no checkout credential, uses
no configured or production secret, enables no dependency cache, uploads no artifact, and contains
no deployment step. Checkout uses only GitHub's ephemeral repository-scoped token and does not
persist it.

The quality job performs locked installation, format/type/test checks, offline demos, a local
working-tree plus full-history secret scan, a registry advisory audit, and a final dirty-tree check.
The dependency audit necessarily contacts the package registry. No RSI source-provider, wallet,
DNS, hosting, or production endpoint is contacted.

## Reviewed volatile pins

Reviewed 2026-08-15. Re-resolve and review every pin before changing it.

| Component          | Reviewed release | Full commit pin                            |
| ------------------ | ---------------- | ------------------------------------------ |
| `actions/checkout` | `v7.0.1`         | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| `pnpm/setup`       | `v2.0.2`         | `84cb39b217b10273981911c288cd62326dc7c6d2` |

Gitleaks Action v2 was rejected because its implementation uses the Actions cache internally and
can resolve its scanner version dynamically. CI instead downloads the official Linux x64 release
archive for Gitleaks `8.30.1`, verifies SHA-256
`551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb`, runs a synthetic-detection
smoke test, and scans the full history with 100% redaction. The archive and checksum were verified
against the [official v8.30.1 release](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1).
The narrow config allowlist requires both an exact file path and an exact, anchored type-only line;
it does not suppress an entire file or rule.

`pnpm/setup` is configured with caching and implicit install disabled; it installs exactly pnpm
`11.20.0` and Node `24.19.0`, after which CI performs its own frozen install. Node `24.19.0` was verified against the
[official Node 24 archive](https://nodejs.org/en/download/archive/v24), which identified it as the
latest Node 24 LTS release at review time. The matching major-line type package is exactly pinned to
`@types/node@24.13.3`. Action tag objects and commits were resolved directly from their public Git
repositories; workflow execution remains the required functional verification.
