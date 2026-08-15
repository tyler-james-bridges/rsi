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

Reviewed 2026-08-14. Re-resolve and review every pin before changing it.

| Component            | Reviewed release | Full commit pin                            |
| -------------------- | ---------------- | ------------------------------------------ |
| `actions/checkout`   | `v4.2.2`         | `11bd71901bbe5b1630ceea73d27597364c9af683` |
| `actions/setup-node` | `v4.4.0`         | `49933ea5288caeca8642d1e84afbd3f7d6820020` |
| `pnpm/action-setup`  | `v4.1.0`         | `a7487c7e89a18df4991f7f222e4898a00d66ddda` |

Gitleaks Action v2 was rejected because its implementation uses the Actions cache internally and
can resolve its scanner version dynamically. CI instead downloads the official Linux x64 release
archive for Gitleaks `8.29.1`, verifies SHA-256
`e4eb209d04e20339d77122a3bdf9cd41351255cfb27ebcb75e85325e04f88924`, runs a synthetic-detection
smoke test, and scans the full history with 100% redaction. The archive and checksum were verified
against the [official v8.29.1 release](https://github.com/gitleaks/gitleaks/releases/tag/v8.29.1).
The narrow config allowlist requires both an exact file path and an exact, anchored type-only line;
it does not suppress an entire file or rule.

Node `24.19.0` was verified against the
[official Node 24 archive](https://nodejs.org/en/download/archive/v24), which identified it as the
latest Node 24 LTS release at review time. The matching major-line type package is exactly pinned to
`@types/node@24.13.3`. Action tag objects and commits were resolved directly from their public Git
repositories; workflow execution remains the required functional verification.
