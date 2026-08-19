# Foundation release ceremony

`@rsi/release-ceremony` is the fail-closed wrapper for RSI's first signed
foundation release. It assembles the exact clean-tree release inventory, binds a
retained successful `main` CI run, asks the fixed MacBook Keychain identity for
one Ed25519 signature, verifies the resulting bundle immediately, and publishes
an independent owner-only receipt.

This package does not provision a key, create a Git tag or GitHub release, push,
deploy, make a provider call, or grant Observer readiness. The production CLI is
MacBook-only. Tests use an injected ephemeral signer; that test seam is not
exported from the package root.

## Fixed boundaries

- release: `0.1.0-foundation.1`
- intended Git tag after separate approval: `foundation-v1`
- repository: public `tyler-james-bridges/rsi`
- branch/event: successful `push` to `main`
- runtime: Node `24.19.0`, pnpm `11.20.0`
- Keychain service: `dev.rsi.macbook.release-signing`
- Keychain account: `release-ed25519-v1`
- output: a create-only `.rsi-release` bundle and distinct create-only
  `.receipt.json`, both outside the repository in an owner-only directory

There is deliberately no private-key, key-path, Keychain-selector, arbitrary
signer-command, tag, push, or publication argument. The Keychain capability is
valid for one signature inside one custody callback and becomes unusable when the
callback ends.

## Ceremony command

First inspect the retained public CI run URL and its exact commit. The CI evidence
file must satisfy the closed `rsi.foundation-ci-evidence` v1 schema, be canonical
JSON without a trailing newline, be mode `0600`, and live outside the repository
in a canonical owner-only directory.

On the designated MacBook only:

```bash
pnpm foundation:ceremony -- \
  --ci-evidence /absolute/owner-only/foundation-ci.json \
  --output /absolute/owner-only/foundation.rsi-release \
  --receipt /absolute/owner-only/foundation.receipt.json \
  --confirm-commit <full-40-character-commit> \
  --confirm-release 0.1.0-foundation.1
```

The command refuses a non-MacBook before reading CI evidence or the Keychain. It
also refuses a dirty tree, a non-`main` checkout, a commit that differs from
`origin/main` or the retained evidence, an already-present `foundation-v1` tag,
stale/future evidence, unsafe paths, existing outputs, wrong runtime pins, and any
bundle that fails immediate signature/receipt verification.

## Evidence limitation

The release signature binds the canonical retained CI record and each closed test
result hash. The CI record is an operator-retained representation of the public
GitHub run; it is not an independently signed GitHub attestation. Before signing,
the operator must independently open the exact public run URL, confirm both jobs
and the commit, and retain the file plus its reported SHA-256. Adding a separately
verifiable CI attestation is future hardening, not a reason to claim it exists now.
