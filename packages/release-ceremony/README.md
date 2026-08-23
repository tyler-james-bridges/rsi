# Foundation release ceremony

`@rsi/release-ceremony` is the fail-closed wrapper for RSI's Foundation Stage A
v2 evidence ceremony. It assembles the exact clean-tree release inventory, binds a
fresh retained public `main` CI run and the repository-pinned provisioning
identity plus an exact independent review, proves it is running on the
platform-pinned designated MacBook, asks the fixed Keychain identity for exactly two
user-presence-gated Ed25519 signatures, and verifies every result before returning.

This package does not provision a key, install a Git object, create a Git ref or
tag, push, create a GitHub release, upload, deploy, make a provider call, spend, or
grant Observer readiness. No real key has been provisioned and no real ceremony
has run. Tests use injected ephemeral signers; that test seam is not exported from
the package root.

The complete operator sequence and current physical blockers are documented in
[Foundation Stage A v2](../../docs/production-readiness/v1/foundation-stage-a-v2.md).
The current signed-component blocker and required public drill record are detailed
in the [release-helper compatibility gate](../../docs/production-readiness/v1/helper-compatibility-gate.md).

## Fixed boundaries

- release: `0.1.0-foundation.1`
- detached tag name: `foundation-v1`
- repository: public `tyler-james-bridges/rsi`
- branch/event: successful `push` to `main`
- runtime: Node `24.19.0`, pnpm `11.20.0`
- Keychain service: `dev.rsi.macbook.release-signing`
- Keychain account: `release-ed25519-v1`
- identity pins:
  `config/foundation-release-identity.v1.json` and
  `config/foundation-release-key-provisioning-receipt.v1.json`
- helper compatibility pin:
  `config/foundation-release-key-helper-compatibility.v1.json`
- independent-reviewer trust pin:
  `config/foundation-independent-reviewer-identity.v1.json`
- inputs: distinct canonical owner-only retained CI and `.review-evidence.json`
  records outside the repository
- outputs: five distinct, create-only, owner-only files outside the repository:
  `.rsi-release`, `.receipt.json`, `.readiness-conclusion.json`,
  `.foundation-tag`, and `.ceremony-report.json`

There is deliberately no private-key, key-path, Keychain-selector, arbitrary
signer-command, helper, tag-installation, push, or publication argument. The
native helper is compiled from the tracked `HEAD` blob and its source, binary, and
compiler-identity hashes must match the committed public identity. The provisioning
source commit must be an ancestor of the pinning commit, while the compatibility
record and helper source must match across the tested, provisioning, and pinning
commits. The exact compatibility-record hash and tested commit are bound into the
identity, receipt, readiness conclusion, and ceremony report. The domain-separated
designated-MacBook platform identity must also match the intent, public pin,
receipt, and live ceremony host. The Keychain capabilities are usable only in the
fixed release-then-tag order inside one custody callback.

## Retain final public CI evidence

After the nonsecret identity and provisioning receipt are pinned through protected
public `main`, inspect the exact public GitHub Actions run and confirm both required
jobs and the full commit. Then retain the canonical record while networked:

```bash
pnpm foundation:ci-retain -- \
  --run-id <decimal-run-id> \
  --output /absolute/owner-only/foundation-ci.json \
  --confirm-commit <full-40-character-commit>
```

The adapter uses only fixed unauthenticated public GitHub GET endpoints and writes
one create-only `0600` file outside the repository. The result is an
operator-retained representation, not an independently signed GitHub attestation;
visual inspection of the public run remains mandatory.

## Independent review evidence

Before the reviewed release commit exists, a non-authoring reviewer must publish
its canonical Ed25519 public identity at the fixed trust path above. The production
reader requires the exact same `100644` Git blob in every parent of the reviewed
commit. A reviewer identity added or changed by the reviewed commit is a self-pin
and is refused. Replace refs, grafts, and shallow history are also refused. The
reviewer ID and key must differ from the release signer and known release operator
identities.

Before signing, that reviewer must approve the exact pinning commit and Git tree in
a canonical, domain-separated Ed25519-signed envelope stored as the owner-only
`.review-evidence.json` file. The complete canonical inner body and exact reviewer
identity hash/key/ID are signed. All five fixed scopes must pass: repository diff,
release-key provisioning, ceremony/tag, failure/recovery controls, and tests/
documentation. Every recorded finding must be unique and resolved with finding/
resolution hashes. The fixed role is `independent-non-authoring-agent`, verdict is
`approved`, and the review must be no more than seven days old when the ceremony
starts. The ceremony hashes and binds the complete signed envelope, not only its
inner body.

The trust file is intentionally absent today, so production review-file ingestion
and the real ceremony remain blocked until an independent reviewer key is created
and its public identity is merged in a strict ancestor commit.

The exact schema and illustrative JSON template are in
[Foundation Stage A v2](../../docs/production-readiness/v1/foundation-stage-a-v2.md#phase-2a-retain-independent-review-evidence).

## Ceremony command

On the designated MacBook only, first update the clean checkout to the exact
pinning commit and transfer the retained CI evidence. Then physically disconnect
networking: no IPv4/IPv6 default route and no active or addressed non-loopback
interface may remain.

```bash
pnpm foundation:ceremony -- \
  --ci-evidence /absolute/owner-only/foundation-ci.json \
  --review-evidence /absolute/owner-only/foundation.review-evidence.json \
  --output /absolute/owner-only/foundation.rsi-release \
  --receipt /absolute/owner-only/foundation.receipt.json \
  --conclusion /absolute/owner-only/foundation.readiness-conclusion.json \
  --tag-object /absolute/owner-only/foundation.foundation-tag \
  --report /absolute/owner-only/foundation.ceremony-report.json \
  --confirm-commit <full-40-character-commit> \
  --confirm-release 0.1.0-foundation.1
```

The command refuses before custody on a non-MacBook, active networking, dirty
tree, non-`main` checkout, commit mismatch with `origin/main` or CI, stale/future
CI, stale or mismatched independent review, unapproved remote, wrong runtime,
absent or mismatched identity pins, non-ancestor provisioning commit, changed
helper evidence, wrong MacBook platform identity, existing `foundation-v1`, unsafe
paths, existing outputs, or any inventory or signature mismatch.

## Signature order and artifacts

The first user-presence prompt signs only the domain-separated release manifest.
The resulting bundle is immediately verified against the repository-pinned public
key, and its independent receipt is held for publication after custody completes.
The tool then creates and verifies a canonical readiness conclusion binding the
complete release/CI/identity/platform and independent-review evidence. Its fifth
fixed check requires the independent adversarial review to have passed.

The second, separate user-presence prompt signs only the fixed OpenSSH `git`
namespace data for an annotated `foundation-v1` tag object. The result is verified
and held with the other ancillary evidence until the custody callback has completed
its exactly-two-signature postcondition and helper cleanup. The canonical report
binds the complete release evidence, readiness-conclusion hash, independent-review
hash, helper/platform evidence, signer, and detached tag identities with
`signatureCount: 2`.

Only after custody completes cleanly does the ceremony publish the four pre-reserved
ancillary outputs, in this order: detached tag, bundle receipt, ceremony report, and
readiness conclusion. The readiness conclusion is published last and is the final
completion marker. A missing or empty conclusion means the retained set is not a
completed ceremony, even if another output contains complete-looking bytes.

The detached bytes are suitable for later independent Git verification, but this
tool never places them in `.git/objects` or creates `refs/tags/foundation-v1`.
Installing or publishing the tag and creating any GitHub release are separate
explicitly approved operations.

## Independent aggregate verification

From a clean, full-history `main` checkout at the exact reviewed commit, with
`origin/main` at the same commit and the approved public remote configured, reopen
the complete retained set with the read-only verifier:

```bash
pnpm foundation:verify -- \
  --bundle /absolute/owner-only/foundation.rsi-release \
  --receipt /absolute/owner-only/foundation.receipt.json \
  --conclusion /absolute/owner-only/foundation.readiness-conclusion.json \
  --tag-object /absolute/owner-only/foundation.foundation-tag \
  --report /absolute/owner-only/foundation.ceremony-report.json \
  --ci-evidence /absolute/owner-only/foundation-ci.json \
  --review-evidence /absolute/owner-only/foundation.review-evidence.json \
  --confirm-commit <full-40-character-commit> \
  --confirm-release 0.1.0-foundation.1
```

The verifier strictly decodes the canonical v2 report and all four ancillary
records, cryptographically verifies the signed bundle and detached tag, and
requires a passed `FOUNDATION_BUILT` conclusion. It reconstructs the complete
ceremony inventory from the exact tracked Git blob objects at the confirmed commit
using the retained CI record and the signed bundle creation time, then compares the
derived artifact count, every artifact-set binding, commit, tree, release, exact
Node/pnpm versions, and null Foundation predecessor with the signed bundle and
report. It also requires CI to precede bundle creation by no more than seven days,
review to follow CI, and review to be no more than seven days before—or five
minutes after—the signed bundle creation time. The production review reader
authenticates the complete signed envelope against the reviewer identity pinned
unchanged in every parent of the reviewed commit, while the production identity
reader independently rechecks the tested-helper, provisioning, and pinning
lineage. Any missing, partial, noncanonical, stale, future, duplicated, or
mismatched evidence refuses.

This command only reads owner-only files and hardened Git metadata. It does not
access Keychain, request a signature, restore files, install the detached Git
object, create a ref, publish, upload, or modify the retained evidence. On success
it prints one canonical summary with
`status: "verified-foundation-ceremony-outputs"`.

The aggregate verifier is implemented and tested with ephemeral cryptographic
fixtures, but it cannot make a production claim today. No real ceremony evidence
exists, the independent-reviewer trust file and passing compatibility record are
absent, the stable signed component is unimplemented, and the v1 compatibility
format is inspection-only. RSI therefore remains below `FOUNDATION_BUILT`.

## Failure and evidence handling

All outputs are create-only, mode `0600`, and live in a canonical owner-only
directory outside the repository. A refusal after a durable output does not erase
it. Preserve every partial artifact and the error, investigate, and use a new empty
output directory only after review. Never overwrite a partial result or interpret
it as a completed ceremony.

Before custody, the ceremony exclusively creates and fsyncs owner-only reservations
for the receipt, readiness conclusion, detached tag, and ceremony report. Inside
custody, release-bundle publication creates and fsyncs its separate internal attempt
file before invoking the first signer. A failed attempt preserves every reservation
and every byte that may have been written. Pre-link/link failures retain a signed
bundle partial; post-link failures retain a unique verified destination whenever
safe. No ancillary reservation is deleted or truncated after custody begins, and no
ancillary success output is published until custody has completed cleanly.

Only independent verification of the retained CI and already-approved review
evidence, bundle, receipt, readiness conclusion, detached tag, report, commit/tree,
designated platform hash, and public fingerprint may support a `FOUNDATION_BUILT`
determination. This repository does not currently make that claim.
