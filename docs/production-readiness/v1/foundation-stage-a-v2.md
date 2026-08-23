# Foundation Stage A v2 workflow

- Status: **fail-closed offline workflow implemented; stable signed component
  unimplemented; physical compatibility, provisioning, signing, and production
  five-scope review remain unperformed**
- Release: `0.1.0-foundation.1`
- Intended tag name: `foundation-v1`
- Authority granted now: **none**

This is the operator sequence for producing the evidence needed to evaluate the
`FOUNDATION_BUILT` label. The repository is the public, build-in-public
[`tyler-james-bridges/rsi`](https://github.com/tyler-james-bridges/rsi) project.
Public source, the nonsecret release identity, and sanitized verification evidence
do not expose operational data or grant provider, wallet, payment, deployment, or
runtime authority. The workspace's `"private": true` package metadata only blocks
accidental npm publication.

No real ceremony has run. Nothing in this document, a passing test, or the
existence of ceremony code means that RSI has attained `FOUNDATION_BUILT`.

## Narrow Stage A key exception

Stage A still permits zero live provider calls and zero provider/runtime
credentials. Its one narrow exception is the offline bootstrap of the dedicated
MacBook governance release key needed to sign Stage A's own evidence. That Ed25519
identity:

- remains in the fixed Data Protection Keychain service
  `dev.rsi.macbook.release-signing`, account `release-ed25519-v1`;
- is restricted to the two fixed ceremony domains: the release manifest first and
  the detached Git tag object second;
- is bound to a domain-separated hash of the designated MacBook's platform UUID;
  the raw UUID is not retained;
- has no network, provider, wallet, payment, trading, deployment, checkpoint,
  operator-approval, or public-artifact authority;
- accepts no caller-selected key, service, account, helper, signer command, or
  private-key path; and
- is backed by exactly two separately encrypted offline recovery envelopes on
  distinct physical disks.

This exception does not authorize any canary or production credential. Those stay
behind the later provisioning checkpoint.

## Hard blocker: throwaway MacBook compatibility drill

The tracked record is fixed at
`config/foundation-release-key-helper-compatibility.v1.json`. It is intentionally
absent today. The provisioning command validates that exact `HEAD` blob, its tested
commit ancestry, helper source at both commits, helper binary/compiler hashes, and
the exact OS/runtime before inspecting recovery targets, reading Keychain presence,
requesting a passphrase, generating a key, or writing durable state.

Do not create the real identity until a disposable MacBook drill proves the exact
macOS/Keychain behavior of the tracked native helper. Record the reviewed commit,
Node `24.19.0`, pnpm `11.20.0`, macOS and Swift compiler identities, helper source
hash, deterministic helper-binary hash, and the observed access-control behavior.

The drill must show that the fixed helper creates and reopens only a Data
Protection Keychain item with `WhenUnlockedThisDeviceOnly`, synchronization
disabled, and user presence required. It must also show two separate user-presence
prompts for the fixed release-then-tag signing sequence, with no persistent
`Always Allow` grant. It must inspect arguments, environment, stdout/stderr, and
temporary files for private material. Any identity, ACL, prompt, helper-hash, or
cleanup ambiguity blocks the designated-MacBook ceremony.

The throwaway drill uses no real recovery passphrase or production identity. Its
evidence is reviewed before proceeding; a successful unit test or Swift typecheck
does not substitute for this physical drill.

The current ad-hoc helper cannot truthfully prove exclusive alternate-client
refusal and therefore cannot produce a passing record. A provisioned, stable
signed component with an exact Keychain access group and internal one-shot
release-then-tag policy must replace it first. See the
[release-helper compatibility gate](./helper-compatibility-gate.md) for the
architectural blocker, exact evidence shape, and T → A → B Git lineage.

## Phase 1: physically provision the release identity

1. Merge and independently review the v2 workflow on protected public `main`.
   Verify a clean checkout with `main == origin/main`, the approved public remote,
   exact runtime pins, and no existing `foundation-v1` tag.
2. Designate the ceremony MacBook. Stop screen recording and livestreaming. Create
   an owner-only local evidence directory outside the repository and the owner-only
   fixed intent directory at
   `~/Library/Application Support/RSI`. Do not put either in a synced folder.
   Provisioning binds this MacBook's domain-separated platform-identity hash; a
   later ceremony on any other MacBook refuses.
3. Prepare two separately owned, physically distinct, encrypted external APFS
   disks. Create one owner-only recovery directory on each. Formatting and
   encryption are destructive manual operations and are intentionally not
   automated by RSI. The preflight resolves each APFS physical-store partition
   to its parent whole disk and requires affirmative physical, external,
   writable, non-internal metadata. Disk images, file-backed/virtual media, and
   two volumes or partitions on the same whole disk are refused.
4. Disable Wi-Fi, Ethernet, Bluetooth networking, VPNs, and other non-loopback
   interfaces. The command requires no IPv4 or IPv6 default route and no active or
   addressed non-loopback interface. Disconnecting only from Wi-Fi is not enough.
5. With both recovery disks mounted, run the fixed create command from the clean
   public `main` checkout:

   ```bash
   pnpm foundation:key-provision -- \
     --mode create \
     --backup-one /Volumes/RSI-RECOVERY-A/recovery \
     --backup-two /Volumes/RSI-RECOVERY-B/recovery \
     --public-identity /absolute/owner-only/foundation.release-public-identity.json \
     --receipt /absolute/owner-only/foundation.release-key-provisioning-receipt.json \
     --confirm-account release-ed25519-v1 \
     --confirm-copy-count 2
   ```

6. Enter two different passphrases only through `/dev/tty`, with echo disabled.
   Do not send them through chat, a shell argument, an environment variable, a
   password manager's clipboard, a screenshot, or a recording.
7. Follow both physical prompts. For each copy, the tool safely ejects the exact
   physical disk; physically disconnect and reconnect it, unlock the same volume,
   and press Return. Success requires rereading and decrypting the envelope after
   remount. The receipt records domain-separated hashes of distinct physical-store
   and volume identities, the envelope hashes, and both restore-verification times.
8. Store the two recovery disks separately after verification. Do not leave both
   attached to the MacBook or stored together.

Before generating key material, create mode writes a fixed, create-only
provisioning intent. It binds the reviewed source commit and the exact two recovery
directory, physical-store, and volume identities. All envelopes, public evidence,
and the intent are create-only, owner-only, fsynced, and reread after publication.
The public identity and receipt bind the tracked helper source, compiled helper
binary, compiler identity, designated-MacBook platform-identity hash, Ed25519
SPKI/fingerprint/key ID, Keychain protection, intent, source commit, and both
recovery-copy results.

The intent, public identity, receipt, and provisioning report also bind
`helperCompatibilityEvidenceSha256` and
`helperCompatibilityTestedCommitSha`. Resume requires the exact same values.

### Crash or ambiguous write

If any durable path may have been created, the tool preserves it and returns
`RESUME_REQUIRED`; it never deletes or overwrites a possibly durable envelope,
intent, identity, or receipt. Do not remove the fixed intent or any partial output
to make `create` pass. Preserve the exact disks, mount paths, output paths, checkout,
and commit, investigate the stop, then use the same command with `--mode resume`.
Resume must recover the surviving identity and exact target bindings; it must never
silently generate a replacement identity.

## Phase 1a: pin the independent reviewer trust anchor

Before creating the commit that the final reviewer will approve, select a stable
non-authoring reviewer and create a dedicated Ed25519 review-signing key. The
reviewer keeps its private key outside the repository and outside release-signing
custody. Its public identity is canonical JSON at exactly:

```text
config/foundation-independent-reviewer-identity.v1.json
```

The trust file is intentionally absent today. That absence is a hard blocker for
production review-file ingestion and the real ceremony; the code does not contain a
default reviewer key.

The identity has this exact shape. `reviewerFingerprintSha256` is SHA-256 over the
canonical Ed25519 SPKI DER, and `keyId` is
`rsi-reviewer-<first-16-fingerprint-hex>`:

```json
{
  "algorithm": "Ed25519",
  "identityType": "rsi.foundation-independent-reviewer-identity",
  "keyId": "<derived-reviewer-key-id>",
  "publicKeySpkiDerBase64url": "<canonical-unpadded-base64url-SPKI>",
  "reviewerFingerprintSha256": "<64-hex>",
  "reviewerId": "<stable-non-authoring-reviewer-id>",
  "reviewerRole": "independent-non-authoring-agent",
  "version": 1
}
```

Merge that public identity through protected public `main` as its own earlier
trust-establishment change. The later reviewed commit must preserve the exact
`100644` blob unchanged in every parent. A key first added by, or changed in, the
reviewed commit is a self-pin and is refused. The reviewer ID and public key must
not be the release signer or a known release operator identity. The production
reader also refuses replace refs, grafts, and shallow history before and after the
lineage proof.

## Phase 2: pin the nonsecret identity and retain final CI

1. Review the canonical public-identity candidate and provisioning receipt out of
   band. They are nonsecret, but the encrypted recovery envelopes, fixed local
   intent, passphrases, and private Keychain item remain off Git.
2. Pin the reviewed canonical files at these exact tracked paths:

   ```text
   config/foundation-release-identity.v1.json
   config/foundation-release-key-provisioning-receipt.v1.json
   ```

   The receipt identifies the clean public source commit used for provisioning;
   the later pinning commit must preserve that source/helper lineage rather than
   pretending the physical ceremony happened on a future commit. It must also
   preserve the independent-reviewer identity from Phase 1a byte-for-byte; never
   add or rotate that trust anchor in this reviewed commit.

3. Merge the pin through protected public `main` and wait for a fresh successful
   `push` CI run on that exact pinning commit. Both `quality` and
   `gitleaks-history` must succeed. The provisioning/source commit recorded in the
   receipt must be an ancestor of this pinning commit, and its exact helper-source
   blob must match the attested helper hash.
4. While networked and outside the signing ceremony, independently open the public
   run URL and confirm its repository, event, branch, full commit, jobs, and
   conclusions. Retain the closed canonical record in an owner-only directory
   outside the repository:

   ```bash
   pnpm foundation:ci-retain -- \
     --run-id <decimal-run-id> \
     --output /absolute/owner-only/foundation-ci.json \
     --confirm-commit <full-40-character-pinning-commit>
   ```

The retention adapter performs only fixed unauthenticated public GitHub reads. The
retained record is not an independently signed GitHub attestation; the operator's
separate visual review remains required. Copy the retained evidence to the
designated MacBook without altering its bytes, update that MacBook to the exact
pinning commit, and disconnect it again before signing.

## Phase 2a: retain independent review evidence

Before the ceremony, a non-authoring agent must independently review the exact
pinning commit and Git tree. The review must cover these five scopes, in this exact
order, with `outcome: "passed"`:

1. `repository-diff`
2. `release-key-provisioning`
3. `release-ceremony-and-tag`
4. `failure-and-recovery-controls`
5. `tests-and-documentation`

The inner review body permits zero to 64 findings. Every finding must have a unique
identifier, allowed severity, hashes of the finding and its resolution, and
`status: "resolved"`; unresolved findings cannot be omitted and block approval. At
ceremony time it must be no more than seven days old, identify
`tyler-james-bridges/rsi`, release `0.1.0-foundation.1`, use role
`independent-non-authoring-agent`, carry verdict `approved`, and match the exact
commit and tree.

The production external file is not a bare body. It is the canonical signed
envelope below, without a trailing newline, mode `0600`, under an absolute
`.review-evidence.json` path in the owner-only evidence directory. Every placeholder
must be replaced before canonical encoding:

```json
{
  "envelopeType": "rsi.foundation-authenticated-independent-review",
  "evidence": {
    "commitSha": "<40-hex-pinning-commit>",
    "evidenceType": "rsi.foundation-independent-review-evidence",
    "findings": [
      {
        "findingId": "<unique-finding-id>",
        "findingSha256": "<64-hex>",
        "resolutionSha256": "<64-hex>",
        "severity": "<critical|high|medium|low|informational>",
        "status": "resolved"
      }
    ],
    "gitTreeSha": "<40-hex-tree>",
    "releaseVersion": "0.1.0-foundation.1",
    "repository": "tyler-james-bridges/rsi",
    "reviewedAt": "<canonical-UTC-timestamp>",
    "reviewerId": "<stable-non-authoring-reviewer-id>",
    "reviewerRole": "independent-non-authoring-agent",
    "scopes": [
      { "name": "repository-diff", "outcome": "passed" },
      { "name": "release-key-provisioning", "outcome": "passed" },
      { "name": "release-ceremony-and-tag", "outcome": "passed" },
      { "name": "failure-and-recovery-controls", "outcome": "passed" },
      { "name": "tests-and-documentation", "outcome": "passed" }
    ],
    "verdict": "approved",
    "version": 1
  },
  "reviewerFingerprintSha256": "<identity-fingerprint-64-hex>",
  "reviewerId": "<stable-non-authoring-reviewer-id>",
  "reviewerIdentitySha256": "<SHA-256-of-exact-canonical-identity-file>",
  "reviewerKeyId": "<derived-reviewer-key-id>",
  "signatureAlgorithm": "Ed25519",
  "signatureBase64url": "<canonical-unpadded-64-byte-signature>",
  "version": 1
}
```

The signature input is the UTF-8 domain
`rsi.foundation-authenticated-independent-review.v1` followed by a NUL byte and
the complete canonical unsigned envelope (every field above except
`signatureBase64url`). This binds the complete canonical review body plus the exact
reviewer identity hash, reviewer ID, key ID, fingerprint, algorithm, envelope type,
and version. The ceremony verifies the pinned key and lineage, then hashes and
binds the complete signed envelope. An empty `findings` array is valid only when
the reviewer found nothing. Neither an unsigned body nor a same-commit key pin is
evidence of an independent pass.

## Phase 3: two-signature offline ceremony

Prepare a new empty owner-only output directory outside the repository. On the
designated MacBook, at exact clean public `main == origin/main`, with every network
interface down, run:

```bash
pnpm foundation:ceremony -- \
  --ci-evidence /absolute/owner-only/foundation-ci.json \
  --review-evidence /absolute/owner-only/foundation.review-evidence.json \
  --output /absolute/owner-only/foundation.rsi-release \
  --receipt /absolute/owner-only/foundation.receipt.json \
  --conclusion /absolute/owner-only/foundation.readiness-conclusion.json \
  --tag-object /absolute/owner-only/foundation.foundation-tag \
  --report /absolute/owner-only/foundation.ceremony-report.json \
  --confirm-commit <full-40-character-pinning-commit> \
  --confirm-release 0.1.0-foundation.1
```

The command revalidates the pinned public identity and receipt from the exact Git
commit, proves the provisioning commit is an ancestor with the attested helper
source, matches the current tracked/compiled helper hashes and designated-MacBook
platform identity, checks fresh retained CI and independent-review evidence,
rebuilds the closed inventory, and asks for exactly two separate user-presence
signatures in one custody session:

1. sign the domain-separated release manifest, then immediately verify the
   create-only `.rsi-release` bundle and prepare its independent receipt;
2. create and verify the readiness conclusion, then sign the fixed OpenSSH `git`
   namespace data for a detached annotated `foundation-v1` tag object.

The readiness conclusion binds the archive, manifest, artifact/source/config/
runbook/recovery sets, lockfile, SBOM, test summary, commit/tree, retained CI,
independent-review evidence, pinned identity, provisioning receipt, platform
identity, and signer identity. Its fifth required check is
`independent-adversarial-review-passed`. The canonical ceremony report binds those
hashes, the helper/platform evidence, exactly two signatures, and the detached
tag-object identities.

Before custody begins, the command exclusively creates and fsyncs owner-only
reservations for the receipt, readiness conclusion, detached tag, and ceremony
report. The release-bundle component separately creates and fsyncs its internal
owner-only attempt file before the first signing capability is consumed. After both
signatures verify, the custody postcondition passes, and helper cleanup succeeds,
the command publishes the ancillary outputs in this exact order: detached tag,
receipt, ceremony report, then readiness conclusion. The readiness conclusion is
the final completion marker. If it is absent or empty, the retained files are a
partial attempt and must not be treated as a completed ceremony.

Every output is create-only and owner-only. If a failure occurs after one or more
durable outputs exist, preserve all partial artifacts and the error record. The
tool does not clean them up, overwrite them, or imply success. Diagnose the exact
failure and use a new empty output directory only after review; never reuse a
partial output as completed evidence.

The four ancillary destinations are reserved and fsynced before custody, and the
bundle attempt file is reserved and fsynced before its signing capability can be
consumed. A failed pre-link or link publication retains the owner-only signed bundle
partial; a later linked failure retains a unique destination when safe. Every
ancillary reservation is preserved without deletion or truncation after custody
begins, including after an ambiguous post-write failure. Ancillary publication does
not begin until custody has completed and cleaned up, and the conclusion remains
empty unless the detached tag, receipt, and report were durably published first.

## Deliberate publication boundary

The ceremony writes detached `.foundation-tag` bytes only. It does **not** write the
Git object database, create `refs/tags/foundation-v1`, push a tag, create a GitHub
release, upload assets, deploy, call a provider, or spend funds. There is no CLI
option that grants those capabilities.

After the ceremony, an independent verifier must compare the bundle, bundle
receipt, readiness conclusion, detached tag object, ceremony report, retained CI,
bound independent-review evidence, public commit/run, designated platform hash,
and pinned fingerprint. Only a successful verification of that already reviewed
evidence set may support a `FOUNDATION_BUILT` determination. From the exact clean
public `main` checkout, run:

```bash
pnpm foundation:verify -- \
  --bundle /absolute/owner-only/foundation.rsi-release \
  --receipt /absolute/owner-only/foundation.receipt.json \
  --conclusion /absolute/owner-only/foundation.readiness-conclusion.json \
  --tag-object /absolute/owner-only/foundation.foundation-tag \
  --report /absolute/owner-only/foundation.ceremony-report.json \
  --ci-evidence /absolute/owner-only/foundation-ci.json \
  --review-evidence /absolute/owner-only/foundation.review-evidence.json \
  --confirm-commit <full-40-character-pinning-commit> \
  --confirm-release 0.1.0-foundation.1
```

The verifier requires clean `main`, the same `origin/main`, the approved public
remote, exact Node `24.19.0` and pnpm `11.20.0`, and complete Git history without
replace refs, grafts, or shallow state. It reopens all five outputs, verifies both
signatures with the repository-pinned identity, authenticates the strict-ancestor
reviewer trust pin, rechecks identity/helper/provisioning lineage, and reconstructs
the complete release inventory from exact tracked Git blobs using the retained CI
evidence and signed bundle creation time. The reconstructed artifact count, hashes,
commit/tree, release, runtime, and null predecessor must equal the signed bundle
and report. CI and review chronology is revalidated against the signed creation
time, including the seven-day age limits and five-minute review future-skew limit.
A missing or empty conclusion is a partial attempt and refuses.

Verification is read-only: it does not access Keychain, sign, restore, write an
object or ref, publish, upload, or change any evidence file. Installing the
detached tag object, creating the ref, pushing it, or publishing a GitHub release
is a separate, explicit owner-approved action and is outside this workflow. The
command and fixture coverage do not mean a real verification has occurred. No real
ceremony evidence exists, the independent-reviewer trust file and passing
compatibility record are absent, the stable signed component is unimplemented, and
the v1 compatibility format is inspection-only. RSI therefore remains below
`FOUNDATION_BUILT`.

## Current physical next steps

The present build must stop before secrets because these steps require the owner
and physical hardware:

1. complete and retain the throwaway-MacBook stable-helper/user-presence drill;
   this first requires the signed-component architecture described above and an
   owner-controlled Apple signing identity/provisioning profile;
2. choose the designated MacBook and two distinct encrypted APFS recovery disks;
3. create the owner-only fixed-intent and evidence directories;
4. have the independent non-authoring reviewer create the dedicated Ed25519 review
   key, retain its private material outside both the repository and release-signing
   custody, and merge only its canonical public identity through `main` in an
   earlier strict-ancestor commit; preserve that exact trust blob unchanged in the
   later reviewed commit;
5. disconnect networking and run real provisioning, including both physical
   eject/disconnect/reconnect/unlock/restore checks;
6. review and pin the nonsecret release identity plus receipt through public
   `main` without changing the reviewer trust blob;
7. retain and visually verify fresh CI for that exact pinning commit;
8. complete and retain the authenticated five-scope non-authoring review envelope
   for the exact commit and tree, with every finding resolved;
9. return the designated MacBook offline and perform the two-prompt ceremony; and
10. independently verify every retained artifact before deciding whether the label
    or any separately approved publication can proceed.

Until every step succeeds, RSI remains below `FOUNDATION_BUILT` and no provider or
production provisioning is authorized.
