# Foundation release-key provisioning

`@rsi/release-key-provisioning` is the fail-closed offline bootstrap for the one
fixed RSI Foundation Stage A release identity. It is deliberately separate from
release signing and is the sole narrow exception to Stage A's zero-credential
rule: a governance-only key is needed to sign Stage A's own evidence. It has no
provider, runtime, network, wallet, payment, trading, deployment, checkpoint,
operator-approval, or public-artifact authority.

The command runs only on a MacBook with no IPv4/IPv6 default route and no active or
addressed non-loopback interface, from clean public `main == origin/main`, under
exact Node `24.19.0` and pnpm `11.20.0`. It accepts no key, seed, passphrase,
Keychain selector, helper, algorithm, KDF, overwrite, deletion, tag, push, or
publication argument.

No real provisioning is permitted until the stable signed component described
below replaces the v1 helper design. No key has been provisioned by the project
today.

The v1 compatibility-evidence format is recognized only for inspection at
`config/foundation-release-key-helper-compatibility.v1.json`; this repository
intentionally has no passing record today. An absent or invalid blob refuses
immediately. Even if a canonical v1 blob is present and its Git lineage and runtime
bindings validate, v1 evidence is architecturally insufficient and the official
path hard-refuses before recovery-target inspection, fixed-intent reads, Keychain
presence, passphrases, key generation, or durable writes. The public native adapter
independently refuses every add, verify-with-key, and signing operation, so
importing its subpath cannot bypass this stopgap.

## Custody boundary

- Keychain service: `dev.rsi.macbook.release-signing`
- Keychain account: `release-ed25519-v1`
- Keychain protection: Data Protection Keychain,
  `WhenUnlockedThisDeviceOnly`, synchronization disabled, user presence required
- historical helper evidence: hashes of the tracked `HEAD` Swift source,
  deterministically compiled/ad-hoc-signed binary, and compiler identity; this
  is inspection-only and has no secret authority
- host binding: a domain-separated SHA-256 of the designated MacBook's platform
  UUID; the raw UUID is never retained
- recovery: two independently salted scrypt + AES-256-GCM envelopes
- media: two writable encrypted external APFS volumes backed by distinct physical
  whole disks, durably bound by each APFS physical-store partition UUID; the
  inspector resolves the store partition to its parent whole disk and rejects
  internal, virtual, disk-image/file-backed, non-external, or read-only media
- passphrases: two distinct values entered and independently re-entered only
  through `/dev/tty` with echo disabled
- outputs: fixed create-only envelope names, a fixed local provisioning intent, a
  nonsecret public-identity candidate, and a nonsecret provisioning receipt

The v1 native helper has no private-key authority. Its adapter refuses before any
secret-bearing helper invocation. A future authorized component must accept key
material only through an anonymous pipe, never through an argument, environment
variable, stdout/stderr value, plaintext file, JSON field, receipt, or chat value,
and must never return private material.

## Mandatory throwaway-MacBook drill

Before touching the designated MacBook or real recovery media, use a disposable
MacBook to prove the tracked helper's behavior on the exact supported macOS/Swift
toolchain. The reviewed drill evidence must bind the source commit, Node/pnpm,
macOS/Swift compiler identity, helper source/binary hashes, exact Data Protection
Keychain attributes, disabled synchronization, and two separate user-presence
prompts for release-then-tag signing. It must show no `Always Allow` persistence
and no private material in process arguments, environment, output, or temporary
files.

A unit test, Swift typecheck, or one successful prompt is not enough. Any unstable
helper identity, unexpected ACL, missing/reused prompt, or cleanup ambiguity blocks
real provisioning. The drill uses a disposable identity and no real recovery
passphrase.

The current deterministic v1 helper is ad-hoc signed and has no provisioned, fixed
Keychain access-group entitlement. `userPresence` alone does not prove an
exclusive caller identity, and the one-shot signature sequence currently lives in
the Node host. It cannot truthfully satisfy the required alternate-client-refusal
check. Its compatibility parser remains available only to inspect historical
evidence; provisioning, custody, and raw native secret methods all refuse it. Do
not fabricate a passing record. First implement and review the stable signed
app-like component described in
[`helper-compatibility-gate.md`](../../docs/production-readiness/v1/helper-compatibility-gate.md).

## Fixed intent, recovery, and crash behavior

Before it generates key material, create mode writes a create-only canonical
intent at:

```text
~/Library/Application Support/RSI/foundation.release-key-provisioning-intent.json
```

The owner must pre-create that parent as a non-synced, owner-only directory. The
intent binds the exact clean public source commit, designated-MacBook platform
identity, and both recovery directory, stable APFS physical-store partition UUID,
and encrypted-volume identities. The BSD whole-disk name (`diskN`) is transient,
is used only to eject the currently inspected device, is never persisted or
hash-bound, and may change after reconnect. This prevents a changed path,
remounted replacement, different MacBook, or later commit from silently creating
a second identity without mistaking a harmless BSD renumbering for new media.

The intent also binds the canonical helper-compatibility evidence hash and tested
helper commit. The public identity, receipt, and report repeat those bindings; a
changed record, helper, runtime, or Git lineage cannot resume or proceed to
ceremony.

Each intent, envelope, public identity, and receipt is first written to a fixed
same-directory owner-only temporary path, fsynced, and made directory-durable.
Only then is its final name published create-only with a hard link and another
proven directory fsync. Unsupported directory sync is failure, never success.
Every ambiguous failure retains the temporary name (and any final link) for
explicit remediation; no signed or encrypted bytes are deleted by an error path.

Each envelope is reread and decrypted. The tool then
safely ejects the exact physical disk and requires the operator to physically
disconnect, reconnect, unlock, and remount it. Only a second read/decrypt from the
same physical-store and volume identity counts as `restore-verified`. Both distinct
copies must pass before the receipt can complete.

If a crash or I/O ambiguity leaves any path possibly durable, the tool preserves
it and returns `RESUME_REQUIRED`. It never cleans up, overwrites, or silently
generates a replacement. Preserve the exact checkout, intent, disks, mount paths,
envelopes, public identity, and receipt; investigate; then rerun the same command
with `--mode resume`. A receipt without its bound public identity, a Keychain
identity without recovery media, changed targets, or mismatched recovered
identities stops for explicit remediation.

## Operator command

Formatting or encrypting media is destructive and is not automated. Prepare two
physically separate encrypted APFS devices and owner-only recovery directories
first. A mounted disk image, VM/virtual disk, internal partition, or volume whose
backing whole disk is not affirmatively external and writable is ineligible even
if its volume metadata resembles encrypted APFS. Create a separate owner-only
evidence directory outside the repository.
Disconnect the MacBook from every network and stop recording or streaming before
entering passphrases.

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

Follow both eject/disconnect/reconnect/unlock prompts. Store the verified disks in
separate physical locations afterward.

The public identity remains a candidate until its SPKI, fingerprint, key ID,
helper source/binary/compiler hashes, protection policy, fixed-intent binding, and
designated-MacBook platform hash, plus two recovery-copy records are reviewed. Only
those two canonical nonsecret files are pinned through public `main` at:

```text
config/foundation-release-identity.v1.json
config/foundation-release-key-provisioning-receipt.v1.json
```

The encrypted envelopes, local intent, passphrases, and private Keychain item never
enter Git. A fresh final `main` CI run is required after the public pin. The signing
ceremony requires the recorded provisioning commit to be an ancestor of that
pinning commit, rehashes the compatibility record and helper source at the tested,
provisioning, and pinning commits, and trusts only the repository pin, exact runtime
and helper evidence, and same designated-MacBook platform hash—never a
caller-supplied fingerprint.

See [Foundation Stage A v2](../../docs/production-readiness/v1/foundation-stage-a-v2.md)
for the full order, retained CI step, two-signature ceremony, publication boundary,
and current physical blockers.
