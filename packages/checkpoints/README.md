# `@rsi/checkpoints`

Offchain Ed25519 checkpoints for `@rsi/store`. The package signs the exact
event-store head `(sequence, eventHash)` and appends it to a canonical,
hash-linked JSONL journal kept outside SQLite. It does not contain blockchain,
network, wallet, transaction, or key-generation APIs.

Checkpointing turns the store's internal SHA-256 chain into an externally held
trust anchor. A successful verification distinguishes the signed prefix from
new events in the unanchored tail.

## Signing

Production code must inject an existing Ed25519 private `KeyObject` or private
key material. `CheckpointSigner` never generates or persists it.

```ts
import { CheckpointSigner } from "@rsi/checkpoints";
import { SqliteEventStore } from "@rsi/store";

const store = new SqliteEventStore("./var/events.sqlite");
const signer = new CheckpointSigner({
  journalPath: "./anchors/events.checkpoints.jsonl",
  storeId: "production-events",
  keyId: "checkpoint-key-2026-01",
  privateKey: privateKeyFromYourKeyProvider,
  expectedJournalHead: previouslyRetainedHead,
});

const checkpoint = signer.append(store);
retainOutsideSqlite(signer.journalHead);
```

`expectedJournalHead` is required. Use `null` only to bootstrap an empty
journal. Each successful append advances the signer's in-memory `journalHead`.
Persist that public hash/sequence through an independent trusted channel before
restarting the signer. A stale, duplicate, truncated, replaced, or forked
journal does not match and is refused.

The store must contain at least one event. Sequence-zero checkpoints are
refused because the universal empty-store hash cannot identify a particular
event-store lineage. Legacy journals containing a signed sequence-zero anchor
are invalid and cannot be replayed against, or continued from, another store.

Append takes the journal's exclusive fail-closed lock, verifies every existing
entry and signature, takes `SqliteEventStore.withExclusiveTransaction()`,
verifies the store, confirms its prior anchored head, signs only an advancing
head, appends with `O_APPEND | O_NOFOLLOW`, and fsyncs the file. New files and
lock changes also fsync their parent directory. A crash-torn last line is
rejected on the next read; it is never silently repaired or discarded. A lock
file left by a killed process must be removed by an operator only after proving
that no writer remains.

The signer refuses an append before writing when the journal would exceed 64
MiB or 100,000 entries. Rotate to a new independently retained journal while
preserving the last trusted head before either limit; a full journal is never
made invalid by a write-then-fail capacity check.

At construction, the journal's real parent directory is required to be owned
by the caller and not group/world writable. Its device and inode are pinned.
Every journal and lock operation rechecks the non-symlink parent identity
around opens and before writes, so renaming the directory and replacing its old
path with a symlink cannot redirect an existing signer or verifier.

## Verification

```ts
import { CheckpointVerifier } from "@rsi/checkpoints";

const verifier = new CheckpointVerifier({
  journalPath: "./anchors/events.checkpoints.jsonl",
  expectedStoreId: "production-events",
  expectedKeyId: "checkpoint-key-2026-01",
  expectedPublicKey: pinnedEd25519PublicKey,
  trustedJournalHead: newestHeadRetainedOutsideTheJournal,
});

const report = verifier.verify(store);
if (!report.valid) throw new Error("Store is not verified against its checkpoint journal");

console.log(report.anchoredThroughSequence);
console.log(report.unanchoredEventCount);
```

The verifier is pinned to all three of the expected store ID, key ID, and
Ed25519 public key. It verifies canonical encoding, strict schemas, journal
sequence, predecessor hashes, monotonic store sequences and timestamps, entry
hashes, and every signature. While holding a store transaction, it then checks
that the current valid store contains every signed event hash at the exact
recorded sequence. `status` is one of `ANCHORED`, `UNANCHORED`, or `INVALID`.

`trustedJournalHead` is optional but strongly recommended. A signature chain
detects modification, insertion, deletion from the middle, and reordering by
itself. No file can prove that its own valid suffix was removed. Retaining the
newest `{ journalSequence, checkpointHash }` elsewhere and supplying it here
makes that rollback detectable. `truncationProtectedThrough` reports the
externally trusted position actually matched.

`verifyJournal()` performs journal-only verification. `verify(store)` adds
store integrity and exact-anchor checks. Reports are immutable and keep journal
issues separate from store issues.

## Payload and encoding

Version 1 signs this canonical payload:

```ts
interface CheckpointPayloadV1 {
  checkpointType: "rsi.store.head";
  createdAt: string; // canonical UTC ISO milliseconds
  journalSequence: number;
  keyId: string;
  previousCheckpointHash: string;
  storeHeadHash: string;
  storeHeadSequence: number; // safe integer >= 1
  storeId: string;
  version: 1;
}
```

`encodeCheckpointPayload(payload)` returns the domain-separated bytes signed by
Ed25519. `computeCheckpointHash(payload, signature)` returns the domain-separated
SHA-256 link hash. Signatures use unpadded base64url; hashes are lowercase hex.

## Main exports

- `CheckpointSigner`, `CheckpointVerifier`
- `encodeCheckpointPayload`, `computeCheckpointHash`
- `CheckpointPayloadV1`, `SignedCheckpoint`, `CheckpointJournalHead`
- `CheckpointJournalVerificationReport`, `CheckpointVerificationReport`
- `CheckpointJournalIntegrityError`, `CheckpointStoreIntegrityError`
- `CheckpointConcurrencyError`, `InvalidCheckpointError`
- `CHECKPOINT_PAYLOAD_VERSION`, `CHECKPOINT_TYPE`,
  `CHECKPOINT_JOURNAL_GENESIS_HASH`

Journal paths resolve through their pinned real parent directory.
Final-component symlinks, non-regular files, multi-linked files, use of the
SQLite file itself, group/world-writable journals, and unsafe replacements
observed while reading are rejected. New journals are created mode `0600`.
