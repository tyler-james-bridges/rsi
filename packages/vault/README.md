# `@rsi/vault`

`@rsi/vault` v2 is a bounded, single-writer encrypted store for short-lived hostile source captures. It deliberately does not expose content addresses, hashes, deduplication, listing, networking, or secrets.

## Security model

- Every `capture()` allocates a fresh, opaque 128-bit random `CaptureId`. The ID is never derived from the body, so equal plaintext creates unrelated IDs and ciphertext.
- Every capture uses a fresh random 256-bit data-encryption key (DEK). AES-256-GCM encrypts and authenticates the raw body and the complete closed `CaptureMetadataV1` schema together.
- A caller-supplied 256-bit wrapping key feeds purpose-separated HKDF-SHA-256 subkeys. The DEK-wrapping subkey encrypts each DEK in a separate `.dek` artifact with a fresh nonce; separate subkeys protect creation, deletion-intent, and tombstone records. Deletion removes and `fsync`s the wrapped DEK before publishing an authenticated, content-free tombstone. A remaining `.body` file is then unrecoverable without another copy of the DEK.
- Creation uses an authenticated `.creating` marker and publishes the encrypted body before the wrapped-DEK commit artifact. Recovery removes incomplete creations, uncommitted body-only orphans, and bounded temporary files.
- Deletion uses an authenticated `.deleting` intent. Recovery can resume a crash between intent publication, DEK destruction, tombstone publication, and ciphertext cleanup. Repeating `delete()` returns the original logical receipt exactly.
- All envelopes bind their format, capture ID, lengths, and purpose-specific domain into GCM additional authenticated data. Bodies, wrapped DEKs, creation markers, deletion intents, and tombstones cannot be swapped between IDs or roles.
- The vault copies the caller's wrapping key, input bytes, and metadata. It wipes retained and working key/DEK/plaintext buffers on the implemented success and error paths and wipes the retained wrapping key when `close()` starts.
- The root is mode `0700`; artifacts and temporary files are mode `0600`. Operations verify owner, mode, regular-file type, inode/device identity, link count, exact namespace, root-directory identity, complete reads, and fixed bounds. They reject symlinks, persistent hard links, permissive files, unknown entries, malformed envelopes, and root namespace replacement.
- Operations are serialized. `close()` refuses new work, waits for every operation that already started, closes the pinned directory handle, and is idempotent. A second vault for the same canonical directory is rejected within the same process.

Raw captures may be zero bytes. `acquiredAt`, `expiresAt`, deletion time, sweep time, and recovery time must use exact `YYYY-MM-DDTHH:mm:ss.sssZ` UTC form. `expiresAt` may equal but cannot precede `acquiredAt`.

## API

```ts
import { randomBytes } from "node:crypto";
import { SnapshotVault } from "@rsi/vault";

const vault = await SnapshotVault.open({
  directory: "/private/service/captures",
  wrappingKey: randomBytes(32), // provision outside the vault
  maxCaptureBytes: 16 * 1024 * 1024,
});

const captured = await vault.capture(Buffer.from(hostileResponse), {
  metadata: {
    schemaVersion: 1,
    source: "x",
    acquiredAt: "2026-08-14T08:00:00.000Z",
    expiresAt: "2026-08-14T10:00:00.000Z",
    mediaType: "application/json; charset=utf-8",
  },
});
// { captureId, metadata, size } -- no address, hash, or deduplication signal

const capture = await vault.get(captured.captureId);
const verification = await vault.verify(captured.captureId);

const receipt = await vault.delete(captured.captureId, {
  deletedAt: "2026-08-14T10:00:00.000Z",
  reason: "explicit",
});
// { schemaVersion: 1, captureId, deletedAt, keyDestroyed: true,
//   reason: "explicit", state: "deleted" }

await vault.sweepExpired({
  now: "2026-08-14T10:00:00.000Z",
  limit: 100,
});

await vault.recover({ recoveredAt: "2026-08-14T10:00:00.000Z" });

// After the encrypted registry has recovered, prove every registered capture
// exists and crypto-shred any complete capture absent from that registry.
await vault.reconcileRegisteredCaptures({
  registeredCaptureIds: registry.listCommittedCaptureIds(),
  reconciledAt: "2026-08-14T10:00:00.000Z",
  limit: 100,
});
await vault.close();
```

Exports include `CaptureId`, `isCaptureId`, the closed metadata/result/receipt types, typed errors, and these hard bounds:

- `DEFAULT_MAX_CAPTURE_BYTES` / `HARD_MAX_CAPTURE_BYTES`
- `DEFAULT_MAX_METADATA_BYTES` / `HARD_MAX_METADATA_BYTES`
- `DEFAULT_EXPIRY_SWEEP_LIMIT` / `HARD_MAX_EXPIRY_SWEEP_LIMIT`

## Required operating constraints

Call `recover()` at controlled startup, recover and authenticate the encrypted capture registry, then call `reconcileRegisteredCaptures()` until its result is not truncated. Reconciliation validates every registry-committed capture before changing anything and crypto-shreds complete vault captures that have no committed registry entry. Call `sweepExpired()` at session close. Treat any recovery, reconciliation, or sweep failure as a fail-closed retention incident. Store no raw vault artifacts or wrapped DEKs in backups. The wrapping key must live outside this package (for RSI, in the environment-specific macOS Keychain) and must not be backed up alongside capture files.

The package rejects a second writer in one Node process, but Node does not provide a portable held `flock`; the service-level exclusive profile lock remains responsible for excluding a second OS process. Filesystem checks defend against accidental and common namespace substitution. A malicious process running as the same OS user can read process memory, race path operations, or copy a wrapped DEK before deletion and is outside this local-store boundary. JavaScript and OpenSSL may retain unmanaged copies despite best-effort buffer wiping; process termination remains part of session-close handling. Crypto-shredding assumes no copy, snapshot, backup, or forensic recovery of the unlinked `.dek` artifact; APFS/SSD physical erasure is not guaranteed by `unlink`, so the approved no-backup policy, FileVault, session purge, and wrapping-key lifecycle remain required layers.
