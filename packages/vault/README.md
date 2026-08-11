# `@rsi/vault`

`@rsi/vault` is an isolated, encrypted, content-addressed store for immutable snapshots of hostile raw source bytes. It intentionally has no raw-content listing or deletion API.

## Security properties

- Snapshot addresses are lowercase SHA-256 digests of the plaintext.
- Snapshot bytes are encrypted with AES-256-GCM and a fresh 96-bit random nonce for each newly published object.
- Canonical JSON metadata and source bytes are encrypted and authenticated together. The format header, lengths, nonce, and expected content address are authenticated as additional data.
- The caller supplies exactly 32 key bytes. The vault defensively copies the key, never writes or logs it, wipes working copies, and wipes its retained copy on `close()`.
- Object creation uses a mode-`0600` temporary file, file `fsync`, and an atomic hard-link publication that cannot replace an existing address. The directory is mode `0700` and is `fsync`ed after publication.
- Addresses have one exact filename form (`<64 lowercase hex>.vault`). Reads reject symlinks, multi-linked or non-regular files, permissive files, directory substitution, malformed envelopes, authentication failures, and address/hash mismatches.
- Input and output bytes and metadata are defensively copied. Stored objects are never overwritten.

Both snapshot bytes and metadata are encrypted. Content addressing still reveals when two snapshots have the same plaintext. Filesystem checks defend against accidental and common path/symlink substitution; as with any local store, do not share the vault directory or its writable ancestors with an adversary running as the same OS user.

Atomic publication briefly gives the completed object and its temporary name two
links. Readers retry that exact transient state for a small bounded window;
after the window, or for any higher link count, they fail closed as an unsafe
persistent hard link.

## API

```ts
import { randomBytes } from "node:crypto";
import { SnapshotVault } from "@rsi/vault";

const key = randomBytes(32); // provision this outside the vault
const vault = await SnapshotVault.open({
  directory: "/private/service/snapshots",
  key,
  maxSnapshotBytes: 16 * 1024 * 1024,
  maxMetadataBytes: 16 * 1024,
});

const put = await vault.put(Buffer.from(hostileResponse), {
  metadata: { contentType: "application/json", source: "example" },
});
// put: { address, created, metadata, size }

const snapshot = await vault.get(put.address);
// snapshot.bytes is a fresh Uint8Array; get authenticates, decrypts, and re-hashes.

const verification = await vault.verify(put.address);
// verification: { address, metadata, size, valid: true }

await vault.close();
```

`put()` accepts zero-byte responses so malformed empty captures can still be preserved, and rejects oversized content. An exact content-and-metadata retry returns the original address with `created: false`. The same content with different metadata raises `SnapshotConflictError`; it never changes the first object. `get()` and `verify()` accept only an exact 64-character lowercase hexadecimal address and use the same full authentication, decryption, and SHA-256 verification path.

Defaults and hard ceilings are exported as `DEFAULT_MAX_SNAPSHOT_BYTES`, `HARD_MAX_SNAPSHOT_BYTES`, `DEFAULT_MAX_METADATA_BYTES`, and `HARD_MAX_METADATA_BYTES`. Typed error classes and all result/input types are exported from the package root.
