# External checkpoint anchor protocol

`@rsi/external-anchor` is the offline protocol and state machine for publishing
signed local checkpoint heads to an independent create-only object plane and for
verifying that plane with a separate read-only capability. The package contains
no Backblaze SDK, HTTP client, environment-variable loader, Keychain integration,
credential, account setup, or network call.

## Object contract

Each object body is canonical JSON with a closed versioned schema:

```json
{
  "anchorType": "rsi.external-checkpoint",
  "authorization": {
    "payload": {
      "authorizationType": "rsi.external-anchor-authorization",
      "checkpointHash": "<sha256>",
      "keyId": "<checkpoint-key-id>",
      "profile": "canary | production-observer",
      "retention": { "days": "30 | 365", "mode": "governance | compliance" },
      "storeId": "<event-store-id>",
      "version": 1
    },
    "signature": "<Ed25519 base64url>"
  },
  "checkpoint": "<closed @rsi/checkpoints SignedCheckpoint object>",
  "version": 1
}
```

The real `checkpoint` value is an object, not the placeholder string shown above.
The parser verifies its Ed25519 signature, checkpoint hash, key ID, store ID, and
non-empty store head. It separately verifies the domain-separated authorization
signature and requires it to bind that exact checkpoint hash, key/store identity,
profile, and retention policy. A provider writer cannot rewrap a valid checkpoint
under a weaker policy without the checkpoint signing key. The authorization must
be created in the signing boundary before it is handed to the outbox; provider
credentials never enter that boundary. Bodies are limited to 4 KiB and reject
non-canonical JSON, unknown or missing fields, accessors, proxies, symbols, sparse
arrays, and unsafe numeric or identifier values where applicable.

Object keys are deterministic and unique per signed checkpoint:

```text
anchors/v1/{profile}/{16-digit-journal-sequence}/{checkpoint-hash}.json
```

The envelope and all receipts are content-free: they contain checkpoint hashes,
sequences, timestamps, profile, retention, and protocol identifiers only. Raw
source content, source IDs, handles, queries, URLs, credentials, and arbitrary
metadata have no schema slot.

## Capability boundary

The publisher transport exposes exactly one operation, `create(request)`. The
verifier transport exposes exactly `list({prefix})` and `read({objectKey})`.
Transport normalizers reject extra methods and proxied functions. The included
in-memory fake returns separate frozen capability objects and implements:

- first exact create: `created`;
- exact retry of the same key/body/retention: `already_exists`;
- reuse of a key with any changed request field: `OBJECT_CONFLICT`;
- no writer read, list, delete, overwrite, or administration method;
- no verifier create, overwrite, delete, or administration method.

A future provider adapter must preserve this boundary using separately scoped
credentials. It must map only an atomic create-if-absent operation into `create`
and must return independently obtained Object Lock metadata. This package does
not claim that an actual provider account or permission policy has been tested.

## Durable publisher outbox

`SqliteExternalAnchorOutbox` authenticates every row plus the complete row-set
projection under a caller-injected 32-byte state key. It binds the profile,
checkpoint identity, and public-key fingerprint, rejects wrong keys and tampered
or deleted state, and authenticates the exact SQLite schema so an injected trigger,
view, index, or schema rewrite cannot become newly trusted during a mutation. It
uses `WAL` plus `synchronous=FULL` and caps storage at 10,000 rows. No state key is
stored in SQLite.

Enqueue is exact and fork-safe: the same checkpoint, time, and retention returns
the existing receipt, while a changed retention/body or a second checkpoint at
the same journal sequence is a conflict. A claim durably consumes its attempt
before transport dispatch. There are at most two attempts.

If the process crashes after remote creation but before local completion:

1. reopen the outbox with the same identity and state key;
2. call `recover({recoveredAt})`;
3. claim again and send the byte-identical request;
4. accept the provider's exact `already_exists` result;
5. durably complete with a content-free publication receipt.

Only typed `ExternalAnchorTransportError` failures are retryable. Invalid results,
conflicts, integrity failures, schema failures, and all unknown errors fail closed.
A valid older copy of the entire SQLite database cannot be distinguished from the
current copy by a key stored outside that database; the independently pinned
accepted head is the rollback boundary for the external plane.

## Independent verification

`ExternalAnchorVerifier` validates a bounded listing and every listed object,
including summary/read equality, body hash and size, canonical envelope,
both signatures, object key, profile, Object Lock mode/duration/expiry, provider time,
checkpoint lineage, monotonically increasing store heads, and the
Governance-to-Compliance transition.

The caller supplies the prior accepted `ExternalAnchorHead` from storage that the
publisher cannot rewrite. Verification accepts either a complete history, a
listing beginning at that exact pinned object, or a suffix beginning exactly one
checkpoint after it. It detects gaps, forks, predecessor changes, rollback,
missing or mismatched pins, retention downgrade/shortening/expiry, timestamp
regression, malformed metadata, and tail branches that do not descend from the
pin. The caller also supplies an independently configured minimum head-retention
mode: Governance accepts either mode, while Compliance requires the verified tail
to end in Compliance. This prevents a suppressed first Compliance object from
passing post-promotion verification. The returned report and pin contain no object
body.

The verifier proves the objects presented through its transport. Session
orchestration must still compare the returned head with the local checkpoint that
the session expected to publish before committing a cursor or accepting a
session.

## Local verification

```sh
pnpm --filter @rsi/external-anchor typecheck
pnpm --filter @rsi/external-anchor test
pnpm --filter @rsi/external-anchor format:check
```

All tests use generated Ed25519 keys, temporary local SQLite files, injected
clocks, and in-memory transports. They make no provider, credential, or network
call.
