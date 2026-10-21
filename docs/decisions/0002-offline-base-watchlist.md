# ADR 0002: Keep the offline Base watchlist separate

- Status: accepted
- Date: 2026-10-20

## Context

RSI needs a useful collection-level research view before it has token prices, orders, or return
data. The existing OpenSea canary cannot provide that view. It destroys collection identities
before it records a content-free completion receipt. The proposal ledger also cannot store the
view honestly because `ResearchProposalV1` requires a token-specific asset.

The first watchlist therefore accepts only an operator-supplied offline projection with the shape
of the existing OpenSea trending parser output. The input remains untrusted. It is not proof that
OpenSea supplied the data, and it cannot become policy or transaction evidence.

## Usage

The operator enters `RESEARCH`, chooses a local JSON file, and previews the normalized snapshot.
The preview shows the snapshot digest, the current history head, and the changes that the import
would record. The operator then confirms that exact preview. The server parses the file again and
requires the same snapshot digest, runtime process, runtime revision, and predecessor head.

The dashboard shows collection contract groups, source ranks, freshness, and these change kinds:

- `new` means that the observed contract group first appears in the current snapshot.
- `rank_changed` means that the same observed contract group has another rank.
- `unchanged` means that the same observed contract group has the same rank.
- `left_window` means that the group left the observed result window. It does not mean that a
  collection was deleted, delisted, or sold.

Every panel labels the data as operator-supplied and unverified. The watchlist has no fetch,
credential, payment, policy, signer, transaction, or execution path.

## Input shape

The import boundary accepts this closed shape:

```ts
interface OfflineBaseWatchlistSnapshotV1 {
  readonly schemaVersion: 1;
  readonly kind: "offline_opensea_trending";
  readonly sourceContractVersion: typeof OPENSEA_TRENDING_CONTRACT_VERSION;
  readonly acquiredAt: string;
  readonly validUntil: string;
  readonly hasNextPage: boolean;
  readonly collections: readonly Readonly<{
    readonly rank: number;
    readonly slug: string;
    readonly baseAddresses: readonly string[];
  }>[];
}
```

The parser rejects unknown fields, raw OpenSea responses, text metadata, URLs, token IDs, prices,
orders, credentials, sparse arrays, accessors, non-plain objects, rank gaps, duplicate slugs,
duplicate contract groups, and contract addresses shared by two groups. It accepts at most ten
collections and sixteen Base addresses per collection. It requires canonical timestamps and
`validUntil` exactly 120 seconds after `acquiredAt`.

The parser normalizes every address to lowercase and sorts each contract set. A collection ID is a
domain-separated SHA-256 digest of the sorted Base contract set. The ID represents only the
observed contract grouping. It does not prove a durable marketplace collection identity. A changed
contract set becomes a new group because this input cannot prove continuity.

The snapshot ID is a domain-separated SHA-256 digest of the complete normalized input. JSON key
order, whitespace, address case, and address order do not change the digest. A change to a rank,
slug, timestamp, pagination flag, or contract set does change it.

## History shape

`@rsi/watchlist` owns one private SQLite event store and one linear aggregate. Each accepted import
appends one `watchlist.snapshot.recorded.v1` event with these facts:

```ts
interface WatchlistSnapshotRecordedV1 {
  readonly snapshotId: SnapshotId;
  readonly predecessorId: SnapshotId | null;
  readonly snapshot: NormalizedOfflineBaseWatchlistSnapshotV1;
  readonly importedAt: string;
  readonly authorization: Readonly<{
    readonly boundary: "watchlist_import";
    readonly authorizationId: string;
    readonly processInstanceId: string;
    readonly mode: "RESEARCH";
    readonly modeRevision: number;
    readonly checkedAt: string;
    readonly eventHash: string;
  }>;
}
```

The package hides event rows, wire input, and storage types. Callers use a small API:

```ts
interface OfflineBaseWatchlist {
  preview(input: unknown, context: PreviewContext): WatchlistImportPreview;
  import(input: WatchlistImportCommand): WatchlistImportResult;
  read(evaluatedAt: string): WatchlistView;
  close(): void;
}
```

The package derives the view from verified events. It does not store a second mutable projection.
The view compares the head only with its bound predecessor. Current rows sort by rank and ID.
`left_window` rows sort by the previous rank and ID. Freshness changes at
`evaluatedAt >= validUntil`, but stored facts and change kinds never change.

The history accepts at most 1,000 snapshots. A full history rejects new snapshots and still accepts
exact duplicate retries. The dashboard shows at most twenty history headers. This version has no
reset, deletion, export, or compaction action.

## Import authority

The runtime adds one boundary named `watchlist_import`. Only `RESEARCH` permits that boundary.
`STOPPED` permits no boundary work, and `PROPOSE_ONLY` does not permit watchlist imports. Existing
boundaries and every permanent financial denial remain unchanged.

The preview records no state. Its result binds the snapshot ID to the displayed runtime process,
runtime revision, and watchlist head. Confirmation sends those expected values with the same
offline input. The host parses and normalizes the input again before it asks the runtime for a
one-shot permit whose action ID is the snapshot ID.

The permit exposes one synchronous protected-commit operation. The runtime first records the
allowed attempt. It then rechecks the process, revision, `RESEARCH` mode, and expiry while it holds
the runtime write lock. The watchlist transaction runs inside that protected callback. STOP either
commits before the callback and prevents the import, or commits after the watchlist transaction.

The runtime and watchlist databases do not share a transaction. A crash can leave an authorized
attempt with no snapshot. It cannot leave a snapshot without a committed authorization receipt.
An identical retry converges on the existing snapshot.

## Duplicate and crash rules

The watchlist transaction applies these rules in order:

1. If the snapshot ID already exists with the same normalized content and predecessor, return the
   stored result without appending an event.
2. If the same ID has other content or another predecessor, fail closed.
3. Require the expected predecessor to equal the current head, or `null` for the first snapshot.
4. Require `acquiredAt` to be later than the current head's acquisition time.
5. Append one complete event and return only after the transaction commits.

A crash before the append commits leaves no snapshot. A crash after commit leaves one snapshot,
even when the HTTP response is lost. Reopen verifies the hash chain, event type, snapshot digest,
predecessor chain, increasing acquisition times, rank rules, and authorization facts before it
returns a view. The hash chain does not detect replacement with a complete older database. That
requires an independently retained head and remains outside this slice.

## Module ownership

- `packages/watchlist` owns parsing, normalization, identity, event replay, import conflicts, and
  deterministic views.
- `packages/runtime` owns the one-shot `watchlist_import` permission and STOP serialization.
- `apps/cli` owns database-path isolation, runtime composition, the trusted clock, and shutdown.
- `apps/operator` owns loopback HTTP admission, the preview and confirmation commands, strict
  response parsing, and inert rendering.
- `scripts/ci/verify-stage0-authority-boundary.mjs` proves that the active graph cannot reach a
  collector, credential host, policy approval, payment, wallet, signer, or execution adapter.

The watchlist database stays separate from the runtime and proposal databases. The host rejects
path, symlink, and hard-link aliases across those files and Stage 1 storage.

## Alternatives considered

### Reuse the proposal ledger

This shape would invent token and proposal fields for collection-only data. It would also turn
`proposal_persist` into a generic write permission. The ledger would hide little because every
caller would need to know which false fields make a watchlist record acceptable.

### Import while `STOPPED`

This shape would make STOP enable a durable research write. It contradicts the runtime contract
that STOP permits no boundary action. A separate app-local permit would also duplicate the
runtime's process, revision, expiry, and STOP serialization rules.

### Use the canary receipt

The receipt contains counts and timing but no collection identities. Reusing it cannot produce a
watchlist. Expanding it would weaken the canary's deletion and public-projection contract.

### Store mutable current rows

A current table plus a history table creates two sources of truth and a recovery protocol. One
event per snapshot keeps the first version bounded and derives every view from one history.

## Consequences

- RSI gains a repeatable offline collection-research workflow without live provider authority.
- The watchlist remains separate from token proposals and policy evidence.
- The runtime adds one narrow, tested local-write permission.
- The first version replays a bounded history instead of maintaining a projection cache.
- Live OpenSea collection reads still require separate commissioning and promotion decisions.

## Implementation reconciliation

Unit 1 preserves the accepted input and identity contract. The existing provider contract version
now has a constant-only export, `@rsi/source-contracts/opensea-trending-version`, so Stage 0 does
not import the provider request descriptor. The provider parser re-exports the same constant.
Ranks must follow array order from one through the result count, matching the existing parser
projection. Contract-address overlap also rejects duplicate contract groups.

Unit 2 keeps authorization and snapshot commits separate. `consumeAndCommit` first commits the
runtime receipt, then rechecks authority under a second runtime write lock around the synchronous
watchlist transaction. The history stores that committed receipt's check time as `importedAt`.
The public runtime capability projection is unchanged. Import permission is represented by the
new boundary and the operator's RESEARCH-only command. Exact retries retain the original import
time and predecessor, including after another snapshot becomes the head.

Unit 3 implements `/api/watchlist`, `/api/watchlist/preview`, and `/api/watchlist/confirm` on the
existing loopback server. Only the two watchlist command bodies have a 32,768-byte limit; existing
control limits remain unchanged. The browser accepts local files up to 30,000 bytes, keeps the
preview input in memory, and sends the exact binding on confirmation. No path or URL is accepted.
The third database defaults beside the research database and can be selected with `--watchlist-db`.
The authority gate allows only `createHash` in the snapshot module and `randomUUID` in the host
provider. Its scanner distinguishes the typed `OfflineBaseWatchlist.import` method from dynamic
module imports; mutation tests still reject an actual `import()` inside that method.

## Next implementation step

The offline vertical slice is implemented. Live provider reads, commissioning, durable rollback
anchors, and any financial action require separate decisions and authorization.
