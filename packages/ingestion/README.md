# `@rsi/ingestion`

This package joins the bounded read-only X collector to RSI's encrypted capture
Vault, authenticated capture registry, and tamper-evident event store.

The fixed OpenSea trending path is intentionally isolated behind
`@rsi/ingestion/opensea-trending`; it is not exported from the package root. It accepts no
request input and binds exactly one `opensea.trending-collections.v1` attempt to the
`marketplace` lane and source plane with the non-payment authorization slot `reservedAtomic:
"1"`. Live bytes are encrypted in Vault before strict schema parsing. Only as many as ten
`collection_slug` identifiers enter the private capture registry, while the durable event and
returned result exclude slugs, addresses, provider hashes, cursors, text, URLs, API keys, and
capture IDs. Fresh results may include a boolean `hasNextPage` and validated rate-limit counters;
neither is reconstructed on retry.

OpenSea crash recovery requires the authenticated operations binding, capture-registry row, and
Vault capture. It never accepts a caller-supplied quarantine or re-brands stored bytes as a live
network response. After checking the attempt fingerprint and Vault metadata, it parses directly
inside the Vault byte-copy wipe scope and compares the projection with the committed private
identifiers. Recovery needs no collector, API key, or egress. Malformed content still crosses the
encrypt-first boundary and becomes `INVALID_RESPONSE_SCHEMA` with an empty private identifier
set.

The encrypted Vault media type carries a private, hex-only `rsi-provenance` digest over the exact
provider content type, fixed request fingerprint, and full durable dispatch binding. This keeps
the provider bytes exact while preventing a genuine capture from one attempt from being swapped
into another attempt that shares the same fixed request fingerprint. The digest never enters an
event or result.

`ingestXRecentSearch` follows a strict lifecycle:

1. validate the closed session, lane, profile, attempt, retention, and network-authorization context;
2. canonicalize the query and bind its fingerprint to a pending registry intent **before egress**;
3. collect one bounded response from the read-only X adapter;
4. verify the response binding and encrypt the exact bytes under a random opaque capture ID;
5. parse only after the encrypted capture boundary and derive a posts-only private source index;
6. atomically bind the capture ID and source index to the pending registry intent;
7. append only `source.capture.recorded.v2`, a closed content-free event; and
8. destroy the quarantine object and wipe every caller-owned byte copy.

An exact retry is resolved from the authenticated registry first. A committed capture is
verified and, when necessary, reparsed from Vault to finish a missing event without a second
network request. Live crash recovery reads the durable dispatched/closed binding from the
authenticated operations store; it needs neither the consumed permit nor a collector. A changed
query, session, lane, profile, expiry, or source conflicts before collection. A terminal removed
attempt with its prior safe event can return that event; a removed attempt without one fails
closed.

Malformed responses follow the same short-lived encrypted path and produce a typed rejection
with an empty private source index. They are not a forensics exception: every capture must be
crypto-shredded at session close and is independently bounded to at most two hours. Queries,
response hashes, provider identifiers, URLs, raw text, capture IDs, and storage paths never
enter the event store or returned result. The minimal projection records Post IDs and an opaque
next-page token only in the private capture registry; it does not infer authors or edit history
that the one-request response did not request. Actor/edit event counts therefore mean records
present in the projection and remain zero.

Callers may provide an `AbortSignal`, which is forwarded only to an in-flight collection. Once
response bytes arrive, ingestion completes the encrypted-first commit so cancellation cannot
strand plaintext or turn a valid capture into an untracked artifact. A fresh call may return the
collector's validated `{ limit, remaining, resetAtUnixSeconds }` receipt. That receipt is never
written to the capture event and is `null` when a durable retry is reconstructed from storage.

`recoverCaptureStorage` is a mandatory startup step before new ingestion. It resumes Vault
deletions, tombstones abandoned pending intents, repairs a Vault-deleted/registry-committed
crash gap, verifies every committed registry reference, and repeatedly reconciles unregistered
Vault captures until no bounded batch remains. Its receipt contains aggregate counts only.

Each runtime profile (`dev`, `canary`, or `production-observer`) requires its own registry
SQLite file and a dedicated 32-byte registry key. The key must be isolated from Vault wrapping,
event-store, outbox, and other profile keys. Opening a registry with another profile is rejected.
The registry directory is private (`0700`) and its database is owner-only (`0600`).

Only collectors branded by the closed X collector factory are accepted; structural lookalikes
fail before egress. Replay is restricted to `dev`. Live collection requires the exact one-shot
runtime `research_collection` authorization, `x.recent-search.v1` attempt authorization, and the
concrete authenticated operations store for the attempt, lane, profile, session, expiry, social
source plane, and reserved USD-micro amount. The operations row must be `reserved` before
collection and `dispatched` immediately afterward.

This package performs no payments, signing, trading, or other state-changing external actions.
