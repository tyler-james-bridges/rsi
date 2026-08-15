# `@rsi/ingestion`

This package joins the bounded read-only X collector to RSI's encrypted capture
Vault, authenticated capture registry, and tamper-evident event store.

`ingestXRecentSearch` follows a strict lifecycle:

1. validate the closed session, lane, profile, attempt, retention, and network-authorization context;
2. canonicalize the query and bind its fingerprint to a pending registry intent **before egress**;
3. collect one bounded response from the read-only X adapter;
4. verify the response binding and encrypt the exact bytes under a random opaque capture ID;
5. parse only after the encrypted capture boundary and derive a bounded private source index;
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
enter the event store or returned result.

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
`x.recent-search.v1` authorization and the concrete authenticated operations store for the
attempt, lane, profile, session, expiry, social source plane, and reserved USD-micro amount. The
operations row must be `reserved` before collection and `dispatched` immediately afterward.

This package performs no payments, signing, trading, or other state-changing external actions.
