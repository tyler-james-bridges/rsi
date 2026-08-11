# `@rsi/ingestion`

This package joins the quarantined X collector to RSI's encrypted snapshot vault and
tamper-evident event store.

`ingestXRecentSearch` follows a strict order:

1. collect a bounded response from the read-only X adapter;
2. encrypt the exact response bytes in `@rsi/vault`;
3. parse the quarantined bytes through the pinned X response schema;
4. append only a closed, text-free archive projection to `@rsi/store`.

Malformed responses are retained as encrypted forensic snapshots and represented by a
safe rejection event. Raw post text, bearer credentials, and the canonical search query
are never placed in SQLite or returned to callers.

The integration accepts collector `live` and `replay` modes only. It refuses `record`
mode before collection because a cassette sink runs inside the collector, before this
package can place the response in the vault. The provided in-memory cassette remains
useful for tests and offline replay; durable live capture must use this encrypt-first path.

This package performs no payments, signing, trading, or other state-changing external
actions.
