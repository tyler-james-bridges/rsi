# `@rsi/store`

SQLite-backed append-only event history for RSI. The store uses canonical JSON,
strictly increasing sequence numbers, and a SHA-256 hash chain. A transactional
metadata head also exposes tail deletion. Every existing database is verified
when opened, and every append verifies the complete chain while holding a write
transaction.

```ts
import { SqliteEventStore } from "@rsi/store";

const store = new SqliteEventStore("./var/rsi-events.sqlite");
const event = store.append({
  type: "claim.observed",
  aggregateId: "claim:123",
  payload: { source: "x", postId: "123" },
  idempotencyKey: "x-post-123",
});
store.close();
```

Use `withExclusiveTransaction(() => ...)` for a synchronous read/decide/append
critical section. `append()` calls made inside the callback share its SQLite
`BEGIN IMMEDIATE` transaction. Native async functions are rejected before they
are invoked, returned promises are rejected, and continuations using the same
store are invalidated after the callback exits. Nested callbacks are rejected.
Callbacks must not schedule asynchronous side effects or open another store;
keep the entire critical section synchronous.

`eventId` and `idempotencyKey` are optional. An exact retry returns the existing
event without consuming a sequence. Reusing either identifier for different
content throws `EventConflictError`. When `occurredAt` is omitted, retry
comparison ignores the newly generated timestamp; an explicitly supplied
timestamp must match.

The hash chain is tamper-evident, not an external trust anchor. An attacker who
can replace the entire database can replace its in-database metadata too. Anchor
published head hashes outside this database before relying on it to prove
history to third parties.
