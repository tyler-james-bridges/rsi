# Recorded collection attention

`@rsi/attention` turns bounded, operator-supplied recorded evidence into Base collection research priorities. It performs no provider request, payment, signing, or execution. `review`, `watch`, and `rejected` are research outcomes, not legitimacy or return predictions.

Policy `attention-v2` tracks marketplace rank windows and X integrity chronology independently. An unusable rank window cannot change collection identity or rank facts. A valid X window still records hashed post-to-content bindings, including an empty window that advances the X chronology cursor. Future or regressed X windows cannot change those facts. A `LEFT_WINDOW` row cites both rank windows and remains valid until the current rank window expires. This unshipped policy does not replay or migrate `attention-v1` history.

## Local recording

Open `RecordedAttentionHistory` with a dedicated SQLite path and `createRuntimeAttentionReceiptVerifier(runtime)`. The verifier exposes only attention-authorization ownership and persisted-receipt verification, and it requires a genuine runtime controller. Keep the runtime open until the history is closed. The first open of an empty database writes one lineage genesis event. Reopening writes nothing. A nonempty pre-genesis database is unsupported and must be migrated or replaced explicitly.

1. Call `findRecorded(rawBundle)` before requesting authority. An exact canonical duplicate returns its original immutable result in every runtime mode, including STOPPED and after restart.
2. Call `preview(rawBundle, { processInstanceId, modeRevision, evaluatedAt })`. This is write-free. It returns either `preview` or `already_recorded`.
3. For a new preview, explicitly request runtime `attention_refresh` authorization with `actionId: attentionPreviewActionId(preview.binding)`.
4. Call `record({ input: rawBundle, expected: preview.binding, authorization })`. The authorization must be genuine, in-process, RESEARCH-only, and bound to the preview's runtime process and revision.

Every explicit new preview gets a fresh preview UUID and action ID. The binding commits its history lineage, preview UUID, canonical bundle identity, policy, audit head, runtime process and revision, evaluated time, 30-second wall-clock deadline, and deterministic decision hash. The history also holds a private 30-second monotonic lease for that exact binding. A restart or close invalidates uncommitted previews. At most 1,000 leases may be live; expired leases are pruned and live leases are never evicted to make room.

Recording recomputes the preview under the attention lock, invokes the final runtime checkpoint, and recomputes time-sensitive classification. It checks the lease before locking, after locking, and immediately before append. The deadline is exclusive, so a preview is invalid at exactly 30,000 milliseconds. Any future, freshness, expiry, history-head, or lineage transition requires a new preview. Failed attempts can leave an allowed runtime receipt without an attention event. Such orphan receipts do not create queue rows.

## Reading and storage

`read(evaluatedAt)` is write-free. It returns saved rows with an effective expiry overlay and the latest twenty history headers. Expired review/watch rows become watch with priority zero and `ASSESSMENT_EXPIRED`; the saved outcome remains visible. A read time before the latest checkpoint returns only `unavailable` with `clock_regressed`.

Every open/read/preview/lookup verifies event-store integrity and the exact pinned genesis identity and hash. A changed head is replayed from empty facts. An unchanged cryptographic head may reuse the already verified replay. All persisted attention receipts are exact-checked in one bounded replay of durable runtime history. Receipt verification happens outside the attention lock. A new commit takes the runtime lock before the attention lock. Unknown events, inconsistent restores, mutated assessments or facts, reused receipts, and chronology violations fail closed.

A copied database intentionally retains its lineage. A valid attention-only prefix rollback can look exactly like a legitimate orphan runtime receipt and this release cannot detect it. Detection requires an independent durable head or a cross-store acknowledgement protocol. A coordinated rollback of both internally consistent databases is also outside this release's detection boundary.

The verifier binds each new authorization to the exact runtime controller instance that issued it. A different controller cannot supply authority even when a separate runtime database deliberately reuses the same process UUID, mode, and revision. This process-local object check grants no durable authority; exact receipt verification against runtime history remains the restart-safe proof for saved events.

History is capped at 1,000 batch events plus one genesis event. Each event is capped at 512 KiB, and the model has a shared 1,000-retained-fact limit. Preview rejects additions that exceed these bounds. Before the first batch, the public batch audit head is `null`; the first batch has raw event sequence 2. Each batch retains sanitized facts, the assessment, next facts, binding, receipt, and checkpoint. Raw post text, IDs, and URLs are never persisted. Public previews/results/views also exclude internal sanitized facts.

## Operator protocol

Use the exported strict parsers for preview commands, record commands, bindings, previews, results, and views. Wire commands accept only `{ input }` or `{ input, expected }`. Runtime authority never crosses HTTP. The local operator obtains it only after parsing and confirming a new preview.
