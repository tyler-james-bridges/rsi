# Recorded collection attention

`@rsi/attention` turns bounded, operator-supplied recorded evidence into Base collection research priorities. It performs no provider request, payment, signing, or execution. `review`, `watch`, and `rejected` are research outcomes, not legitimacy or return predictions.

## Local recording

Open `RecordedAttentionHistory` with a dedicated SQLite path and `createRuntimeAttentionReceiptVerifier(runtime)`. The verifier exposes only attention-authorization ownership and persisted-receipt verification, and it requires a genuine runtime controller. Keep the runtime open until the history is closed.

1. Call `findRecorded(rawBundle)` before requesting authority. An exact canonical duplicate returns its original immutable result in every runtime mode, including STOPPED and after restart.
2. Call `preview(rawBundle, { processInstanceId, modeRevision, evaluatedAt })`. This is write-free. It returns either `preview` or `already_recorded`.
3. For a new preview, explicitly request runtime `attention_refresh` authorization with `actionId: preview.binding.refreshId`.
4. Call `record({ input: rawBundle, expected: preview.binding, authorization })`. The authorization must be genuine, in-process, RESEARCH-only, and bound to the preview's runtime process and revision.

The binding includes the canonical bundle, policy, audit head, evaluated time, a 30-second deadline, and a deterministic decision hash. Recording recomputes the preview under the attention lock, invokes the final runtime checkpoint, and recomputes time-sensitive classification. Any future, freshness, or expiry transition requires a new preview. Failed attempts can leave an allowed runtime receipt without an attention event. Such orphan receipts do not create queue rows.

## Reading and storage

`read(evaluatedAt)` is write-free. It returns saved rows with an effective expiry overlay and the latest twenty history headers. Expired review/watch rows become watch with priority zero and `ASSESSMENT_EXPIRED`; the saved outcome remains visible. A read time before the latest checkpoint returns only `unavailable` with `clock_regressed`.

Every open/read/preview/lookup verifies the full event chain, replays the pinned policy from empty facts, and checks each receipt against durable runtime history. Receipt verification happens outside the attention lock. A new commit takes the runtime lock before the attention lock. Unknown events, inconsistent restores, mutated assessments or facts, reused receipts, and chronology violations fail closed. Coordinated rollback of both internally consistent databases is outside this release's detection boundary.

The verifier binds each new authorization to the exact runtime controller instance that issued it. A different controller cannot supply authority even when a separate runtime database deliberately reuses the same process UUID, mode, and revision. This process-local object check grants no durable authority; exact receipt verification against runtime history remains the restart-safe proof for saved events.

History is capped at 1,000 events, each at 512 KiB, with the model's shared 1,000-retained-fact limit. Preview rejects additions that exceed these bounds. The event retains sanitized facts, the assessment, next facts, binding, receipt, and checkpoint. Raw post text, IDs, and URLs are never persisted. Public previews/results/views also exclude internal sanitized facts.

## Operator protocol

Use the exported strict parsers for preview commands, record commands, bindings, previews, results, and views. Wire commands accept only `{ input }` or `{ input, expected }`. Runtime authority never crosses HTTP. The local operator obtains it only after parsing and confirming a new preview.
