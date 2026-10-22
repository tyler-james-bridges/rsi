# Live collection-attention grounding

## Product boundary

RSI currently has two safe but disconnected paths:

1. Stage 0 imports an operator-supplied OpenSea-shaped snapshot and displays a Base collection watchlist.
2. Stage 1 performs tightly bounded, one-shot reads from X, OpenSea, or Base RPC, destroys the raw response, and emits a minimal receipt.

Neither path produces a durable, authenticated collection-level research queue. The safe extension is a separate attention queue containing typed, sanitized evidence and deterministic assessments. It must not reuse the token-specific proposal ledger, imply profitability, or create execution authority.

## Existing components and limits

| Component | Responsibility | Limit |
| --- | --- | --- |
| Runtime controller | One-shot, mode/revision/process-bound authority serialized against STOP | No queue-specific permission |
| Operations store | Provider attempt, budget, fingerprint, and lifecycle bounds | No collection assessment |
| Vault and capture registry | Encrypt raw responses and verify deletion/key destruction | Deleted content cannot be reconstructed |
| X ingestion | Strictly parses up to ten `{id, text}` posts | Durable projection drops text and has no author, timestamp, metrics, or URLs |
| OpenSea ingestion | Strictly parses Base contract groups, ranks, slugs, and validity | Durable projection drops addresses and ranks; no token, listing, price, volume, or order data |
| Base RPC ingestion | Validates one provider-reported finalized Base anchor | Does not inspect collection contracts, tokens, owners, or orders |
| Offline watchlist | Imports normalized Base collection groups and derives rank changes | Operator-supplied, not authenticated provider evidence |
| Research replay | Exercises hostile recorded scenarios | Fixture-only, abstention-only, and token-specific |
| Proposal ledger | Stores token-specific `ResearchProposalV1` | Every claim requires a token ID; it is not a queue |

## Current live lifecycle

1. A fixed request is bound to a budget and attempt.
2. Runtime grants one-shot `research_collection` authority.
3. Provider bytes enter a bounded quarantine and are encrypted before parsing.
4. A strict source parser produces a typed projection.
5. `guardCompletion()` rechecks STOP, mode, process, revision, and expiry.
6. The attempt closes, raw capture is deleted, its key is destroyed, and a content-free receipt remains.

The useful live retention seam is after strict parsing and before projection loss. Admission must still be bound to successful STOP-aware completion. Existing completed canaries cannot be backfilled from their receipts.

## Safe target shape

1. A pure collection-attention model owns Base collection identity, bounded evidence references, deterministic score components, closed rejection reasons, freshness, missing-check semantics, and `review | watch | rejected` outcomes.
2. A separate append-only history owns assessments. It must not overload watchlist history or the proposal ledger. Exact retries are idempotent; restart never dispatches work.
3. A narrow operator projection shows rank components, provenance, expiry, missing checks, reasons, and the next research action without raw content or execution fields.
4. A future live-evidence checkpoint retains sanitized parser output without widening public receipts. A same-store outbox is preferred over a cross-database write inside runtime completion because it avoids a two-database atomicity claim.

## Policy invariants

- Internet content is data, never instruction.
- OpenSea rank means research attention, never expected return.
- X contribution is deduplicated and capped; the current source cannot prove independent authors.
- Base RPC health is context, not collection corroboration.
- Missing X evidence yields `watch`, not a negative legitimacy verdict.
- Ambiguous identity, overlapping contract groups, unsupported chains, stale/future evidence, instruction-like content, integrity failures, or forged provenance yield rejection or a closed cap.
- No queue artifact contains transaction targets, calls, approvals, signer access, profit estimates, or purchase eligibility.
- Provider commissioning, credentials, and explicit authorization remain separate from queue implementation.

## Unsupported claims

The present system cannot claim that offline snapshots came from OpenSea, recover the deleted X capture, establish independent X consensus, prove a collection scam-free, validate collection contracts through Base RPC, rank token purchases, estimate profit, run recurring live monitoring, or send funds.

## Decisions the architecture must close

1. The first shippable input and provenance class: offline recorded bundle, authenticated live outbox, or both with strict separation.
2. The queue persistence authority and mode.
3. Crash-safe ordering between live completion and evidence retention.
4. Exact Base collection identity continuity rules.
5. Whether risk raises an investigation queue or suppresses the primary queue.
6. Stable deduplication and clustering across acquisition batches.
7. Expiry, partial-window, and `left_window` semantics.
8. Whether whole-database rollback is in scope.

