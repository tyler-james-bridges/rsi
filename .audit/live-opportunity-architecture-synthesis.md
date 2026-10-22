# Collection-attention architecture synthesis

## Arena result

Candidate B is the implementation base. The independent cross-judge scored it 27/30, ahead of A at 25/30 and C at 16/30.

The selected shape is one cohesive `@rsi/attention` package with enforced pure model boundaries, a dedicated append-only SQLite history, a new RESEARCH-only `attention_refresh` runtime permission, and explicit preview/record/read operator actions. The first release accepts only bounded recorded evidence and labels it `operator_supplied_unverified`. It performs no provider call and creates no execution artifact.

## Grafts

Two ideas from candidate A are incorporated:

1. Contract sets remain the durable collection identity and slugs remain labels. A disjoint contract set reusing a slug is a new collection whose first observation is capped to watch; it is not permanently vetoed by an earlier unverified label association.
2. A read clock earlier than the latest durable commit returns a strict `clock_regressed` unavailable view. GET never writes a clock correction or silently restores freshness.

Candidate C contributed no graft. Its useful STOP and receipt-verification ideas were already expressed more coherently in B.

## Rejected alternatives

- Do not reuse the watchlist or token proposal ledger.
- Do not use network-capable `research_collection` authority for a local assessment commit.
- Do not let rejected future or stale incident batches advance the usable comparison cursor.
- Do not let repeated copied social content receive a new first-seen time.
- Do not infer X authors, post publication times, metrics, redirects, or independent consensus from the current `{id,text}` source contract.
- Do not identify duplicates by a random preview UUID; use canonical bundle plus policy identity.
- Do not write live evidence directly into the attention database during provider completion.
- Do not implement the future authenticated outbox in this recorded-evidence series.

## First-release contract

- Input: a strict bounded marketplace rank window, optional recorded X `{id,text}` posts, and optional recorded Base head context.
- Identity: Base chain 8453 plus an exact sorted contract set.
- Outcomes: `review`, `watch`, or `rejected`; these are research triage, never legitimacy, expected return, or purchase eligibility.
- Social matching: exact contract-address mentions only; normalized duplicate text counts once; contribution is capped; authors remain unknown.
- Safety: ambiguous identity, overlapping groups, unsupported chains, future/stale mandatory evidence, changed post content, instruction-like content, deceptive links, and financial solicitations are closed policy reasons.
- History: one complete immutable assessed batch per canonical bundle and policy, exact retry returns the original, incident chronology is separate from the last usable comparison window, and restart performs no work.
- Operator: explicit local file preview and record actions, plus a read-only queue view with score components, provenance, expiry, missing checks, reasons, and next action.

## Future seam

A later security-reviewed series may retain a sanitized source projection in a keyed authenticated operations outbox, bind it to the exact attempt and STOP-aware completion, gate delivery on raw-capture deletion and key destruction, and import it only through another explicit queue action. Existing receipts cannot be backfilled. The current canary recovery ordering must be redesigned and kill-point tested before that outbox exists.

## Verification status

Three subsystem reviews, three design candidates, and an independent cross-judge established the architecture. The implementation through `d339bdb` passes the pinned Node 24.19.0 checks, 1,339 tests, the Stage 0 and Stage 1 gates, and the fresh-process HTTP flow. Independent security and product reviews passed. The final real-browser receipt and PR landing remain pending in `todo.md`.

## Exact-preview authorization amendment

The history owns three different identities. The canonical refresh ID identifies one recorded bundle and policy. An immutable genesis event identifies the durable history lineage. A fresh preview ID identifies one 30-second confirmation window.

The runtime action ID is a domain-separated hash of the complete versioned preview binding. The binding commits to the history lineage, preview ID, canonical refresh, current audit head, decision hash, policy, process, mode revision, evaluation time, and wall deadline. A private bounded lease registry starts at preview creation, uses a monotonic clock, disappears on restart, prunes expired entries, and rejects new previews when every remaining slot is live. The history checks the lease before runtime consumption, after it acquires the attention lock, and immediately before append.

The first open of an empty attention database writes exactly one structural identity event under the attention lock. Reopen writes nothing. Nonempty legacy attention histories are rejected because their refresh-only receipts cannot be upgraded into exact-preview receipts. Public batch chronology remains separate from the raw store head, so the first assessed batch has raw sequence 2 while its predecessor remains null.

Candidate Astra is the base. The cross-judge scored it 23/25 against Candidate Luna at 18/25 because it closes the same authorization gaps without changing generic store metadata or adding runtime-owned attention leases. The selected grafts from Luna are branded history, preview, and action IDs; a fresh preview ID for every explicit preview; field-mutation tests; and fail-closed lease-map saturation.

A complete database copy retains its lineage by design. A valid attention-only prefix rollback remains indistinguishable from a legitimate orphan runtime receipt. Detection requires an independent durable head or a cross-store acknowledgement protocol and is outside this recorded, non-executable release.
