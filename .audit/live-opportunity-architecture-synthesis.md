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

The architecture was grounded by three subsystem explorers, synthesized by an explainer, explored by three independent candidates, and cross-judged. Implementation and product verification have not yet been run; the exit condition remains the repository checklist in `todo.md`.
