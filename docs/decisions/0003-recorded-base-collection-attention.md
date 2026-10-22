# ADR 0003: recorded Base collection-attention queue

## Status

Accepted for implementation.

## Context

RSI's Stage 0 watchlist retains useful Base collection identity and rank data but its source is operator supplied and unverified. The Stage 1 canaries authenticate tightly bounded provider reads but deliberately discard the collection details needed for a queue before destroying raw capture material. Current X data has only post ID and text; OpenSea data has collection contract groups, rank, slug, and a short validity window; Base RPC supplies environment health context rather than collection validation.

Token proposals require a token ID and carry a different meaning. Reusing them for collection triage would create false identity and execution-adjacent semantics.

## Decision

Build a separate recorded Base collection-attention queue.

The queue will:

- accept only strict bounded recorded evidence through an explicit local preview and record flow;
- assign `operator_supplied_unverified` provenance at ingress rather than accepting a provenance claim from the file;
- identify a collection by chain 8453 and its exact sorted contract set;
- derive deterministic `review`, `watch`, and `rejected` research outcomes with closed reasons and no free-form verdict;
- cap and deduplicate X-shaped text evidence without claiming author independence;
- treat OpenSea-shaped rank as attention, Base RPC-shaped data as zero-point context, and missing evidence as missing coverage;
- store complete assessed batches in a dedicated append-only history;
- authorize a new batch only through a one-shot RESEARCH-only `attention_refresh` local commit boundary serialized against STOP;
- expose score components, provenance, expiry, missing checks, reasons, and a closed next action in the loopback operator; and
- perform no provider read, payment, signing, transaction, or execution action.

A canonical bundle and policy identify an assessment. An exact retry returns the original record without renewing evidence. History tracks both the audit head and the last usable source window so rejected future or stale incidents cannot poison later comparisons. Copied social content keeps its first-seen expiry across batches. A regressed read clock makes the view unavailable rather than restoring freshness.

## Consequences

This produces a usable, auditable research-priority queue before live provider commissioning. Its output remains an operator aid, not authenticated market truth or a trade recommendation.

The runtime, research proposal, watchlist, and attention databases remain separate. The attention history must verify its stored runtime receipts against durable runtime history and must fail closed on corruption or an inconsistent restore. A coordinated rollback of all internally consistent databases is outside this release's detection boundary.

The first release does not modify live collectors or canary receipts. A later authenticated path requires a keyed source-evidence outbox bound to the exact acquisition attempt, allowed completion, and verified erasure. It needs a separate security review because current canary recovery cannot safely adopt that ordering unchanged.

## Rejected options

- Enrich the watchlist history with policy outcomes.
- Use a sentinel token ID or relax `ResearchProposalV1`.
- Use `research_collection` for local persistence.
- Refresh on GET, startup, timers, or page reload.
- Treat rank, verification labels, social volume, or Base head health as profit or legitimacy evidence.
- Accept caller-supplied authenticated provenance.
- Write the attention database from a live completion callback.

