# `@rsi/research-ledger`

Durable, content-free Stage 0 research proposal scorecards.

The ledger uses its own `SqliteEventStore` file; do not point it at the runtime authority
database. A new proposal is accepted only when:

- it passes the isolated strict `ResearchProposalV1` schema;
- it contains exact chain, contract, token ID, evidence IDs, closed provenance, flags,
  disposition, and bounded scores;
- it contains none of the executable or raw-content fields rejected by that schema; and
- it consumes a genuine, one-shot `proposal_persist` authorization bound to the same proposal ID
  while the runtime is still in the exact `PROPOSE_ONLY` revision; and
- the runtime's complete allowed receipt is bound to that authorization and checked strictly before
  its fixed expiry. The ledger derives `persistedAt` from the runtime-owned `checkedAt`; callers
  cannot supply a persistence timestamp.

The ledger verifies its complete event chain and semantic bindings before projecting data. Its hash
chain detects local edits, reordering, tail deletion, and foreign events, but it cannot detect
replacement by a complete older internally consistent file without an independently retained
head.
