# `@rsi/runtime`

Signer-blind, local runtime authority for RSI's first production stage. It owns a dedicated
`SqliteEventStore` path and exposes no raw store handle, network transport, credential, signer,
wallet, payment permit, policy approval, execution adapter, or general-purpose action callback. Its
only dispatch callback is the one-shot, write-locked `research_collection` boundary described
below.

## Modes

```text
STOPPED -> RESEARCH -> PROPOSE_ONLY
              ^             |
              +-------------+

RESEARCH -------> STOPPED <------- PROPOSE_ONLY
```

Every `open` writes a new startup STOP event before returning. A prior `RESEARCH` or
`PROPOSE_ONLY` process is never resumed after restart. Escalation requires the exact expected mode
and revision. Emergency `stop` requires neither, succeeds from every mode, and invalidates all
outstanding authorizations by advancing the revision. Startup and emergency STOP clamp a regressed
provider clock to the current audit timestamp so clock rollback cannot prevent deactivation. A
same-request retry returns the current audit head only while that exact mode revision remains
current.

`RESEARCH` can authorize only `research_collection`. `PROPOSE_ONLY` can authorize collection and
`proposal_persist`. `policy_approval`, `paid_read`, `wallet_sign`, `execution_adapter`,
`transaction_broadcast`, and `external_publish` are permanently forbidden by runtime schema v1.

## Boundary use

`requestBoundaryAuthorization` returns an authentic, process-bound, revision-bound, one-shot
object with a fixed 30-second lifetime. The controller owns both the wall and monotonic clocks used
to issue and consume it; callers cannot supply either timestamp. Non-network boundaries retain the
zero-argument `consume` method. A `research_collection` authorization instead exposes only
`consumeAndDispatch`, which replays and rechecks durable state while holding the runtime SQLite
write lock across one synchronous transport invocation. A competing process cannot persist STOP in
the validation-to-dispatch gap. After dispatch, that same object exposes one terminal
`guardCompletion` call. It verifies the exact durable ALLOWED dispatch event and rechecks the
current process, mode, and revision while holding the runtime write lock across one synchronous,
content-free result checkpoint. Thus completion and a competing STOP have a defined database-lock
winner; a STOP that commits first prevents the checkpoint callback from running. The fixed lifetime
limits dispatch authority; completion grants no new egress and remains bound to that exact durable
dispatch. Dispatch expiry, clock regression, a mode transition, STOP, restart, duplicate or
malformed use, an asynchronous or proxied callback, a copied object, or a fabricated object fails
closed.

The runtime database and `listAudit` DTO contain only closed mode and boundary audit fields.
External content and research proposals belong in separate stores. `ResearchProposalV1` is
deliberately non-executable; it cannot be converted into an `ExecutionIntent` inside this package.
