# RSI read-only product loop

- [x] Read the Principles section of the poteto-mode skill.
- [x] Phase A: Frame.
- [x] Phase B: Design the workflow.
- [x] Phase C: Run the loop.
  - [x] Add and satisfy an end-to-end acceptance test on a fresh database.
  - [x] Add the pure proposal assessment data shape and scorer.
  - [x] Add one idempotent recorded-replay coordinator behind runtime authorization.
  - [x] Expose the bounded replay through the loopback operator API and dashboard.
  - [x] Add durable outcome evaluation only if it is required by the acceptance predicate. Not required for this bounded product slice; the existing capital-oriented in-memory loop is not represented as durable RSI.
  - [x] Extend authority-graph and production-contract gates.
  - [x] Verify restart, duplicate, STOP, hostile-input, and zero-authority behavior.
- [x] Phase D: Keep the audit trail.
- [x] Phase E: Verify and hand back.

## Throughput checkpoint

- [x] Blocking first steps. Install pinned pstack, inspect the active flow, define the exit predicate, and create an isolated worktree before fan-out.
- [x] Independent workstreams. Architecture, runtime readiness, and product-gap investigation are read-only and ran in parallel. Code work stays with one owner because the operator, runtime authorization, ledger, and dashboard form one coupled path.
- [x] Shared mutable state. Only the root agent writes this worktree. Review agents stay read-only until the implementation is committed.
- [x] Smallest safe decomposition. One owner builds the vertical slice in verifiable commits; separate reviewers attack the resulting diff and authority boundary.
