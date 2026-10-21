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

# Live Base watchlist

- [x] `how` over the affected subsystem.
- [x] `architect` for parallel design exploration.
- [x] Write the throughput checkpoint as four todo items.
- [x] Delegate code-writing to a subagent using the configured feature model with a specific scope.
- [x] Verify on the matching surface. Fresh subprocess HTTP flow and real Chrome file selection, preview, confirmation, and STOP verified.
- [x] Rebase into small, ordered commits. Stack follow-ups. Pure model, authorized history, then operator integration.
- [ ] If the design is contested, `interrogate` before shipping. Parent review remains pending.
- [x] Run Opening a PR. skip: the user forbids pushing or opening a PR.

## Architect phases

- [x] Ground.
- [x] Sketch.
- [x] Agree.
- [x] Implement.
- [x] Scrap. skip: no temporary design sketch was added to the implementation tree.

## Throughput checkpoint

- [x] Blocking first steps. Trace the OpenSea boundary, Stage 0 product loop, research persistence, and authority gates before selecting a shape.
- [x] Independent workstreams. Use read-only explorers and independent design candidates in parallel. Give the implementation to one exclusive worktree owner because the vertical slice crosses shared public contracts.
- [x] Shared mutable state. The implementation owner alone writes this worktree. Reviewers use read-only access or separate worktrees after commits exist.
- [x] Smallest safe decomposition. Build one offline collection-watchlist vertical slice with a typed artifact, deterministic history diff, operator UI, and executable no-authority gate. Live credentials and egress remain excluded.

## Architect arena

- [x] Frame.
- [x] Fan out.
- [x] Cross-judge.
- [x] Pick.
- [x] Graft.
- [x] Verify.
