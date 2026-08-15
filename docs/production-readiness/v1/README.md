# RSI Observer production-readiness contract v1

- Status: **accepted design; offline foundation integration in final verification**
- Accepted decision set: **Q1-Q195**
- Contract date: **2026-08-14**
- Product role: **Observer**
- Capital authority: **none**
- Next attainable readiness label: **`FOUNDATION_BUILT`**

This directory is the normative Stage A contract for RSI Observer. It does not
authorize a live provider call, credential entry, provider provisioning, host
mutation, DNS change, deployment, publication, payment, or transaction.

## Contract documents

| Document                                                                | Purpose                                                                                                     |
| ----------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| [Production-readiness specification](./production-readiness-spec.md)    | Normative product, safety, architecture, operations, recursive-improvement, and implementation requirements |
| [Observer threat model](./observer-threat-model.md)                     | Assets, trust boundaries, attackers, abuse cases, and required mitigations                                  |
| [Decision traceability](./traceability.md)                              | Q1-Q195 mapped to requirement IDs and honest current/planned evidence                                       |
| [Data classification and retention](./data-classification-retention.md) | Allowed data, storage locations, retention clocks, backup/public/model rules, and destruction evidence      |
| [Credential and permission matrix](./credential-permission-matrix.md)   | Maximum authority and custody for accounts, credentials, and signing keys                                   |
| [Incident and reset taxonomy](./incident-reset-taxonomy.md)             | Stop conditions, Class A/B/C effects, response ownership, and disclosure rules                              |
| [Readiness and qualification protocol](./qualification-protocol.md)     | Readiness labels, session state machine, drills, commissioning, qualification, activation, and burn-in      |
| [Runbook index](./runbooks/README.md)                                   | Bounded response procedures and the evidence each procedure must produce                                    |
| [Sanitized restore procedure](./recovery/observer-restore.md)           | Verify-before-restore process for the three closed recovery companions                                      |

## Normative language and precedence

`MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, and `MAY` are normative. The contract is
the set of documents above, not this index alone. More restrictive requirements
take precedence. If two requirements cannot both be met, Observer fails closed and
the affected design branch is reopened; an implementer must not choose the easier
interpretation.

The decision-specific `DEC-Qnnn` entries in the traceability table are normative.
The family requirement IDs provide stable implementation and test targets. Evidence
marked **planned** is not proof that the requirement is implemented.

## Current reality

At the contract date plus the current offline implementation pass, the repository
contains strict schemas and a policy kernel; a hash-linked SQLite event store;
local Ed25519 checkpoints; Vault v2 with opaque capture IDs, per-capture DEKs, and
verified deletion; a profile-bound encrypted capture registry; exact retry and
restart reconciliation; a bounded X recent-search collector with offline replay
and one-use reservations; authenticated cost and cursor state; read-only host
preflight; an external-anchor protocol and publication outbox; supervised session
lifecycle and billing gates; a content-free alert outbox; and three closed recovery
components for state evidence, sanitized events, and signed source/config/runbooks.
The recovery-to-lifecycle controller verifies all three recovery components,
cross-checks their profile, session, release, backup, and signing-key bindings, and
derives the closed local-verification evidence before advancing a genuine session
coordinator.
The loopback operator dashboard exposes only fixed assets and a closed local
lifecycle-control vocabulary. The signed public projection implements delayed,
content-free receipt/correction/tombstone chains with a browser-safe verifier. Exact
offline OpenSea and finalized Base/Robinhood Chain contracts bind asset, order,
block, ownership, runtime-code, and EIP-1967 facts without providing a transport.
The Stage A drill gate runs the complete repository suite and offline demos with
external destinations denied at the Node process boundary.

The remaining work is release/repository evidence and later operational provisioning,
not permission to weaken the boundary. The repository still lacks the complete
production event vocabulary, physical two-copy recovery verification, real
B2/Resend/Healthchecks adapters and resources, quarantined marketplace/chain
transports, host hardening, and qualification evidence. Exact Node 24.19.0 now runs
the full offline drill suite, but preflight observation is not remediation and does
not prove the current host is hardened; stock Darwin AirPlay Receiver status remains
an explicit `unknown`, not a pass. No approved live provider call has occurred.
Consequently, no readiness label in the v1 ladder has yet been signed or attained.

### Explicit Stage A integration blockers

- Assemble and verify the exact release inventory from Git, retain its signed
  evidence, and obtain a clean private-repository CI receipt.
- Perform the final traceability/release review and record the Stage A handoff with
  exact commands, hashes, review verdict, zero spend, and zero external provider
  changes.
- Provisioning remains a separate checkpoint: close every supported host-preflight
  observation, create physical recovery copies, and configure provider resources
  only after explicit approval.

Every item remains a pre-live blocker. None is a raw-retention exception or
permission to weaken the Observer boundary.
