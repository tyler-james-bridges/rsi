# Observer v1 readiness and qualification protocol

## No current readiness label

The repository has implemented the Stage A offline components and is completing its
release/repository evidence gate. Until that evidence is retained and the readiness
conclusion is signed, it is **not** `FOUNDATION_BUILT`, `PROVISIONING_READY`,
`COMMISSIONED`, `QUALIFIED`, or `PRODUCTION_OBSERVER`.

A readiness label is a signed evidence conclusion. It is not inferred from a passing
test command, a merge, a deployment, or a live response.

## Readiness ladder

| State                 | Entry evidence                                                                                                                                | Authority granted                                                                                |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `FOUNDATION_BUILT`    | Complete Stage A contract/traceability, offline implementation, secret-free CI, audits, demos, drills, scans, and independent review all pass | Request a separate checkpoint for host/provider provisioning; no credential or network authority |
| `PROVISIONING_READY`  | Host, Keychains, accounts, scopes, alerts, anchors, backups, and provider terms/prices are configured and verified without spending           | Request approval for bounded commissioning; no general live collection                           |
| `COMMISSIONED`        | Separately approved one-call X canary and bounded OpenSea/chain canaries pass and reconcile                                                   | Begin the fixed supervised qualification release/source plan                                     |
| `QUALIFIED`           | Ten accepted sessions on ten distinct days within a rolling 14-day window plus mandatory drills and signed operator approval                  | Begin frozen activation procedure; no automatic service yet                                      |
| `PRODUCTION_OBSERVER` | Independent MacBook activation and a clean seven-day burn-in pass                                                                             | Run approved read-only weekday X and continuous private market-observation schedules             |

No label grants payment, wallet, transaction, trading, public market-intelligence,
or financial-advice authority.

## Stage A: `FOUNDATION_BUILT`

Before asking for credentials, provider resources, DNS, host mutation, deployment,
or a live call, Stage A MUST complete:

- versioned specification, threat model, classification/permission matrices,
  runbooks, qualification protocol, diagrams, and Q1-Q195 traceability;
- private GitHub repository, full-history secret scan, secret-free offline CI,
  signed foundation tag/release evidence, Node 24 and pnpm 11 pins;
- non-mutating host-preflight tooling;
- Vault v2 with per-capture keys/index/deletion/orphan recovery;
- content-free event schemas and schema-lineage behavior;
- cost reservations, encrypted pending cursors, crash-safe session state machine;
- external-checkpoint and backup interfaces with offline fakes;
- alert/lifecycle logic, loopback operator dashboard, and static public projection;
- offline X/OpenSea/chain adapter contracts and adversarial fixtures;
- failure-drill harness, full test/format/typecheck/audit/demo suite, and independent
  non-authoring-agent review.

There are zero live calls and zero credentials in this stage.

## Provisioning: `PROVISIONING_READY`

Provisioning requires separate operator approval and local entry. It verifies:

- supported, updated, encrypted, hardened Mac mini posture;
- separate standard non-iCloud canary and production accounts;
- FileVault, firewall/services/sleep, clock, disk, runtime, and exclusive-writer
  behavior;
- provider accounts owned by the operator, MFA/passkeys, offline recovery, exact
  terms/price/retention review, and least-privilege credential scopes;
- Keychain-only masked credential entry with harmless scope checks;
- B2 Object Lock checkpoint bucket, separate review-outbox, asymmetric writer and
  verifier credentials, retention, and unique-object behavior;
- APFS-encrypted SSD plus MacBook backup/restore path;
- Resend sender and Healthchecks dead-man without inbound control;
- MacBook release/operator/public keys and per-environment checkpoint/vault keys;
- no wallet, AgentCash, x402, Robinhood, OpenSea-write, X-write, or remote-control
  credentials.

Credential values and account-specific inputs are entered locally, not through
chat, source files, or CI.

## Commissioning: `COMMISSIONED`

Commissioning is not qualification session 1. It requires another explicit live
approval after fresh provider review.

### X commissioning

- one curated official query;
- `max_results = 10`;
- one attempt and no retry;
- $0.15 reservation;
- encrypt-before-parse and full purge;
- stop immediately and reconcile the provider console;
- verify actual request-field dialect, auth, size, cost, terms, event allowlist,
  deletion, checkpoint, backup, and alert behavior.

### Marketplace and chain commissioning

- approved secondary ERC-721/1155 watchlist fixture or live read target only;
- OpenSea REST and Stream read-only canaries, with Stream treated as trigger;
- Alchemy read-only Base and Robinhood Chain calls;
- canary support for the finalized block tag and current finality behavior;
- optional public RPC/Blockscout cross-check, never a qualification dependency;
- no metadata/media/token-URI fetch and no historical X backfill;
- bounded retry, timeout, response-size, freshness, raw purge, checkpoint, backup,
  and cost evidence.

Any conflict with the planning assumptions reopens only the affected source branch.

## Qualification release freeze

All ten counting sessions use one immutable signed release, policy, redaction
schema, source plan, and query plan. A material behavior change restarts the window.
A normal credential rotation does not restart only when it is a planned drill and
no compromise or behavior change occurred.

The first X commissioning call never counts. Required failure drills run in
separate, non-counting sessions.

## Qualifying session procedure

### 1. Plan

- Schedule one session on a distinct calendar day; maximum ten counting sessions in
  one rolling 14-day window and never more than one per day.
- Reserve 120 minutes maximum and X tickets/costs before work.
- Freeze the five queries/lanes; no mid-session mutation.

### 2. Preflight

The dashboard displays and verifies:

- release, lockfile, runtime, configuration, policy, and schema hashes;
- credential scope presence without values;
- disabled financial and state-changing adapters;
- exact egress allowlist and no inbound/remote control;
- two-source clock status, disk/resource ceilings, exclusive writer;
- database/event/checkpoint lineage and incident latch;
- vault deletion/orphan state, cursor state, and cost reservations;
- B2, MacBook verifier, encrypted backup target, Resend, and Healthchecks readiness.

The operator types the generated session ID. Any failure prevents `running`.

### 3. Run under supervision

- Maximum 120 minutes; acknowledgments around minute 45 and 90.
- Five required X lanes: official announcements, approved contract/watchlist,
  marketplace/liquidity discussion, security/manipulation, discovery.
- 15 X tickets total: 12 curated, three discovery; at most two attempts per ticket.
- OpenSea REST plus Stream closure and Alchemy canonical chain closure.
- No model affects collection, trust, or ranking.
- Every raw capture uses Vault v2 and remains inside session retention.
- Every batch receives a unique B2 checkpoint; cursor stays pending.

Missed acknowledgment, clock violation, bound violation, or stop condition enters
the abort path without extension.

### 4. Close and purge

- Block new egress and consume in-flight reservations.
- Close every required lane or abstain/invalidate.
- Destroy all raw captures, encrypted source indexes, and per-capture keys.
- Verify expiry/orphan scans and content-free deletion receipts.
- Build the private content-free digest and event checkpoint.
- Write and verify sanitized backup to the encrypted SSD and MacBook.
- MacBook verifies the complete B2 suffix and signs the operator receipt.
- Commit cursors only after all prior steps pass.

### 5. Reconcile and accept

Provider billing may remain pending for at most 48 hours. While pending, the session
does not count and cannot publish. When exact cost stays within reservations and all
evidence passes, transition to `accepted`. Missing/over-reserve cost invalidates;
later corrections are incidents.

The operator applies signed `useful`, `unclear`, `noise`, or `misleading` feedback
within 24 hours for volatile findings. Feedback cannot override safety.

## Session acceptance equation

A session counts only if all are true:

```text
preflight
AND five X lanes closed
AND OpenSea plane closed
AND finalized Alchemy plane closed
AND evidence/integrity verified
AND raw purge and orphan scan verified
AND content-free events/digest verified
AND B2 suffix verified by MacBook
AND encrypted backup verified
AND costs reconciled inside reservations
AND alert/dead-man healthy
AND no incident
AND explicit close complete
```

The qualification passes only with **ten accepted sessions on ten distinct days
within one rolling 14-day window and no Class B or C incident in that window**.
Class A attempts do not count and do not reset an otherwise valid window. Promotion
still requires signed operator approval.

Qualification MAY pass with zero `insight_eligible` findings. In that case it proves
only operational reliability and explicitly records that usefulness, edge,
prediction, and profitability remain unvalidated.

## Human usability gate

The operator completes the dashboard acceptance script without a shell:

1. inspect preflight and provenance;
2. start with typed session ID;
3. acknowledge both supervision points;
4. inspect a typed finding and an abstention;
5. invoke kill/abort and verify new egress blocks immediately, acknowledgment within
   one second, and `stopping` within five seconds;
6. restart only through the approved local flow;
7. close, verify, purge, and inspect the MacBook receipt;
8. label feedback and prepare—but do not automatically publish—a candidate.

Every task must succeed without showing quarantined/raw content or permitting edits
to policy, query, budget, credential, cursor, event, or history state.

## Mandatory drill matrix

Before qualification, independently pass bounded drills for:

- network loss, timeout, 408/429/502/503/504, auth rejection, and malformed schema;
- redirect rejection, oversize response/event, queue overflow, disk/capture limits;
- clock skew, backward jump, and discontinuity;
- missed acknowledgment, local abort, crash, reboot, logout, second writer;
- cursor loss/partial pagination and no premature advancement;
- database/event/checkpoint mismatch and B2 outage;
- Resend failure and Healthchecks dead-man behavior;
- encrypted backup restore and host-replacement lineage;
- provider credential rotation and actual-compromise procedure;
- signing-key transition and compromised-key freeze;
- crypto-shred, failed deletion, expiry, and orphan recovery;
- public signature, predecessor, correction, tombstone, stale, and leak handling;
- model disabled/drift boundaries and forbidden financial-adapter absence.

Drills use fixtures or controlled canary failures, never hostile production payloads.
Repeat the complete matrix quarterly and the affected subset before each relevant
release. Planned contained drills do not trigger incident resets.

## Activation and burn-in

After qualification:

1. freeze the signed release/configuration for 24 hours;
2. have the MacBook independently verify release, backups, checkpoints, source
   scopes, and the complete qualification package;
3. sign the go-live record with the operator-approval key;
4. type the unique activation phrase locally on the Mac mini;
5. run the first production day fully supervised;
6. complete seven days of burn-in with daily physical review and daily MacBook
   verification; Class B/C stops production;
7. only after seven clean days enable the normal weekday X schedule and continuous
   private market-observation cadence through a user-level service.

Burn-in does not relax any budget, source, evidence, retention, or supervision
limit. Production has no availability SLA and no remote restart.

## Evidence package at each milestone

Each readiness transition produces:

- exact commit and signed release/tag identity;
- requirement and decision coverage;
- commands, versions, and complete results;
- independent-review verdict;
- drills and acceptance evidence;
- residual risks and known gaps;
- exact money spent and external state changed;
- rollback/recovery instructions;
- next local inputs and approvals required.

A later milestone cannot retroactively excuse an incomplete earlier one.

## Acceptance matrix

| Control                  | Evidence type                                      | Objective pass condition                                                                                                                                                                                                                                                                                                        |
| ------------------------ | -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Contract coverage        | Offline mechanical review                          | Exactly Q001-Q195, each once, each mapped to a defined requirement ID and honest evidence status; all local links resolve                                                                                                                                                                                                       |
| Repository and release   | Local/GitHub, secret-free                          | Full-history scan clean; remote graph equals local; required CI green; signed manifest/SBOM binds exact sources/runtime/config/tests                                                                                                                                                                                            |
| Offline boundary         | Test and network-denial harness                    | Normal tests/demos/CI make no external request and contain no provider/financial credential path                                                                                                                                                                                                                                |
| Vault v2                 | Unit, property, crash-point fault injection        | Opaque IDs, one DEK/capture, encrypted identity index, no equality leak, no complete unindexed capture at any crash point, capture/event retry idempotency, receipts on every cleanup, expiry/orphan recovery, no forbidden durable field                                                                                       |
| Event and schema lineage | Unit, migration, tamper                            | Unknown fields reject; predecessor/sequence/signature verify; prior-version reader works; incompatible writer creates linked lineage; rollback cannot write newer state                                                                                                                                                         |
| Cost ledger              | Unit, concurrency, crash                           | Reservation precedes egress; full operation/source/lane/profile/session/expiry/$0.15 binding matches before collection; every attempt consumes; no double use; all crash points remain within ceilings                                                                                                                          |
| Cursor lifecycle         | Unit, fault-injection                              | Only a closed successful same-profile/source/lane attempt can stage exactly one advance; each page consumes a reservation; times are monotonic and every retry returns its original identical result; every pre-verification failure leaves committed cursor unchanged; loss starts bounded-overlap lineage and blocks findings |
| External anchor          | Fake then B2/MacBook drill                         | Unique content-free object; writer cannot read/list/delete/replace accepted state; verifier cannot write; full suffix/retention metadata verify                                                                                                                                                                                 |
| Backup and restore       | Isolated restore drill                             | Last accepted sanitized state restores within 24h with zero accepted-session loss and without raw, cursor, credential, operations-state key, wrapping key, or DEK                                                                                                                                                               |
| Alert path               | Fake clock then provider canary                    | Local stop immediate; Resend handoff ≤60s; five-minute heartbeat/ten-minute grace; only closed content-free payload appears                                                                                                                                                                                                     |
| Dashboard                | Scripted operator acceptance                       | All required tasks complete without shell; no raw data; no forbidden mutation; kill acknowledgment ≤1s and stopping ≤5s                                                                                                                                                                                                         |
| Public projection        | Schema, signature, browser, correction tests       | Only allowlisted fields; ≥24h/manual approval; valid sequence/predecessor/correction; failures show `UNVERIFIED`; takedown/tombstone works                                                                                                                                                                                      |
| Source adapters          | Offline fixtures then separately approved canaries | X is exactly ten results and ≤512 query characters; exact origin/method/schema/time/size/retry/freshness/terms/finality contract passes; raw purge and cost reconcile; no silent substitute                                                                                                                                     |
| Evidence kernel          | Visible/hidden/adversarial corpus                  | Zero safety/redaction leaks; positive needs all three planes/three clusters; hard negative abstains; stale/incomplete findings expire                                                                                                                                                                                           |
| StrategyPatch            | Statistical/review evidence                        | One bounded active patch; 100% safety/hidden pass; ≥30 labels; paired 95% CI improvement; no worse misleading/cost/latency/freshness/abstention; signed human promotion                                                                                                                                                         |
| Qualification            | Signed ten-session ledger                          | Ten accepted sessions on ten distinct days in rolling 14 days, required drills, no Class B/C, usability pass, explicit approval                                                                                                                                                                                                 |
| Activation and burn-in   | MacBook/operator signed package                    | 24h freeze, independent verification, typed local activation, supervised day one, seven clean reviewed days before service enable                                                                                                                                                                                               |

An incomplete or inapplicable row is a failure, not an implicit waiver. Provider
canary rows are outside Stage A and cannot be satisfied with fixtures alone.
