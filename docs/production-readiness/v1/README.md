# RSI Observer production-readiness contract v1

- Status: **accepted design; fail-closed Stage A scaffolding in final software verification; stable signed component and physical evidence remain blocked**
- Accepted decision set: **Q1-Q195**
- Contract date: **2026-08-14**
- Last revised: **2026-08-23 — aggregate verification and physical-media gates reconciled**
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
| [Foundation Stage A v2 workflow](./foundation-stage-a-v2.md)            | Offline governance-key bootstrap, retained CI, two-signature evidence ceremony, and physical blockers       |
| [Release-helper compatibility gate](./helper-compatibility-gate.md)     | Current signed-component blocker, canonical public drill evidence, and T → A → B Git lineage                |
| [Runbook index](./runbooks/README.md)                                   | Bounded response procedures and the evidence each procedure must produce                                    |
| [Sanitized restore procedure](./recovery/observer-restore.md)           | Verify-before-restore process for the three closed recovery companions                                      |
| [Public project decision](./decisions/2026-08-16-build-in-public.md)    | Accepted public project/repository disclosure, controls, exclusions, and irreversibility                    |

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

The remaining Stage A work begins with implementing and reviewing the stable signed
helper described below, followed by physical release/repository evidence. Later
operational provisioning remains separate; none of this is permission to weaken
the boundary. Foundation Stage A v2 now has
a fixed-intent MacBook release-key bootstrap, exact two-media recovery evidence,
public identity/receipt pin parser, bounded public CI-retention adapter, and a
platform-pinned, independent-review-gated, two-signature offline ceremony that
emits a verified bundle, readiness conclusion, detached tag bytes, and a canonical
report. The workflow preserves partial durable artifacts and never installs or
publishes a Git object/ref/tag/release. None of those physical steps has been
performed.

The repository still lacks the complete
production event vocabulary, physical two-copy recovery verification, real
B2/Resend/Healthchecks adapters and resources, quarantined marketplace/chain
transports, host hardening, and qualification evidence. Exact Node 24.19.0 now runs
the full offline drill suite, but preflight observation is not remediation and does
not prove the current host is hardened; stock Darwin AirPlay Receiver status remains
an explicit `unknown`, not a pass. No approved live provider call has occurred.
Consequently, no readiness label in the v1 ladder has yet been signed or attained.

### Explicit Stage A integration blockers

- Replace the ad-hoc helper with the provisioned stable signed component, then
  complete the throwaway-MacBook drill proving exclusive helper identity, exact Data
  Protection Keychain attributes, and two distinct user-presence prompts without
  persistent approval. This is a hard blocker before any real key exists.
- On the designated offline MacBook, bind a fixed provisioning intent to two
  distinct encrypted APFS physical disks; create, eject, physically reconnect,
  unlock, and restore-verify both recovery envelopes; then retain the nonsecret
  public identity and provisioning receipt. The intent and pins bind a
  domain-separated platform identity so a different MacBook refuses. Any ambiguous
  write remains preserved and requires the exact resume flow.
- Review and pin that nonsecret identity plus receipt through protected public
  `main`, retain and visually verify fresh CI, and retain a fresh canonical
  five-scope non-authoring review for the exact pinning commit/tree with every
  finding resolved. The provisioning commit must be an ancestor and contain the
  exact attested helper source.
- On the same designated offline MacBook, run the ceremony's two user-presence
  signatures in release-then-detached-tag order. Independently verify the bundle,
  receipt, readiness conclusion, detached tag bytes, ceremony report, retained CI,
  bound review evidence, public commit/tree, platform hash, and signer fingerprint
  before deciding whether `FOUNDATION_BUILT` is supported. The tooling does not
  create a Git object/ref/tag, GitHub release, push, or deployment.
- Record the Stage A handoff with exact commands, hashes, review verdict, zero
  spend, and zero external provider changes. Provider/runtime credentials and host
  provisioning remain a later, separately approved checkpoint.

Every item remains a pre-live blocker. None is a raw-retention exception or
permission to weaken the Observer boundary.
