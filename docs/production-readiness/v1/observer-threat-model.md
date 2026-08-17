# RSI Observer v1 threat model

## Scope and prime assumption

This model covers the read-only Observer release. It assumes an attacker can study
public artifacts, the brand, livestream narrative, observed timing, public chain
state, and any later-disclosed scoring concepts. The attacker can manufacture social
activity and marketplace events tailored to those concepts, compromise a formerly
trusted account, exploit provider or supply-chain weaknesses, and submit hostile
bytes intended to influence an agent or leak through a projection.

**External activity ranks hypotheses; it never grants authority.** Observer has no
capital or transaction authority, and no code path may make hostile content an
instruction.

## Protected assets

| Asset                               | Security objective                                                 |
| ----------------------------------- | ------------------------------------------------------------------ |
| Operator and provider credentials   | Confidentiality, least privilege, revocability, profile isolation  |
| Raw source captures and identifiers | Session-bounded confidentiality and verifiable destruction         |
| Sanitized event history             | Integrity, append-only lineage, bounded disclosure                 |
| Cursors and budget reservations     | Confidentiality, atomicity, no advancement after incomplete work   |
| Checkpoint and release lineage      | Authenticity, rollback and suffix-deletion detection               |
| Public artifacts and signing keys   | Authenticity, correction capability, no source-data leakage        |
| Qualification evidence              | Completeness, independence, no selective omission or metric gaming |
| Host and runtime                    | Single-writer integrity, no remote control, bounded resources      |
| Human authority                     | No forged promotion, resume, publication, or activation approval   |

## Trust boundaries

1. **Internet to quarantine:** X, OpenSea, Alchemy, public RPC, and all response
   metadata are hostile until encrypted and schema-validated.
2. **Vault to extractor:** decryption occurs only inside the bounded quarantine
   path; parsing does not grant tools, network, or signer access.
3. **Typed claims to evidence kernel:** closed schemas and independent evidence
   determine eligibility. Model prose is never admitted.
4. **Private state to operator dashboard:** only explicit safe projections cross;
   loopback binding does not replace schema-level redaction.
5. **Mac mini to B2/MacBook:** unique checkpoint objects and asymmetric credentials
   prevent the collector from rewriting verified history.
6. **Mac mini candidate to public site:** the mini emits an unsigned, content-free
   candidate; the MacBook independently reviews and signs after the delay.
7. **Observer to future execution:** a one-way observation bundle is evidence, not
   authorization. The v1 system has no execution route.

## Threats and required responses

| ID     | Threat                                                                     | Required mitigation and failure behavior                                                                                                                                               |
| ------ | -------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| TM-001 | Prompt, tool, or indirect instruction injection                            | Encrypt before parse; process in a no-tools boundary; strict closed schemas; instruction-like content is quarantined; zero escapes are tolerated.                                      |
| TM-002 | Coordinated shilling or fake consensus                                     | Cluster stable origins, timing, contract references, and coordination patterns; count one cluster once; require three planes and three origin clusters for positive insight.           |
| TM-003 | Compromised official or previously trusted account                         | Treat X as a provisional trigger; detect identity/edit/delete changes; require marketplace and finalized-chain corroboration; one hard negative forces abstention.                     |
| TM-004 | Contract, proxy, collection, or chain substitution                         | Match full chain/address/token scope; resolve proxy implementation at the relevant time; change returns the asset to quarantine.                                                       |
| TM-005 | Marketplace manipulation, wash activity, or stale order state              | Use OpenSea as one plane, require canonical chain state, enforce short freshness, and avoid P&L or executable-value claims.                                                            |
| TM-006 | Malicious metadata, media, URI, SVG, HTML, or IPFS content                 | Never fetch or render it in Observer v1.                                                                                                                                               |
| TM-007 | Source outage or provider terms change                                     | Mark the lane unavailable, preserve unaffected risk-only facts, and abstain; never scrape or substitute silently.                                                                      |
| TM-008 | Redirect, oversized response, retry storm, or decompression/resource abuse | Forbid redirects; enforce origin, timeout, byte, event, retry, queue, disk, and capture limits before semantic handling.                                                               |
| TM-009 | Authentication rejection or credential reflection                          | Never retry auth/permission failure; reject responses containing credential material; stop, revoke, inspect, rotate, and retest the affected plane.                                    |
| TM-010 | Billing ambiguity or provider price change                                 | Reserve pessimistically before each attempt; retries consume; keep the session pending up to 48 hours; invalidate on missing or excess cost; no recharge.                              |
| TM-011 | Cursor loss, partial pagination, or overlap gap                            | Keep encrypted pending cursors; commit only after full external verification; use bounded overlap and new lineage after loss; block findings until closure.                            |
| TM-012 | Raw-data retention or deletion failure                                     | Per-capture keys, wrapping-key separation, idempotent crypto-shred, expiry and orphan scans; stop and invalidate; no forensics exception.                                              |
| TM-013 | Event tampering, tail deletion, or database replacement                    | Hash-linked SQLite events, signed checkpoints, independently retained suffix head, unique B2 objects, MacBook verification, and linked schema lineages.                                |
| TM-014 | Signing-key theft or forged history                                        | Separate release/operator/public/checkpoint keys; offline recovery copies; signed transitions; freeze the affected plane and establish a new lineage after compromise.                 |
| TM-015 | Cross-environment contamination                                            | Separate macOS accounts, Keychains, state, cursors, keys, and credentials; contamination is Class C and requires incident review.                                                      |
| TM-016 | Second writer, stale state, crash restart, or split brain                  | Exclusive OS lock, startup integrity checks, one writer, no automatic crash restart, incident latch, and no cursor commit before acceptance.                                           |
| TM-017 | Clock rollback or timestamp manipulation                                   | Two independent clock sources; warn over two seconds, abort over five seconds or on backward/>2-second discontinuity.                                                                  |
| TM-018 | Backup omission or false acceptance                                        | Acceptance waits for encrypted-drive backup and MacBook verification; restore drills; accepted-session RPO is zero.                                                                    |
| TM-019 | Alert suppression or unattended runtime                                    | Local immediate stop and red state; Resend handoff; Healthchecks dead-man; missing supervision invalidates the session; no remote resume.                                              |
| TM-020 | Public-projection leak or tampering                                        | Closed content-free schema, 24-hour review delay, separate repository/outbox, MacBook signature, browser verification, correction/tombstone procedure, no public object lock.          |
| TM-021 | Model prompt injection, data leakage, or drift                             | No raw/model path; sanitized closed `ModelObservation`; no tools/web/state; model optional to qualification; replay/shadow gate on drift.                                              |
| TM-022 | Malicious dependency, CI action, or compromised release                    | Protected public project repository, tree/history secret scans, full-SHA actions, offline secret-free CI, SBOM, signed whole bundles, independent review, no CI deployment.            |
| TM-023 | RSI modifies its own safeguards or test oracle                             | StrategyPatch cannot address immutable controls, code, tests, logs, credentials, evaluator, or deployment; hidden corpus; human promotion; automatic safety rollback.                  |
| TM-024 | Host compromise or physical loss                                           | FileVault, standard non-iCloud accounts, firewall/services hardening, narrow egress, encrypted backups, replaceable provider credentials, new lineage/qualification after restoration. |
| TM-025 | Accidental wallet, x402, Robinhood, or marketplace-write activation        | No credentials; disabled interfaces; preflight explicitly proves absence; any financial credential in Observer is Class C.                                                             |
| TM-026 | Livestream or screenshot disclosure                                        | Dev fixtures only; never display production surfaces or provider consoles; review recordings before keeping or publishing them.                                                        |

## Abuse-sensitive asset classes

The following are risk-only and cannot become positive `insight_eligible` findings:

- unresolved or ambiguous chain, contract, proxy, owner, token scope, or marketplace;
- securities, RWA, financial-return, or unsupported ownership claims;
- gambling or chance-based activity;
- stolen, frozen, sanctioned, or otherwise restricted assets or parties;
- copyright infringement, impersonation, homograph, or copied-collection risk;
- any conclusion dependent on arbitrary web content or NFT metadata/media.

## Mandatory security properties

- A hostile byte sequence cannot invoke a tool, mutate policy, emit public text, or
  reach a signer.
- A positive finding cannot exist without fresh X, marketplace, and finalized-chain
  evidence plus independent-origin clustering.
- A hard negative can force abstention; positive evidence cannot exploit this
  asymmetry.
- Unknown schema fields fail closed at event, model, candidate, and public
  boundaries.
- Running work cannot make its cursor durable before external verification.
- Observer cannot obtain payment or execution authority through configuration.
- Only the operator can resume, promote, publish, or activate.

## Residual risk and non-claims

Even with these controls, providers can be wrong, multiple planes can share an
upstream source, the host can be compromised while unlocked, deletion cannot undo
data already exposed outside approved boundaries, and NFT markets can move faster
than verified finality. Observer therefore makes no availability, completeness,
profitability, prediction, or advice claim. Qualification demonstrates bounded
read-only operational reliability only.

## Required adversarial evidence

The complete drill matrix is normative in the qualification protocol. At minimum,
security review must show zero policy/redaction escapes under hostile fixtures;
failed schema/auth/budget/deletion/integrity cases do not retry; crash and partial
page cases do not advance cursors; public artifacts remain content-free; model-off
operation remains valid; and every future financial adapter stays absent and
uncredentialed.
