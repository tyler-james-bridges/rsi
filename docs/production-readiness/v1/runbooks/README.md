# Observer v1 runbook index

These are bounded operator procedures, not authorization to provision or call a live
service. Every runbook begins by stopping the affected plane and ends with signed,
content-free evidence plus explicit local operator disposition.

## Common evidence envelope

Every runbook records only: schema version, random incident/session ID, UTC time,
profile, release/config/policy hashes, bounded incident code/class, affected plane,
counts/costs, permitted integrity references, actions completed, verification
status, operator signature, and predecessor. It never records source text,
identities, queries, URLs, provider origins, credentials, emails, stack traces,
vault addresses, or exact defensive details.

## Index

| Runbook                                 | Trigger                                                                | Core steps                                                                                                                  | Successful exit                                                                                         |
| --------------------------------------- | ---------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `RB-01 Preflight refusal`               | Any preflight check fails                                              | Do not unlock egress; preserve no new cursor; identify bounded code; repair in canary                                       | Complete preflight passes under same signed release or the release/change gate restarts                 |
| `RB-02 Local abort/kill`                | Operator kill, missed acknowledgment, bound/clock violation            | Block new outbound work; account for in-flight reservations; keep cursors pending; purge; checkpoint if safe; lock Keychain | Session is invalid, purge receipt verifies, no cursor advanced, local operator decides next attempt     |
| `RB-03 Crash/reboot/logout`             | Writer exits before acceptance                                         | Keep incident latch; start offline; verify database/checkpoints; purge/orphan scan; invalidate                              | Integrity proves clean and operator resumes, or Class B/C recovery begins                               |
| `RB-04 Provider outage`                 | Required source timeout/unavailable                                    | Stop retry at policy bound; quarantine lane; retain unaffected risk-only counts; abstain                                    | Class A attempt invalidates; new attempt only after provider health and preflight pass                  |
| `RB-05 Cost anomaly`                    | Missing, excess, changed, or late charge                               | Stop affected plane/recharge; freeze reservations; reconcile provider console from operator device                          | Within-reserve pending cost resolves before 48 hours, otherwise invalidate/incident and re-review price |
| `RB-06 Provider credential compromise`  | Suspected exposure or unauthorized provider activity                   | Stop plane; revoke; inspect content-free evidence/account; rotate; scope-test; classify                                     | Operator resume after Class B repair, or Class C branch reopening for broader exposure                  |
| `RB-07 Signing-key compromise`          | Forged/disclosed checkpoint, release, approval, or public key          | Freeze plane; pin last independent head; retire key; create backed-up successor; establish recovery transition              | Independent verification of new lineage; Class C design approval before restart                         |
| `RB-08 Raw-data/deletion failure`       | Purge, expiry, DEK, index, or orphan check fails                       | Block egress/cursor; retry idempotent local purge only; verify every capture; reproduce synthetically                       | Class B after proven cleanup; Class C if retention/exposure escaped boundary                            |
| `RB-09 Cursor loss or premature commit` | Cursor absent, corrupt, or ahead of verified suffix                    | Stop source; invalidate findings; pin last head; new lineage and bounded overlap                                            | Overlap closes with no findings beforehand; qualification restarts when applicable                      |
| `RB-10 Event/checkpoint/B2 mismatch`    | Chain, journal, signature, suffix, or object verification fails        | Stop writer; do not “repair” canonical history; retain content-free disputed heads; verify from MacBook                     | Restore last trusted accepted state/new lineage and apply Class B/C classification                      |
| `RB-11 Backup restore/host replacement` | Restore drill, host loss, or replacement                               | Restore only sanitized accepted state; exclude raw/cursors/operations-state/wrapping keys/secrets; create new lineages      | Recovery within 24 hours, zero accepted-session loss, fresh qualification after replacement             |
| `RB-12 Alert/dead-man failure`          | Resend handoff or Healthchecks behavior fails                          | Local stop remains authoritative; keep payload content-free; test bounded fallback path                                     | Class A when nonsensitive availability only; Class B/C if monitoring integrity or data leaked           |
| `RB-13 Public correction/takedown`      | Invalid signature, stale head, leakage, terms/legal issue              | Remove head; delete R2 object; purge cache if supported; sign correction/tombstone; open incident                           | Correction within 24 hours and, when required, bounded postmortem within seven days                     |
| `RB-14 Provider/terms/finality drift`   | Price, terms, endpoint, auth, retention, schema, or finality ambiguity | Disable lane; record source location/date/outcome; no substitution; reopen affected source plan                             | Fresh canary and change/requalification gate pass                                                       |
| `RB-15 Release rollback`                | Regression without history compromise                                  | Stop; select whole prior signed bundle; verify lineage/config/schema read/write compatibility; canary                       | Last-known-good bundle runs without writing incompatible newer state                                    |
| `RB-16 Qualification reset`             | Class B or C during qualification                                      | Freeze evidence; classify; discard active window; repair and drill; obtain required design approval                         | New immutable release/source plan starts a new ten-session window                                       |
| `RB-17 Activation`                      | Signed `QUALIFIED` package and 24-hour freeze complete                 | MacBook verify; operator sign; type local activation phrase; supervise day one                                              | Seven-day burn-in begins; no automatic schedule before clean completion                                 |
| `RB-18 Retirement`                      | Operator ends Observer permanently                                     | Disable schedule/egress; revoke providers; destroy operations-state/wrapping keys/cursors; purge; final checkpoint          | Signed public retired status; sanitized records age out under 365-day/lock rules                        |
| `RB-19 Operations/vault key compromise` | Operations-state or vault-wrapping key is suspected exposed            | Stop profile; safely purge; pin independent head; destroy key; create distinct replacement and new applicable lineages      | Class B only if no disclosure/mutation/cross-profile effect is proven; otherwise Class C branch review  |

## Procedure invariants

- No runbook can broaden egress, credentials, retention, budget, provider scope, or
  public fields.
- Retrying a source call is never a recovery step unless the normal bounded retry
  policy explicitly permits it.
- Raw content is never copied into a ticket, incident note, model, alert, terminal
  transcript, or postmortem.
- A local-only checkpoint, backup, or approval cannot substitute for the MacBook and
  B2 requirements.
- The operator is the only resume authority. Being away means Observer remains
  stopped and the public viewer becomes visibly stale after 24 hours without a
  signed daily epoch.
- A new rule discovered during recovery must become a regression test before the
  affected release can progress.
