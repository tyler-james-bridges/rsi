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

## Foundation release ceremony gate

This pre-commissioning gate is not a twentieth incident runbook and grants no live
authority. Before any provisioning input is accepted:

1. Merge and independently review the v2 implementation through protected public
   `main`; do not provision or sign a dirty, detached, feature-branch, or unpushed
   tree.
2. Before any real key exists, pass and retain the throwaway-MacBook drill for the
   exact tracked helper: stable source/compiler/binary evidence, exact Data
   Protection Keychain attributes, disabled synchronization, device-only custody,
   and two separate user-presence prompts with no persistent approval.
3. On the designated MacBook, pre-create the owner-only, non-synced fixed-intent
   parent and an owner-only evidence directory. Prepare two distinct encrypted
   external APFS physical disks and separate recovery directories. Stop recording,
   physically disconnect networking, and verify Node `24.19.0`, pnpm `11.20.0`,
   public `origin`, clean `main == origin/main`, and no existing `foundation-v1`.
   The intent binds a domain-separated platform UUID hash; no different MacBook may
   resume provisioning or perform the final ceremony.
4. Run the fixed release-key create command in
   `packages/release-key-provisioning/README.md`. Enter two different recovery
   passphrases only through the echo-disabled `/dev/tty`. For each disk, complete
   the safe eject, physical disconnect/reconnect, unlock, reread, and decrypt
   restore check. Store the disks separately.
5. If any provisioning write or crash is ambiguous, preserve the fixed intent and
   every partial envelope/evidence file. Do not delete or overwrite them. Diagnose
   and use `--mode resume` with the exact commit, paths, and physical media so the
   surviving identity is recovered rather than replaced.
6. Review the nonsecret identity and provisioning receipt, then commit only those
   canonical records at the fixed `config/` paths through protected public `main`.
   The Keychain item, passphrases, local intent, and encrypted envelopes remain off
   Git.
7. Open the fresh public GitHub Actions run for the exact pinning commit. Verify the
   full commit and both required jobs out of band, then use the fixed CI-retention
   command to write the owner-only canonical evidence plus SHA-256. The record is
   operator-retained evidence, not an independently signed GitHub attestation.
8. Require a non-authoring agent to review that exact commit/tree. Retain canonical
   `.review-evidence.json` no more than seven days before the ceremony. All five
   fixed scopes must pass and every finding must be recorded as resolved with
   finding/resolution hashes. The receipt's provisioning commit must be an ancestor
   of the pinning commit and contain the attested helper source.
9. Transfer both exact evidence records and the checkout to the designated
   MacBook, disconnect every network interface again, and run the closed
   two-signature command in `packages/release-ceremony/README.md`. The first
   user-presence prompt signs and verifies the release bundle; the second signs and
   verifies only detached `foundation-v1` tag-object bytes.
10. Retain the create-only `.rsi-release`, `.receipt.json`,
    `.readiness-conclusion.json`, `.foundation-tag`, and
    `.ceremony-report.json`. Independently compare them with the retained CI,
    bound review, public commit/tree/run, pinned identity/receipt,
    platform/helper evidence, and signer fingerprint before deciding whether
    `FOUNDATION_BUILT` is supported.
11. Stop on every refusal or mismatch. Preserve partial durable artifacts; never
    overwrite or reinterpret them as complete. The tooling does not install a Git
    object, create a tag/ref or GitHub release, push, publish, or deploy. Each is a
    separate explicit owner decision after successful review.

The exact commands and evidence bindings are in
[Foundation Stage A v2](../foundation-stage-a-v2.md). The current project has not
passed the physical helper drill, provisioned the platform-bound release key,
verified the two real recovery media, pinned the resulting identity, retained final
CI and five-scope review, or performed the two real signatures. It therefore does
not claim `FOUNDATION_BUILT`.

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
