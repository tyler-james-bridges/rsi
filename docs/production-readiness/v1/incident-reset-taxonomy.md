# Observer v1 incident and reset taxonomy

## Universal response order

Every suspected incident follows the objective hierarchy:

1. block new outbound work in the affected profile;
2. account for and close in-flight cost reservations without retrying;
3. preserve pending cursors without committing them;
4. crypto-shred and purge required ephemeral data;
5. checkpoint content-free state when doing so is safe;
6. alert with the minimum approved payload;
7. classify the incident and apply its reset rule;
8. require local operator review and explicit resume.

Availability never outranks containment. Only the operator may resume.

## Reset classes

| Class                         | Examples                                                                                                                                                                                                                                 | Qualification effect                                                                                                                                 | Required recovery                                                                                                                    |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| **A — invalid attempt**       | Provider outage, incomplete evidence lane, missed midpoint acknowledgment, billing reconciliation delayed but within policy, nonsensitive alert-delivery failure                                                                         | The attempt does not count and does not reset an otherwise valid 14-day window                                                                       | Stop/purge/invalidate, repair or wait for source, pass relevant checks, operator resumes                                             |
| **B — qualification restart** | Material code/policy/schema/source-plan change; cursor loss; host restore/replacement; deletion, checkpoint, or backup failure; actual provider-credential compromise without evidence of broader exposure; erroneous public publication | Discard the active ten-session window and restart after repair and evidence                                                                          | Incident record, root cause, affected drill subset, new signed release/lineage when applicable, operator restart approval            |
| **C — design branch reopen**  | Raw-data leakage; policy/redaction escape; cross-environment contamination; signing-key compromise; unauthorized exposure; wallet, AgentCash, x402, Robinhood, OpenSea-write, or other financial credential in Observer                  | Qualification stops; no restart until incident review, new lineage/keys where applicable, and a new grilling/design decision for the affected branch | Full containment, revocation, scope analysis, new trust root as needed, independent review, explicit design replacement and approval |

Planned synthetic drills do not trigger a reset when they are contained in their
declared fixture/canary boundary and produce the required signed evidence.

## Immediate stop conditions

The runtime MUST latch stopped for any of these:

- policy, redaction, retention, or no-execution boundary escape;
- raw, identity, query, credential, account, email, provider, or hostile-content
  leakage into a permanent event, model input, backup, public candidate, alert, or
  artifact;
- event, database, journal, checkpoint, B2 suffix, release, or signature mismatch;
- unexpected cost, exhausted reservation, auto-recharge, unreconciled cost beyond
  48 hours, or later budget correction;
- purge, crypto-shred, expiry, or orphan-recovery failure;
- credential exposure, scope expansion, unapproved key transition, or missing
  credential-separation evidence;
- unapproved release, query, configuration, policy, provider, schema, source plan,
  publication, or deployment;
- backward clock movement, excessive skew/discontinuity, cursor corruption, or
  commit before external verification;
- malformed public artifact, signature/predecessor/correction failure, or public
  source-content disclosure;
- disk, capture, queue, durable-state, response-size, retry, or time bounds exceeded;
- second writer, crash/reboot/logout, database corruption, or incident-latch bypass;
- any future financial/state-changing adapter becoming credentialed or reachable.

A normal required-source outage quarantines that plane and causes abstention. It is
Class A unless integrity, terms, retention, or substitution behavior is also
implicated.

## Incident-specific decisions

### Provider credential suspected or confirmed compromised

1. Stop only the affected plane unless evidence indicates broader host/account
   compromise.
2. Revoke the exact credential from a clean operator device.
3. Inspect provider account activity and content-free local evidence.
4. Rotate and re-run the harmless scope test.
5. Apply Class B for actual compromise; escalate to Class C for data leakage,
   cross-profile access, unauthorized mutation, or broader exposure.
6. Only the operator may resume.

### Checkpoint, release, approval, or public signing key compromised

1. Freeze the affected collection, release, approval, or publication plane.
2. Pin the last independently verified B2/public/release head.
3. Revoke/retire the key; do not delete disputed evidence.
4. Create a new key with two encrypted offline recovery copies.
5. Establish a signed or independently witnessed predecessor-to-successor recovery
   transition and new lineage.
6. Restore and independently verify; classify as C and reopen the key-trust branch.

### Operations-state or vault-wrapping key suspected compromised

1. Stop the affected profile and block cursor commit, backup, and publication.
2. Purge all reachable ephemeral captures before destroying the affected key when
   doing so is still safe; never retain raw data for investigation.
3. Pin the last independently verified content-free event/checkpoint head and
   inspect authenticated operational evidence from a clean device.
4. Destroy the key, create a distinct replacement in the correct profile Keychain,
   and start new operations, cursor, and vault lineages as applicable.
5. Classify as B only when independent evidence proves no raw disclosure, store
   mutation, or cross-profile access. Any inability to bound those effects is C and
   reopens the affected trust branch.

### Raw-data, privacy, or public-projection leak

1. Stop collection and publication; remove the mutable public head.
2. Delete affected R2 artifacts and purge caches where supported; publish a signed
   tombstone/correction when it can be done without repeating the leak.
3. Destroy remaining ephemeral copies and revoke exposed credentials/keys.
4. Determine affected fields, profiles, recipients, duration, and external systems
   using content-free records.
5. Classify as C; create a new lineage when trust or event history is affected.
6. Apply the disclosure rule below.

### Deletion, expiry, or orphan-recovery failure

1. Block egress and cursor commit.
2. Retry only the idempotent local purge operation—never the provider request.
3. Verify per-capture key destruction, body/index removal, and orphan scan.
4. If completion cannot be proven, invalidate and classify as B; escalate to C if
   unapproved retention or exposure occurred.
5. Reproduce the bug with synthetic bytes and add a regression test.

### Cursor loss or incorrect advancement

1. Stop the affected source and reject pending findings.
2. Preserve the last independently verified content-free checkpoint.
3. Start a new source lineage with only the approved bounded overlap.
4. Do not emit findings until overlap closure proves continuity.
5. Classify as B during qualification; production resumption uses a new canary and
   applicable requalification.

### B2, MacBook verifier, or backup unavailable

If work has not been accepted, purge and invalidate without cursor advancement. An
availability failure is Class A; failed checkpoint/backup integrity or an inability
to demonstrate accepted-state recovery is Class B. There is no local-only
acceptance shortcut.

### Provider terms, price, API, or finality drift

Disable the affected lane without substitution. Record only source location, review
date, outcome, and bounded reason. Revalidate contract, price, retention, endpoint,
authentication, and finality behavior in canary. A material source-plan or behavior
change is Class B/requalification work; ambiguity stays disabled.

### Host loss, restore, or replacement

Do not restore raw data, operations-state or wrapping keys, credentials, or cursors.
Restore only the last accepted sanitized backup and release evidence, establish new
operations/source lineages and host keys, repeat host/preflight/restore drills, and
restart qualification as Class B. Evidence of unauthorized access or secret
disclosure escalates to C.

## Alert contract

The local dashboard immediately shows a red stopped state. Resend handoff occurs
within 60 seconds, and Healthchecks uses five-minute heartbeats with a ten-minute
grace. Alerts contain only:

- incident code and severity;
- UTC timestamp;
- environment/profile and random session ID;
- “open the local RSI console.”

No source, asset, Post, provider, query, credential, account, recipient, error text,
stack trace, URL, or exact defense appears in the alert.

## Disclosure and correction

Every incident receives a private, signed, content-free record. A faulty or unsafe
public artifact is withdrawn immediately and receives a signed correction within 24
hours. A bounded public root-cause summary is published within seven days only when
public integrity or exposed data was affected. It may state timing, scope,
classification, and remediation; it omits hostile payloads, secrets, raw provider
data, identities, and exploitable defensive details.

## Change after incident

Every incident that reveals a new policy rule or failure mode adds a regression
test. Emergency security fixes stop production until canary and required review
pass. Urgency does not waive supply-chain, retention, deletion, signature, or
qualification gates.
