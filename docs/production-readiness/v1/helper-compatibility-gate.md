# Release-helper compatibility gate

- Status: **blocking; no passing record exists**
- Fixed record path:
  `config/foundation-release-key-helper-compatibility.v1.json`
- Real key, recovery media, Keychain item, and signatures created: **none**

This gate prevents the Foundation release-key provisioning command from reaching
recovery-target inspection, the fixed intent, Keychain presence, passphrase
prompts, key generation, or any durable provisioning write until a reviewed
throwaway-MacBook drill matches the exact helper and runtime about to run.

The record is public, canonical evidence. It contains no private key, recovery
material, passphrase, raw platform identifier, credential, or operational data.
Do not add a record merely to make the command pass.

## Current architectural blocker

The current Swift helper is deterministically compiled and ad-hoc signed for
offline tests. It uses `userPresence`, but that condition authenticates the user;
it does not establish an exclusive application identity. The helper currently has
no provisioned Keychain access-group entitlement, stable Apple Team identity, or
trusted app-like bundle. It also relies on the Node ceremony host—not the trusted
component itself—for the release-once-then-tag-once sequence.

For the Data Protection Keychain, macOS derives available access groups from code
signing entitlements. Apple states that those entitlements must be authorized by a
provisioning profile and that a command-line component using a restricted
entitlement needs an app-like bundle. See [TN3137: On Mac keychain APIs and
implementations](https://developer.apple.com/documentation/Technotes/tn3137-on-mac-keychains),
[Keychain access groups](https://developer.apple.com/documentation/security/ksecattraccessgroup),
and [Creating distribution-signed code for
macOS](https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac/).

Therefore the current helper cannot truthfully satisfy
`unauthorizedAlternateClientAccess: "refused"`. The compatibility file is
intentionally absent, and real provisioning must remain blocked.

Before a physical drill can pass, a separately reviewed change must:

1. replace the ephemeral helper with a stable, app-like component signed by the
   owner's Apple team and authorized provisioning profile;
2. pin its Team ID, bundle/code-signing identifier, designated requirement,
   provisioning profile, entitlements, exact Keychain access group, Hardened
   Runtime state, executable/bundle hashes, and compiler identity;
3. set and verify the exact `kSecAttrAccessGroup` on every Keychain operation;
4. move complete payload validation and durable release-once-then-tag-once state
   into that trusted component so copying or invoking it cannot create a generic
   signing oracle; and
5. extend this evidence schema and the runtime verifier to bind those facts before
   requesting any production secret.

That change requires an owner-controlled Apple signing identity and provisioning
profile. Neither belongs in Git, chat, logs, environment variables, or test
fixtures.

## Required Git lineage

The evidence is not self-referential. Use this topology:

1. **T — tested helper commit:** contains the exact helper source used by the
   throwaway drill.
2. **A — reviewed evidence/provisioning commit:** adds the canonical compatibility
   record naming T. T must be a real ancestor, and the helper source must be
   unchanged.
3. **B — identity-pinning commit:** later adds the nonsecret public identity and
   provisioning receipt. A must be an ancestor, and the compatibility record plus
   helper source must be byte-identical through B.

Provisioning records A. The public identity, fixed intent, provisioning receipt,
readiness conclusion, and ceremony report bind the compatibility-record hash and
T. Ceremony verification rereads the record and helper from the exact Git commits;
a changed or missing blob refuses before signing.

## Physical drill requirements

After the signed-component architecture exists, use a disposable MacBook and a
disposable identity. The drill must not use the designated production MacBook,
real recovery disks, or real recovery passphrases.

Retain raw, independently hashable evidence for all of these checks:

- exact public repository commit, helper source, component binary/bundle,
  compiler, architecture, macOS product version/build, Node `24.19.0`, and pnpm
  `11.20.0`;
- exact Data Protection Keychain, `WhenUnlockedThisDeviceOnly`, disabled
  synchronization, fixed access group, and user-presence attributes;
- actual access refusal for an unauthorized alternate client, without treating an
  operator pressing Cancel as access-control proof;
- two fresh component processes and two distinct approved prompts, with no
  persistent approval;
- verified release-domain and Git-tag-domain signatures in the fixed order;
- process arguments, environment, stdout, stderr, logs/diagnostics, and filesystem
  artifacts scanned for private material; and
- deletion of the disposable Keychain item, destruction of disposable private
  material, and verified cleanup of temporary artifacts.

The drill operator and independent approver must be different people or agents.
The approver must neither author the tested component/evidence nor operate the
drill.

## Canonical record shape

The following is structural only. Every placeholder must be replaced with
observed data and backed by retained raw evidence. Encode the final object as
canonical UTF-8 JSON with no trailing newline.

```json
{
  "cleanup": {
    "evidenceSha256": "<64-hex>",
    "keychainItem": "deleted-and-absence-verified",
    "outcome": "passed",
    "temporaryArtifacts": "removed-and-absence-verified",
    "testPrivateMaterial": "destroyed-and-absence-verified"
  },
  "completedAt": "<canonical-UTC-timestamp>",
  "drillId": "<stable-drill-id>",
  "drillOperatorId": "<stable-operator-id>",
  "environment": {
    "architecture": "<arm64|x64>",
    "hardwareClass": "MacBook",
    "macosBuildVersion": "<sw_vers-buildVersion>",
    "macosProductVersion": "<sw_vers-productVersion>",
    "nodeVersion": "v24.19.0",
    "pnpmVersion": "11.20.0"
  },
  "evidencePath": "config/foundation-release-key-helper-compatibility.v1.json",
  "evidenceType": "rsi.release-key-helper-compatibility-evidence",
  "helper": {
    "binarySha256": "<64-hex>",
    "compilerIdentitySha256": "<64-hex>",
    "sourceSha256": "<64-hex>"
  },
  "helperPath": "packages/release-key-provisioning/native/keychain-helper.swift",
  "independentApproval": {
    "approvedAt": "<canonical-UTC-timestamp-at-or-after-completion>",
    "approvalEvidenceSha256": "<64-hex>",
    "authorship": "did-not-author-tested-helper-or-evidence",
    "drillParticipation": "did-not-operate-drill",
    "reviewerId": "<stable-reviewer-id>",
    "reviewerRole": "independent-non-authoring-reviewer",
    "verdict": "approved"
  },
  "keychainControls": {
    "accessibility": "when-unlocked-this-device-only",
    "dataProtectionKeychain": "verified",
    "evidenceSha256": "<64-hex>",
    "persistentApproval": "not-granted",
    "synchronizable": "disabled",
    "unauthorizedAlternateClientAccess": "refused",
    "userPresence": "required"
  },
  "privateMaterialLeakScan": {
    "evidenceSha256": "<64-hex>",
    "outcome": "passed",
    "scopes": [
      { "name": "process-arguments", "outcome": "passed" },
      { "name": "process-environment", "outcome": "passed" },
      { "name": "standard-output", "outcome": "passed" },
      { "name": "standard-error", "outcome": "passed" },
      { "name": "logs-and-diagnostics", "outcome": "passed" },
      { "name": "filesystem-artifacts", "outcome": "passed" }
    ]
  },
  "prompts": [
    {
      "attempt": 1,
      "evidenceSha256": "<64-hex>",
      "freshHelperProcess": "verified",
      "outcome": "user-presence-prompt-observed-and-approved-once",
      "scenario": "first-fresh-helper-invocation",
      "signatureVerification": "passed"
    },
    {
      "attempt": 2,
      "evidenceSha256": "<different-64-hex>",
      "freshHelperProcess": "verified",
      "outcome": "user-presence-prompt-observed-and-approved-once",
      "scenario": "second-fresh-helper-invocation-after-first-completed",
      "signatureVerification": "passed"
    }
  ],
  "repository": "tyler-james-bridges/rsi",
  "repositoryVisibility": "public",
  "testedCommitSha": "<40-hex-T>",
  "verdict": "passed",
  "version": 1
}
```

This current schema documents the physical observations accepted by the parser.
It is not sufficient authorization to use the present ad-hoc helper. The signed
component change above must extend the schema and runtime binding first.
