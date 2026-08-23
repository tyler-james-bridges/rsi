# Optional high-assurance session controller

This package preserves the earlier all-source closure workflow as an optional software component.
It does not define or block the active staged single-machine path; a one-provider `READ_CANARY`
requires a separate capability-specific acceptance record.

`@rsi/session-controller` is the local composition boundary between verified recovery files and
the authenticated session lifecycle. It performs no network, provider, credential, or financial
work.

`verifySessionRecoveryArtifacts` invokes the state-evidence, sanitized-event-archive, and
signed-release-bundle verifiers. It then requires one profile, session, release manifest, backup
identity, and release signing-key fingerprint across all three results. Only a report created by
that successful verification path can be converted into lifecycle recovery evidence.

`verifyAndRecordLocalClosure` is the production composition path. It requires genuine operations,
capture-registry, Vault, event-store, alert-outbox, and session-coordinator instances. It runs
capture restart reconciliation, derives source closure from authenticated attempt aggregates,
requires an exact fully anchored event head, checks content-free alert state, and records either a
passing or explicitly failed local-verification transition. Its recovery evidence still comes only
from the three-component verifier above.

`recordVerifiedLocalClosure` is the lower-level closed-schema boundary used by the high-level
composer and focused tests. It derives the evidence hash itself; callers cannot submit replacement
recovery status strings or archive hashes through either path.

The remaining controller work is preflight composition, independently retained software evidence,
provider billing reconciliation, and the fixed 15-ticket source-plan ledger. Backup restore drills
may run into a fresh temporary directory on the existing computer. None of those conditions is
inferred by this package.
