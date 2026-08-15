# Observer session controller

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

The remaining controller work is preflight composition, independent external/MacBook verification,
provider billing reconciliation, the fixed 15-ticket source-plan ledger, and the physical two-copy
restore drill. None of those conditions is inferred by this package.
