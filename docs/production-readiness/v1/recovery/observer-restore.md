# Observer sanitized recovery procedure

`RSI-RECOVERY-PROCEDURE-V1`

This procedure restores only a previously accepted Observer session from its three signed,
receipt-pinned recovery components. It does not restore credentials, raw captures, source indexes,
encrypted cursors, operations state, wrapping keys, per-capture keys, provider state, or execution
authority.

## Preconditions

- Observer is stopped and no egress or scheduled service is enabled.
- The restore target is a new, empty, operator-owned directory on an approved encrypted device.
- The retained state-evidence, event-archive, and release-bundle receipts and expected public keys
  come from the independent MacBook record, not from the files being restored.
- The expected profile, session, release manifest, signing-key fingerprint, event head, checkpoint
  head, and retention class are known before any destination is created.

## Procedure

1. `VERIFY-BEFORE-RESTORE`: verify all three complete files against their independently retained
   receipts and keys. Reject any mismatch, missing companion, unexpected file, predecessor gap,
   stale head, unsafe path, or unsupported schema without creating a destination.
2. Restore the signed release bundle and sanitized event archive into separate new directories.
   Never merge with or overwrite an existing tree.
3. Import the event archive into a genuine, genesis-empty event store in one exclusive transaction.
   Recompute every event hash and require the final count, sequence, and head to equal the signed
   state evidence.
4. Re-run exact-runtime, contract, secret, dependency, offline-drill, and release-inventory checks
   from the restored release. Keep provider and financial adapters unavailable.
5. `NO-SECRET-RESTORE`: prove the restored namespaces contain none of the excluded raw, identity,
   cursor, credential, private-key, operations-key, Vault-key, or per-capture-key classes.
6. `NEW-LINEAGE-REQUIRED`: create fresh local operations, cursor, Vault, capture-registry, alert,
   external-anchor-outbox, and session lineages. A recovered release or event head never revives
   prior ephemeral authority.
7. Run non-mutating preflight and the complete offline recovery drill. Record only content-free
   hashes, counts, statuses, timestamps, and the operator disposition.

## Exit

A successful restore proves that the sanitized accepted history and reviewed release are readable
and internally consistent. It does not authorize provisioning, commissioning, collection,
publication, payment, wallet use, or production activation. Any failed check leaves Observer
stopped and starts the applicable incident procedure.
