# Sanitized state-evidence component

`@rsi/backup` creates, verifies, and restores a closed, content-free observer
state-**evidence** component of an RSI recovery backup. It accepts typed evidence
only; it never crawls a directory, copies a database, or accepts generic
artifact bytes.

This component is deliberately **not** a complete OBS-REC-003 recovery bundle.
Its event count/head is not an event archive, and its recovery/release hashes do
not make event records, code, or runbook documentation bytes restorable. Every
manifest, independent receipt, and verification report therefore says
`evidence-only` and requires both a separately produced
`sanitized-event-archive` and a `signed-release-bundle`. Session state
`acceptance-ready` identifies the pre-commit component, while `accepted`
identifies a later post-commit evidence archive. This package does not make the
cross-store acceptance transition atomic and does not close that transition's
RPO window. No session acceptance controller may treat this component alone as
restorable state.

The archive contains exactly seven roles: content-free event-state evidence, the
signed checkpoint journal and head, public keys, closed config-schema hashes,
recovery evidence, and release evidence. Raw Vault bodies or DEKs, capture
indexes, operations databases/cursors/budgets/state keys, credentials,
environment files, WAL/SHM files, source/provider identifiers, and arbitrary
content have no input field or artifact role.
