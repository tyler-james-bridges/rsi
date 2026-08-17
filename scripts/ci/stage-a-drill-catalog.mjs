export const STAGE_A_DRILLS = Object.freeze([
  Object.freeze({
    id: "D01",
    evidencePath: "packages/x-collector/test/request-and-transport.test.ts",
    evidenceText: "refuses redirects and non-200 statuses",
  }),
  Object.freeze({
    id: "D02",
    evidencePath: "packages/x-collector/test/request-and-transport.test.ts",
    evidenceText: "exceeds the byte bound",
  }),
  Object.freeze({
    id: "D03",
    evidencePath: "packages/x-collector/test/request-and-transport.test.ts",
    evidenceText: "clock moves backward",
  }),
  Object.freeze({
    id: "D04",
    evidencePath: "packages/session-lifecycle/test/session-lifecycle.test.ts",
    evidenceText: "misses either required supervision acknowledgement",
  }),
  Object.freeze({
    id: "D05",
    evidencePath: "packages/session-lifecycle/test/session-lifecycle.test.ts",
    evidenceText: "invalidates every nonterminal session on reopen",
  }),
  Object.freeze({
    id: "D06",
    evidencePath: "packages/operations/test/sqlite-operations-store.test.ts",
    evidenceText: "recovers expired reservations as consumed aborts",
  }),
  Object.freeze({
    id: "D07",
    evidencePath: "packages/operations/test/sqlite-operations-store.test.ts",
    evidenceText: "rejects stale competing commits",
  }),
  Object.freeze({
    id: "D08",
    evidencePath: "packages/store/test/sqlite-event-store.test.ts",
    evidenceText: "detects deletion of the chain tail",
  }),
  Object.freeze({
    id: "D09",
    evidencePath: "packages/checkpoints/test/checkpoints.test.ts",
    evidenceText: "detects valid suffix truncation",
  }),
  Object.freeze({
    id: "D10",
    evidencePath: "packages/external-anchor/test/verifier.test.ts",
    evidenceText: "detects gaps, forks, compliance downgrades, and pinned rollback",
  }),
  Object.freeze({
    id: "D11",
    evidencePath: "packages/alerts/test/alert-outbox.test.ts",
    evidenceText: "recovers crashed attempts after reopen",
  }),
  Object.freeze({
    id: "D12",
    evidencePath: "packages/event-archive/test/event-archive.test.ts",
    evidenceText: "transactionally reimports every exact event",
  }),
  Object.freeze({
    id: "D13",
    evidencePath: "packages/release-bundle/test/release-bundle.test.ts",
    evidenceText: "fully verifies before restore",
  }),
  Object.freeze({
    id: "D14",
    evidencePath: "packages/vault/test/snapshot-vault.test.ts",
    evidenceText: "crypto-shreds via the separate wrapped-DEK artifact",
  }),
  Object.freeze({
    id: "D15",
    evidencePath: "packages/capture-registry/test/sqlite-capture-registry.test.ts",
    evidenceText: "content-free idempotent tombstone",
  }),
  Object.freeze({
    id: "D16",
    evidencePath: "packages/public-projection/test/public-projection.test.ts",
    evidenceText: "returns exactly the closed UNVERIFIED report",
  }),
  Object.freeze({
    id: "D17",
    evidencePath: "packages/source-contracts/test/source-contracts.test.ts",
    evidenceText: "wrong chain, moved block, missing code, or false interface",
  }),
  Object.freeze({
    id: "D18",
    evidencePath: "apps/operator/test/server.test.ts",
    evidenceText: "rejects DNS-rebinding Host headers",
  }),
  Object.freeze({
    id: "D19",
    evidencePath: "packages/preflight/test/host.test.ts",
    evidenceText: "cannot resolve live credentials for the dev profile",
  }),
  Object.freeze({
    id: "D20",
    evidencePath: "packages/operations/test/sqlite-operations-store.test.ts",
    evidenceText: "serializes independent writers against the same hard cap",
  }),
]);
