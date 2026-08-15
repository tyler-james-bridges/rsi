import { types as utilTypes } from "node:util";

import { isAlertOutbox, type AlertOutbox } from "@rsi/alerts";
import { isSqliteCaptureRegistry, type SqliteCaptureRegistry } from "@rsi/capture-registry";
import { CheckpointVerifier, type CheckpointVerifierOptions } from "@rsi/checkpoints";
import { recoverCaptureStorage, type CaptureStorageRecoverySummaryV1 } from "@rsi/ingestion";
import {
  isSqliteOperationsStore,
  type SessionAttemptSummaryV1,
  type SourceAttemptGroupSummaryV1,
  type SqliteOperationsStore,
} from "@rsi/operations";
import {
  isSqliteSessionCoordinator,
  type SessionRecordV1,
  type SqliteSessionCoordinator,
} from "@rsi/session-lifecycle";
import { isSqliteEventStore, type SqliteEventStore } from "@rsi/store";
import { isSnapshotVault, type SnapshotVault } from "@rsi/vault";

import { isVerifiedSessionRecoveryArtifacts, recordVerifiedLocalClosure } from "./controller.js";
import { SessionControllerError } from "./errors.js";
import type {
  SessionLocalVerificationFactsV1,
  VerifiedSessionRecoveryArtifactsV1,
} from "./types.js";

export interface VerifyAndRecordLocalClosureOptions {
  readonly alertOutbox: AlertOutbox;
  readonly captureRegistry: SqliteCaptureRegistry;
  readonly checkpoint: CheckpointVerifierOptions;
  readonly coordinator: SqliteSessionCoordinator;
  readonly eventStore: SqliteEventStore;
  readonly operationsStore: SqliteOperationsStore;
  readonly recovery: VerifiedSessionRecoveryArtifactsV1;
  readonly sessionId: string;
  readonly vault: SnapshotVault;
  readonly verifiedAt: string;
}

export interface VerifiedLocalClosureResultV1 {
  readonly schemaVersion: 1;
  readonly captureRecovery: Readonly<CaptureStorageRecoverySummaryV1> | null;
  readonly record: Readonly<SessionRecordV1>;
  readonly sourceSummary: Readonly<SessionAttemptSummaryV1> | null;
}

/**
 * Derives every local acceptance fact available in Stage A from genuine authenticated stores.
 * Missing or failed evidence is recorded as a failed lifecycle transition; details are collapsed.
 */
export async function verifyAndRecordLocalClosure(
  optionsValue: VerifyAndRecordLocalClosureOptions,
): Promise<Readonly<VerifiedLocalClosureResultV1>> {
  const options = parseOptions(optionsValue);
  let checkpointVerifier: CheckpointVerifier;
  try {
    checkpointVerifier = new CheckpointVerifier(options.checkpoint);
  } catch {
    throw new SessionControllerError("INPUT_INVALID");
  }
  const session = options.coordinator.getSession(options.sessionId);
  if (
    session === undefined ||
    session.state !== "stopping" ||
    session.stoppedAt === null ||
    session.egressStatus !== "blocked" ||
    session.profile !== options.recovery.profile ||
    options.captureRegistry.getSessionStateSummary(options.sessionId).profile !== session.profile ||
    options.alertOutbox.profile !== session.profile
  ) {
    throw new SessionControllerError("RECOVERY_BINDING_MISMATCH");
  }

  let sourceSummary: Readonly<SessionAttemptSummaryV1> | null = null;
  try {
    const integrity = options.operationsStore.verifyIntegrity();
    if (integrity.valid) {
      sourceSummary = options.operationsStore.getSessionAttemptSummary(
        options.sessionId,
        session.profile,
      );
    }
  } catch {
    sourceSummary = null;
  }

  let captureRecovery: Readonly<CaptureStorageRecoverySummaryV1> | null = null;
  let purgePassed = false;
  try {
    captureRecovery = await recoverCaptureStorage({
      captureRegistry: options.captureRegistry,
      recoveredAt: options.verifiedAt,
      vault: options.vault,
    });
    const registryIntegrity = options.captureRegistry.verifyIntegrity();
    const state = options.captureRegistry.getSessionStateSummary(options.sessionId);
    purgePassed = registryIntegrity.valid && state.pending === 0 && state.committed === 0;
  } catch {
    captureRecovery = null;
    purgePassed = false;
  }

  let eventAndCheckpointPassed = false;
  try {
    const eventIntegrity = options.eventStore.verifyIntegrity();
    const checkpoint = checkpointVerifier.verify(options.eventStore);
    eventAndCheckpointPassed =
      eventIntegrity.valid &&
      checkpoint.valid &&
      checkpoint.status === "ANCHORED" &&
      checkpoint.unanchoredEventCount === 0;
  } catch {
    eventAndCheckpointPassed = false;
  }

  let alertHealthy = false;
  let incidentCount = 1;
  try {
    const integrity = options.alertOutbox.verifyIntegrity();
    const summary = options.alertOutbox.getSessionSummary(options.sessionId);
    alertHealthy =
      integrity.valid &&
      integrity.errors.length === 0 &&
      summary.states.pending === 0 &&
      summary.states.in_flight === 0 &&
      summary.states.exhausted === 0;
    incidentCount = summary.incidentCount;
  } catch {
    alertHealthy = false;
    incidentCount = 1;
  }

  const facts = localFacts({
    alertHealthy,
    eventAndCheckpointPassed,
    incidentCount,
    purgePassed,
    sourceSummary,
  });
  const record = recordVerifiedLocalClosure({
    coordinator: options.coordinator,
    facts,
    recovery: options.recovery,
    sessionId: options.sessionId,
    verifiedAt: options.verifiedAt,
  });
  return Object.freeze({ captureRecovery, record, schemaVersion: 1 as const, sourceSummary });
}

function localFacts(
  input: Readonly<{
    alertHealthy: boolean;
    eventAndCheckpointPassed: boolean;
    incidentCount: number;
    purgePassed: boolean;
    sourceSummary: Readonly<SessionAttemptSummaryV1> | null;
  }>,
): SessionLocalVerificationFactsV1 {
  const summary = input.sourceSummary;
  const crossProfileClean = summary !== null && summary.crossProfileAttemptCount === 0;
  const lane = (group: Readonly<SourceAttemptGroupSummaryV1> | undefined) =>
    crossProfileClean && sourceGroupClosed(group) ? "closed" : "failed";
  return {
    alertCheck: input.alertHealthy ? "healthy" : "failed",
    canonicalChain: lane(summary?.canonicalChain),
    digestIntegrity: input.eventAndCheckpointPassed ? "verified" : "failed",
    eventIntegrity: input.eventAndCheckpointPassed ? "verified" : "failed",
    explicitClose: "complete",
    incidentCount: input.incidentCount,
    localCheckpoint: input.eventAndCheckpointPassed ? "verified" : "failed",
    openSea: {
      rest: lane(summary?.openSea.rest),
      stream: lane(summary?.openSea.stream),
    },
    purge: {
      captureKeys: input.purgePassed ? "destroyed" : "failed",
      encryptedIndexes: input.purgePassed ? "clean" : "failed",
      orphanScan: input.purgePassed ? "clean" : "failed",
      rawCaptures: input.purgePassed ? "clean" : "failed",
    },
    schemaVersion: 1,
    xLanes: {
      contract: lane(summary?.xLanes.contract),
      discovery: lane(summary?.xLanes.discovery),
      marketplace: lane(summary?.xLanes.marketplace),
      official: lane(summary?.xLanes.official),
      security: lane(summary?.xLanes.security),
    },
  };
}

function sourceGroupClosed(group: Readonly<SourceAttemptGroupSummaryV1> | undefined): boolean {
  return (
    group !== undefined &&
    group.attemptCount > 0 &&
    group.closedCount === group.attemptCount &&
    group.succeededCount + group.emptyCount > 0
  );
}

function parseOptions(
  value: VerifyAndRecordLocalClosureOptions,
): Readonly<VerifyAndRecordLocalClosureOptions> {
  const record = exactRecord(value, [
    "alertOutbox",
    "captureRegistry",
    "checkpoint",
    "coordinator",
    "eventStore",
    "operationsStore",
    "recovery",
    "sessionId",
    "vault",
    "verifiedAt",
  ]);
  if (
    !isAlertOutbox(record.alertOutbox) ||
    !isSqliteCaptureRegistry(record.captureRegistry) ||
    !isSqliteSessionCoordinator(record.coordinator) ||
    !isSqliteEventStore(record.eventStore) ||
    !isSqliteOperationsStore(record.operationsStore) ||
    !isSnapshotVault(record.vault) ||
    !isVerifiedSessionRecoveryArtifacts(record.recovery) ||
    typeof record.sessionId !== "string" ||
    typeof record.verifiedAt !== "string" ||
    typeof record.recovery !== "object" ||
    record.recovery === null
  ) {
    throw new SessionControllerError("INPUT_INVALID");
  }
  const checkpoint = parseCheckpointOptions(record.checkpoint);
  return Object.freeze({
    alertOutbox: record.alertOutbox,
    captureRegistry: record.captureRegistry,
    checkpoint,
    coordinator: record.coordinator,
    eventStore: record.eventStore,
    operationsStore: record.operationsStore,
    recovery: record.recovery as VerifiedSessionRecoveryArtifactsV1,
    sessionId: record.sessionId,
    vault: record.vault,
    verifiedAt: record.verifiedAt,
  });
}

function parseCheckpointOptions(value: unknown): CheckpointVerifierOptions {
  const required = ["expectedKeyId", "expectedPublicKey", "expectedStoreId", "journalPath"];
  const record = exactRecord(
    value,
    typeof value === "object" && value !== null && Object.hasOwn(value, "trustedJournalHead")
      ? [...required, "trustedJournalHead"]
      : required,
  );
  return {
    expectedKeyId: record.expectedKeyId as string,
    expectedPublicKey: record.expectedPublicKey as CheckpointVerifierOptions["expectedPublicKey"],
    expectedStoreId: record.expectedStoreId as string,
    journalPath: record.journalPath as string,
    ...(Object.hasOwn(record, "trustedJournalHead")
      ? {
          trustedJournalHead: record.trustedJournalHead as NonNullable<
            CheckpointVerifierOptions["trustedJournalHead"]
          >,
        }
      : {}),
  };
}

function exactRecord(value: unknown, expectedKeys: readonly string[]): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    utilTypes.isProxy(value)
  ) {
    throw new SessionControllerError("INPUT_INVALID");
  }
  const keys = Reflect.ownKeys(value);
  const sorted = keys.filter((key): key is string => typeof key === "string").sort();
  const expected = [...expectedKeys].sort();
  if (
    sorted.length !== keys.length ||
    sorted.length !== expected.length ||
    sorted.some((key, index) => key !== expected[index])
  ) {
    throw new SessionControllerError("INPUT_INVALID");
  }
  const record: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of sorted) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw new SessionControllerError("INPUT_INVALID");
    }
    record[key] = descriptor.value;
  }
  return record;
}
