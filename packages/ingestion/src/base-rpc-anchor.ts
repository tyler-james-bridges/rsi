import { createHash } from "node:crypto";
import { types as utilTypes } from "node:util";

import {
  SqliteCaptureRegistry,
  type CommittedCaptureAttempt,
  type PendingCaptureAttempt,
} from "@rsi/capture-registry";
import {
  isBaseRpcAnchorCollector,
  isQuarantinedBaseRpcAnchorResponse,
  parseBaseRpcAnchorQuarantine,
  prepareBaseRpcAnchorCollectorRequest,
  type BaseRpcAnchorCollector,
  type QuarantinedBaseRpcAnchorResponse,
} from "@rsi/base-rpc-collector";
import {
  isNetworkAttemptDispatchReceipt,
  type DurableNetworkAttemptBinding,
} from "@rsi/operations";
import { SnapshotIntegrityError, type CaptureId } from "@rsi/vault";

import {
  BASE_RPC_ANCHOR_CONTRACT_VERSION,
  BASE_RPC_ANCHOR_URL,
  BASE_RPC_INGESTION_JSON_CONTENT_TYPES,
  BASE_RPC_INGESTION_LANE,
  BASE_RPC_INGESTION_OPERATION,
  BASE_RPC_INGESTION_REQUEST_FINGERPRINT,
  BASE_RPC_INGESTION_RESERVED_ATOMIC,
  BASE_RPC_INGESTION_SOURCE,
  BASE_RPC_INGESTION_SOURCE_PLANE,
  assertBaseRpcAnchorRequestIdentity,
} from "./base-rpc-anchor-contract.js";
import {
  acceptedBaseRpcAnchorProjection,
  appendBaseRpcAnchorProjection,
  assertBaseRpcAnchorAttemptContext,
  assertBaseRpcAnchorCaptureMetadata,
  assertBaseRpcAnchorNetworkBinding,
  assertBaseRpcAnchorProjectionMatchesCommit,
  assertBaseRpcAnchorStorageValues,
  baseRpcAnchorEventKey,
  boundBaseRpcAnchorVaultMediaType,
  parseBaseRpcAnchorContext,
  readBaseRpcAnchorDurableBinding,
  rebindBaseRpcAnchorAttempt,
  recoverBaseRpcAnchorFromStorage,
  rejectedBaseRpcAnchorProjection,
  resumeBaseRpcAnchorCommittedAttempt,
  sameBaseRpcAnchorIdentifiers,
  type BaseRpcAnchorCaptureProjection,
  type BaseRpcAnchorIngestionContext,
  type BaseRpcAnchorIngestionResult,
  type BaseRpcAnchorStorageDependencies,
} from "./base-rpc-anchor-storage.js";

export interface BaseRpcAnchorIngestionDependencies extends BaseRpcAnchorStorageDependencies {
  /** Required only while a pending attempt may perform the one authorized collection. */
  readonly collector?: BaseRpcAnchorCollector;
  /** Required only while a pending attempt may begin or commit. */
  readonly now?: () => string;
  /** Best-effort cancellation before or during collection; ignored after bytes arrive. */
  readonly signal?: AbortSignal;
}

const INGESTION_DEPENDENCY_KEYS = Object.freeze([
  "captureRegistry",
  "collector",
  "now",
  "operationsStore",
  "signal",
  "store",
  "vault",
] as const);
const REQUIRED_DEPENDENCY_KEYS = Object.freeze([
  "captureRegistry",
  "operationsStore",
  "store",
  "vault",
] as const);

function parseDependencies(value: unknown): Readonly<BaseRpcAnchorIngestionDependencies> {
  if (
    typeof value !== "object" ||
    value === null ||
    utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new TypeError("Base RPC ingestion dependencies must be a plain object");
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.some(
      (key) =>
        typeof key !== "string" || !(INGESTION_DEPENDENCY_KEYS as readonly string[]).includes(key),
    ) ||
    REQUIRED_DEPENDENCY_KEYS.some((key) => !keys.includes(key))
  ) {
    throw new TypeError("Base RPC ingestion dependencies are invalid");
  }
  const data = Object.create(null) as Record<string, unknown>;
  for (const key of keys) {
    if (typeof key !== "string") throw new TypeError("Base RPC ingestion dependencies are invalid");
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw new TypeError("Base RPC ingestion dependencies must be enumerable data properties");
    }
    data[key] = descriptor.value;
  }
  const storage: BaseRpcAnchorStorageDependencies = {
    captureRegistry: data.captureRegistry as BaseRpcAnchorStorageDependencies["captureRegistry"],
    operationsStore: data.operationsStore as BaseRpcAnchorStorageDependencies["operationsStore"],
    store: data.store as BaseRpcAnchorStorageDependencies["store"],
    vault: data.vault as BaseRpcAnchorStorageDependencies["vault"],
  };
  assertBaseRpcAnchorStorageValues(storage);
  if (data.now !== undefined && (typeof data.now !== "function" || utilTypes.isProxy(data.now))) {
    throw new TypeError("Base RPC ingestion clock is invalid");
  }
  if (
    data.signal !== undefined &&
    (utilTypes.isProxy(data.signal) || !(data.signal instanceof AbortSignal))
  ) {
    throw new TypeError("an authentic AbortSignal is required");
  }
  return Object.freeze({
    ...storage,
    ...(data.collector === undefined
      ? {}
      : { collector: data.collector as BaseRpcAnchorCollector }),
    ...(data.now === undefined ? {} : { now: data.now as () => string }),
    ...(data.signal === undefined ? {} : { signal: data.signal as AbortSignal }),
  });
}

function storageDependencies(
  dependencies: Readonly<BaseRpcAnchorIngestionDependencies>,
): Readonly<BaseRpcAnchorStorageDependencies> {
  return Object.freeze({
    captureRegistry: dependencies.captureRegistry,
    operationsStore: dependencies.operationsStore,
    store: dependencies.store,
    vault: dependencies.vault,
  });
}

function readNow(
  dependencies: Readonly<BaseRpcAnchorIngestionDependencies>,
  label: string,
): string {
  if (typeof dependencies.now !== "function") {
    throw new Error("an explicit ingestion clock is required");
  }
  const value = dependencies.now();
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) ||
    !Number.isFinite(Date.parse(value)) ||
    new Date(Date.parse(value)).toISOString() !== value
  ) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

function sha256(value: Uint8Array): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function assertCollectorBinding(
  collector: BaseRpcAnchorCollector,
  context: BaseRpcAnchorIngestionContext,
): void {
  if (!isBaseRpcAnchorCollector(collector)) {
    throw new Error("an authentic Base RPC anchor collector is required");
  }
  assertBaseRpcAnchorNetworkBinding(collector.attemptBinding, context);
}

function beginNewAttempt(
  dependencies: Readonly<BaseRpcAnchorIngestionDependencies>,
  context: BaseRpcAnchorIngestionContext,
): PendingCaptureAttempt | CommittedCaptureAttempt {
  const begunAt = readNow(dependencies, "Base RPC ingestion begin time");
  const attempt = dependencies.captureRegistry.beginAttempt({
    acquiredAt: begunAt,
    attemptId: context.attemptId,
    expiresAt: context.expiresAt,
    lane: BASE_RPC_INGESTION_LANE,
    profile: context.profile,
    requestFingerprint: BASE_RPC_INGESTION_REQUEST_FINGERPRINT,
    sessionId: context.sessionId,
    source: BASE_RPC_INGESTION_SOURCE,
  });
  if (attempt.state === "removed") throw new Error("capture attempt is terminal");
  assertBaseRpcAnchorAttemptContext(attempt, context);
  return attempt;
}

function assertResponseBinding(
  response: QuarantinedBaseRpcAnchorResponse,
  attempt: PendingCaptureAttempt | CommittedCaptureAttempt,
  context: BaseRpcAnchorIngestionContext,
  durable: Readonly<DurableNetworkAttemptBinding>,
): void {
  const dispatched = response.metadata.networkAttempt;
  if (
    !isNetworkAttemptDispatchReceipt(dispatched) ||
    response.metadata.contractVersion !== BASE_RPC_ANCHOR_CONTRACT_VERSION ||
    response.metadata.endpoint !== BASE_RPC_ANCHOR_URL ||
    response.metadata.requestFingerprint !== BASE_RPC_INGESTION_REQUEST_FINGERPRINT ||
    !(BASE_RPC_INGESTION_JSON_CONTENT_TYPES as readonly string[]).includes(
      response.metadata.contentType,
    ) ||
    dispatched.dispatchedAt !== durable.dispatchedAt ||
    dispatched.binding.attemptId !== context.attemptId ||
    dispatched.binding.attemptId !== durable.attemptId ||
    dispatched.binding.authorizationExpiresAt !== context.expiresAt ||
    dispatched.binding.authorizationExpiresAt !== durable.authorizationExpiresAt ||
    dispatched.binding.lane !== BASE_RPC_INGESTION_LANE ||
    dispatched.binding.lane !== durable.lane ||
    dispatched.binding.operation !== BASE_RPC_INGESTION_OPERATION ||
    dispatched.binding.operation !== durable.operation ||
    dispatched.binding.profile !== context.profile ||
    dispatched.binding.profile !== durable.profile ||
    dispatched.binding.reservedAtomic !== BASE_RPC_INGESTION_RESERVED_ATOMIC ||
    dispatched.binding.reservedAtomic !== durable.reservedAtomic ||
    dispatched.binding.sessionId !== context.sessionId ||
    dispatched.binding.sessionId !== durable.sessionId ||
    dispatched.binding.sourcePlane !== BASE_RPC_INGESTION_SOURCE_PLANE ||
    dispatched.binding.sourcePlane !== durable.sourcePlane
  ) {
    throw new Error("quarantined response does not match its authorized Base RPC dispatch");
  }
  const begun = Date.parse(attempt.acquiredAt);
  const acquired = Date.parse(response.metadata.acquiredAt);
  const expires = Date.parse(context.expiresAt);
  if (acquired < begun || acquired > expires || expires - acquired > 2 * 60 * 60 * 1_000) {
    throw new Error("capture acquisition is outside its authorized window");
  }
}

function projectResponse(
  response: QuarantinedBaseRpcAnchorResponse,
): Readonly<BaseRpcAnchorCaptureProjection> {
  try {
    return acceptedBaseRpcAnchorProjection(parseBaseRpcAnchorQuarantine(response).anchor);
  } catch {
    return rejectedBaseRpcAnchorProjection();
  }
}

async function assertResponseMatchesCommittedCapture(
  dependencies: Readonly<BaseRpcAnchorStorageDependencies>,
  attempt: CommittedCaptureAttempt,
  response: QuarantinedBaseRpcAnchorResponse,
  binding: Readonly<DurableNetworkAttemptBinding>,
): Promise<void> {
  const capture = await dependencies.vault.get(attempt.captureId);
  try {
    assertBaseRpcAnchorCaptureMetadata(capture.metadata, capture.size, attempt, binding);
    if (
      capture.metadata.acquiredAt !== response.metadata.acquiredAt ||
      capture.metadata.mediaType !==
        boundBaseRpcAnchorVaultMediaType(response.metadata.contentType, binding) ||
      capture.size !== response.metadata.byteLength ||
      sha256(capture.bytes) !== response.metadata.responseHash
    ) {
      throw new Error("concurrent response does not match the committed Base RPC capture");
    }
  } finally {
    capture.bytes.fill(0);
  }
}

async function deleteUncommittedCapture(
  dependencies: Readonly<BaseRpcAnchorStorageDependencies>,
  captureId: CaptureId,
  acquiredAt: string,
  primaryError: unknown,
): Promise<never> {
  try {
    await dependencies.vault.delete(captureId, { deletedAt: acquiredAt, reason: "explicit" });
  } catch (cleanupError) {
    throw new AggregateError(
      [primaryError, cleanupError],
      "Base RPC ingestion failed and the uncommitted capture could not be crypto-shredded",
    );
  }
  throw primaryError;
}

async function captureAndCommit(
  dependencies: Readonly<BaseRpcAnchorIngestionDependencies>,
  context: BaseRpcAnchorIngestionContext,
  attempt: PendingCaptureAttempt,
  response: QuarantinedBaseRpcAnchorResponse,
  binding: Readonly<DurableNetworkAttemptBinding>,
): Promise<Readonly<BaseRpcAnchorIngestionResult>> {
  const storage = storageDependencies(dependencies);
  const bytes = response.copyBytes();
  let captureId: CaptureId | undefined;
  let committed = false;
  let commitOutcomeAmbiguous = false;
  try {
    if (sha256(bytes) !== response.metadata.responseHash) {
      throw new Error("quarantined response failed its capture boundary");
    }
    const capture = await dependencies.vault.capture(bytes, {
      metadata: {
        acquiredAt: response.metadata.acquiredAt,
        expiresAt: context.expiresAt,
        mediaType: boundBaseRpcAnchorVaultMediaType(response.metadata.contentType, binding),
        schemaVersion: 1,
        source: BASE_RPC_INGESTION_SOURCE,
      },
    });
    captureId = capture.captureId;
    if (sha256(bytes) !== response.metadata.responseHash) {
      throw new Error("quarantined response failed its capture boundary");
    }

    // Provider bytes cross the encrypted Vault boundary before source parsing.
    const projection = projectResponse(response);
    const committedAt = readNow(dependencies, "Base RPC ingestion commit time");
    if (
      Date.parse(committedAt) < Date.parse(response.metadata.acquiredAt) ||
      Date.parse(committedAt) > Date.parse(context.expiresAt)
    ) {
      throw new Error("capture commit is outside its authorized window");
    }

    let committedAttempt: CommittedCaptureAttempt;
    try {
      const result = dependencies.captureRegistry.commitCapture({
        attemptId: context.attemptId,
        captureId,
        committedAt,
        sourceIdentifiers: projection.sourceIdentifiers,
      });
      if (result.state !== "committed") throw new Error("capture commit did not become durable");
      committedAttempt = result;
      committed = true;
    } catch (error) {
      let winner;
      try {
        winner = dependencies.captureRegistry.getAttempt(context.attemptId);
      } catch {
        commitOutcomeAmbiguous = true;
        throw error;
      }
      if (winner?.state === "committed") {
        assertBaseRpcAnchorAttemptContext(winner, context);
        if (winner.captureId === captureId) {
          committed = true;
          if (
            winner.committedAt !== committedAt ||
            !sameBaseRpcAnchorIdentifiers(winner.sourceIdentifiers, projection.sourceIdentifiers)
          ) {
            throw new SnapshotIntegrityError();
          }
          committedAttempt = winner;
        } else {
          await assertResponseMatchesCommittedCapture(storage, winner, response, binding);
          await dependencies.vault.delete(captureId, {
            deletedAt: response.metadata.acquiredAt,
            reason: "explicit",
          });
          captureId = undefined;
          assertBaseRpcAnchorProjectionMatchesCommit(projection, winner);
          return resumeBaseRpcAnchorCommittedAttempt(
            storage,
            context,
            winner,
            binding,
            binding.dispatchedAt ?? undefined,
          );
        }
      } else {
        throw error;
      }
    }

    assertBaseRpcAnchorProjectionMatchesCommit(projection, committedAttempt);
    return appendBaseRpcAnchorProjection(
      storage,
      context,
      response.metadata.acquiredAt,
      response.metadata.byteLength,
      projection,
    );
  } catch (error) {
    if (captureId !== undefined && !committed && !commitOutcomeAmbiguous) {
      return deleteUncommittedCapture(storage, captureId, response.metadata.acquiredAt, error);
    }
    throw error;
  } finally {
    bytes.fill(0);
  }
}

/**
 * Bind the fixed two-method Base request before egress, encrypt raw bytes before
 * parsing, and persist only a provider-reported-finalized block-number handle
 * in the authenticated private registry plus a content-free event.
 */
export async function ingestBaseRpcAnchor(
  dependenciesInput: Readonly<BaseRpcAnchorIngestionDependencies>,
  contextInput: unknown,
): Promise<Readonly<BaseRpcAnchorIngestionResult>> {
  if (arguments.length !== 2) {
    throw new Error("Base RPC anchor ingestion accepts no request input");
  }
  const dependencies = parseDependencies(dependenciesInput);
  const context = parseBaseRpcAnchorContext(contextInput);
  const storage = storageDependencies(dependencies);
  const request = prepareBaseRpcAnchorCollectorRequest();
  assertBaseRpcAnchorRequestIdentity(request);

  const existingEvent = dependencies.store.getByIdempotencyKey(
    baseRpcAnchorEventKey(context.attemptId),
  );
  const existingAttempt = dependencies.captureRegistry.getAttempt(context.attemptId);
  if (existingAttempt === undefined && existingEvent !== undefined) {
    throw new Error("capture event exists without its authenticated registry record");
  }
  if (existingAttempt?.state === "removed" || existingAttempt?.state === "committed") {
    return recoverBaseRpcAnchorFromStorage(storage, context);
  }
  if (existingEvent !== undefined) {
    throw new Error("capture event exists before its registry commit");
  }

  const collector = dependencies.collector;
  if (!isBaseRpcAnchorCollector(collector)) {
    throw new Error("an authentic Base RPC anchor collector is required before collection");
  }
  assertCollectorBinding(collector, context);
  readBaseRpcAnchorDurableBinding(storage, context, "pre-egress");
  const attempt =
    existingAttempt === undefined
      ? beginNewAttempt(dependencies, context)
      : rebindBaseRpcAnchorAttempt(dependencies.captureRegistry, existingAttempt, context);
  if (attempt.state !== "pending") throw new SnapshotIntegrityError();

  let response: QuarantinedBaseRpcAnchorResponse | undefined;
  try {
    response = await collector.collectRaw(
      dependencies.signal === undefined ? undefined : { signal: dependencies.signal },
    );
    if (!isQuarantinedBaseRpcAnchorResponse(response)) {
      throw new Error("collector returned an invalid Base RPC quarantine object");
    }
    const durable = readBaseRpcAnchorDurableBinding(storage, context, "post-response");
    assertResponseBinding(response, attempt, context, durable);
    if (
      durable.dispatchedAt === null ||
      Date.parse(durable.dispatchedAt) < Date.parse(attempt.acquiredAt) ||
      Date.parse(durable.dispatchedAt) > Date.parse(response.metadata.acquiredAt)
    ) {
      throw new Error("network dispatch is outside its Base RPC capture window");
    }

    const current = dependencies.captureRegistry.getAttempt(context.attemptId);
    if (current?.state === "committed") {
      assertBaseRpcAnchorAttemptContext(current, context);
      await assertResponseMatchesCommittedCapture(storage, current, response, durable);
      const projection = projectResponse(response);
      assertBaseRpcAnchorProjectionMatchesCommit(projection, current);
      return resumeBaseRpcAnchorCommittedAttempt(
        storage,
        context,
        current,
        durable,
        durable.dispatchedAt,
      );
    }
    if (current?.state !== "pending") throw new Error("capture attempt became terminal");
    return await captureAndCommit(dependencies, context, current, response, durable);
  } finally {
    response?.destroy();
  }
}

export type {
  BaseRpcAnchorCaptureStatus,
  BaseRpcAnchorIngestionContext,
  BaseRpcAnchorIngestionResult,
  BaseRpcAnchorStorageDependencies,
} from "./base-rpc-anchor-storage.js";
