import { createHash } from "node:crypto";
import { types as utilTypes } from "node:util";

import {
  SqliteCaptureRegistry,
  isSqliteCaptureRegistry,
  type CaptureSourceIdentifiers,
  type CommittedCaptureAttempt,
  type PendingCaptureAttempt,
} from "@rsi/capture-registry";
import {
  CAPTURE_RECORDED_EVENT_TYPE,
  CanonicalTimestampSchema,
  OperationsProfileSchema,
  SqliteOperationsStore,
  UuidSchema,
  appendCaptureRecordedEvent,
  isSqliteOperationsStore,
  parseCaptureRecordedEventPayload,
  parseWithSchema,
  type DurableNetworkAttemptBinding,
  type OperationsProfile,
} from "@rsi/operations";
import {
  isBaseRpcFinalizedAnchor,
  parseBaseRpcFinalizedAnchor,
} from "@rsi/source-contracts/base-rpc-anchor";
import { isSqliteEventStore, type SqliteEventStore, type StoredEvent } from "@rsi/store";
import { SnapshotIntegrityError, isSnapshotVault, type SnapshotVault } from "@rsi/vault";
import { z } from "zod";

import {
  BASE_RPC_ANCHOR_CONTRACT_VERSION,
  BASE_RPC_INGESTION_ADAPTER_ID,
  BASE_RPC_INGESTION_JSON_CONTENT_TYPES,
  BASE_RPC_INGESTION_LANE,
  BASE_RPC_INGESTION_OPERATION,
  BASE_RPC_INGESTION_REQUEST_BODY,
  BASE_RPC_INGESTION_REQUEST_FINGERPRINT,
  BASE_RPC_INGESTION_RESERVED_ATOMIC,
  BASE_RPC_INGESTION_SOURCE,
  BASE_RPC_INGESTION_SOURCE_PLANE,
} from "./base-rpc-anchor-contract.js";

export type BaseRpcAnchorCaptureStatus = "accepted" | "rejected";

export interface BaseRpcAnchorIngestionContext {
  readonly attemptId: string;
  readonly expiresAt: string;
  readonly lane: typeof BASE_RPC_INGESTION_LANE;
  readonly profile: OperationsProfile;
  readonly sessionId: string;
}

export interface BaseRpcAnchorStorageDependencies {
  readonly captureRegistry: SqliteCaptureRegistry;
  readonly operationsStore: SqliteOperationsStore;
  readonly store: SqliteEventStore;
  readonly vault: SnapshotVault;
}

export interface BaseRpcAnchorBindingIdentity {
  readonly attemptId: string;
  readonly authorizationExpiresAt: string;
  readonly lane: string;
  readonly operation: string;
  readonly profile: OperationsProfile;
  readonly reservedAtomic: string;
  readonly sessionId: string;
  readonly sourcePlane: string;
}

/** Contains no block number, hash, parent hash, provider body, or opaque capture handle. */
export interface BaseRpcAnchorIngestionResult {
  readonly acquiredAt: string;
  readonly adapterId: typeof BASE_RPC_INGESTION_ADAPTER_ID;
  readonly anchorCount: 1 | null;
  readonly byteLength: number;
  readonly expiresAt: string;
  readonly failureCode: "INVALID_RESPONSE_SCHEMA" | null;
  /** This is only the provider's response to the `finalized` tag, not independent finality proof. */
  readonly providerReportedFinalized: true | null;
  readonly status: BaseRpcAnchorCaptureStatus;
}

export interface BaseRpcAnchorCaptureProjection {
  readonly anchorCount: 1 | null;
  readonly failureCode: "INVALID_RESPONSE_SCHEMA" | null;
  readonly providerReportedFinalized: true | null;
  readonly sourceIdentifiers: Extract<
    CaptureSourceIdentifiers,
    { readonly source: typeof BASE_RPC_INGESTION_SOURCE }
  >;
  readonly status: BaseRpcAnchorCaptureStatus;
}

const BaseRpcAnchorIngestionContextSchema = z.strictObject({
  attemptId: UuidSchema,
  expiresAt: CanonicalTimestampSchema,
  lane: z.literal(BASE_RPC_INGESTION_LANE),
  profile: OperationsProfileSchema,
  sessionId: UuidSchema,
});

const STORAGE_DEPENDENCY_KEYS = Object.freeze([
  "captureRegistry",
  "operationsStore",
  "store",
  "vault",
] as const);

const VAULT_PROVENANCE_PARAMETER = "rsi-provenance" as const;

export function parseBaseRpcAnchorContext(value: unknown): BaseRpcAnchorIngestionContext {
  return parseWithSchema(
    BaseRpcAnchorIngestionContextSchema,
    value,
    "Base RPC anchor ingestion context",
  );
}

export function assertBaseRpcAnchorStorageValues(
  dependencies: Readonly<BaseRpcAnchorStorageDependencies>,
): void {
  if (!isSqliteCaptureRegistry(dependencies.captureRegistry)) {
    throw new Error("an authenticated capture registry is required");
  }
  if (!isSqliteOperationsStore(dependencies.operationsStore)) {
    throw new Error("Base RPC ingestion requires its authenticated operations store");
  }
  if (!isSqliteEventStore(dependencies.store)) {
    throw new Error("an authenticated event store is required");
  }
  if (!isSnapshotVault(dependencies.vault)) {
    throw new Error("an authenticated snapshot vault is required");
  }
}

export function parseBaseRpcAnchorStorageDependencies(
  value: unknown,
): Readonly<BaseRpcAnchorStorageDependencies> {
  if (
    typeof value !== "object" ||
    value === null ||
    utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new TypeError("Base RPC recovery dependencies must be a plain object");
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== STORAGE_DEPENDENCY_KEYS.length ||
    keys.some(
      (key) =>
        typeof key !== "string" || !(STORAGE_DEPENDENCY_KEYS as readonly string[]).includes(key),
    )
  ) {
    throw new TypeError("Base RPC recovery accepts storage dependencies only");
  }
  const parsed = Object.create(null) as Record<(typeof STORAGE_DEPENDENCY_KEYS)[number], unknown>;
  for (const key of STORAGE_DEPENDENCY_KEYS) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw new TypeError("Base RPC recovery dependencies must be enumerable data properties");
    }
    parsed[key] = descriptor.value;
  }
  const dependencies: BaseRpcAnchorStorageDependencies = {
    captureRegistry: parsed.captureRegistry as SqliteCaptureRegistry,
    operationsStore: parsed.operationsStore as SqliteOperationsStore,
    store: parsed.store as SqliteEventStore,
    vault: parsed.vault as SnapshotVault,
  };
  assertBaseRpcAnchorStorageValues(dependencies);
  return Object.freeze(dependencies);
}

export function baseRpcAnchorEventKey(attemptId: string): string {
  return `capture-recorded-v2:${attemptId}`;
}

export function assertBaseRpcAnchorNetworkBinding(
  binding: Readonly<BaseRpcAnchorBindingIdentity>,
  context: BaseRpcAnchorIngestionContext,
): void {
  if (
    binding.attemptId !== context.attemptId ||
    binding.authorizationExpiresAt !== context.expiresAt ||
    binding.lane !== BASE_RPC_INGESTION_LANE ||
    binding.operation !== BASE_RPC_INGESTION_OPERATION ||
    binding.profile !== context.profile ||
    binding.reservedAtomic !== BASE_RPC_INGESTION_RESERVED_ATOMIC ||
    binding.sessionId !== context.sessionId ||
    binding.sourcePlane !== BASE_RPC_INGESTION_SOURCE_PLANE
  ) {
    throw new Error("Base RPC ingestion context does not match its reserved network attempt");
  }
}

export function readBaseRpcAnchorDurableBinding(
  dependencies: Readonly<BaseRpcAnchorStorageDependencies>,
  context: BaseRpcAnchorIngestionContext,
  phase: "committed-resume" | "post-response" | "pre-egress",
): Readonly<DurableNetworkAttemptBinding> {
  const binding = dependencies.operationsStore.readNetworkAttemptBinding(context.attemptId);
  assertBaseRpcAnchorNetworkBinding(binding, context);
  const validState =
    phase === "pre-egress"
      ? binding.state === "reserved" && binding.dispatchedAt === null
      : phase === "post-response"
        ? binding.state === "dispatched" && binding.dispatchedAt !== null
        : (binding.state === "dispatched" || binding.state === "closed") &&
          binding.dispatchedAt !== null;
  if (!validState) throw new Error(`network attempt is not valid for ${phase}`);
  return binding;
}

export function assertBaseRpcAnchorAttemptContext(
  attempt: PendingCaptureAttempt | CommittedCaptureAttempt,
  context: BaseRpcAnchorIngestionContext,
): void {
  if (
    attempt.expiresAt !== context.expiresAt ||
    attempt.lane !== BASE_RPC_INGESTION_LANE ||
    attempt.profile !== context.profile ||
    attempt.requestFingerprint !== BASE_RPC_INGESTION_REQUEST_FINGERPRINT ||
    attempt.sessionId !== context.sessionId ||
    attempt.source !== BASE_RPC_INGESTION_SOURCE
  ) {
    throw new Error("capture attempt does not match the Base RPC ingestion context");
  }
}

export function rebindBaseRpcAnchorAttempt(
  registry: SqliteCaptureRegistry,
  attempt: PendingCaptureAttempt | CommittedCaptureAttempt,
  context: BaseRpcAnchorIngestionContext,
): PendingCaptureAttempt | CommittedCaptureAttempt {
  const rebound = registry.beginAttempt({
    acquiredAt: attempt.acquiredAt,
    attemptId: context.attemptId,
    expiresAt: context.expiresAt,
    lane: BASE_RPC_INGESTION_LANE,
    profile: context.profile,
    requestFingerprint: BASE_RPC_INGESTION_REQUEST_FINGERPRINT,
    sessionId: context.sessionId,
    source: BASE_RPC_INGESTION_SOURCE,
  });
  if (rebound.state === "removed") throw new Error("capture attempt is terminal");
  assertBaseRpcAnchorAttemptContext(rebound, context);
  return rebound;
}

export function boundBaseRpcAnchorVaultMediaType(
  providerContentType: string,
  binding: Readonly<DurableNetworkAttemptBinding>,
): string {
  if (
    binding.dispatchedAt === null ||
    !(BASE_RPC_INGESTION_JSON_CONTENT_TYPES as readonly string[]).includes(providerContentType)
  ) {
    throw new SnapshotIntegrityError();
  }
  const canonical = [
    "rsi.base-rpc-anchor.capture-provenance.v1",
    BASE_RPC_INGESTION_REQUEST_FINGERPRINT,
    BASE_RPC_ANCHOR_CONTRACT_VERSION,
    BASE_RPC_INGESTION_REQUEST_BODY,
    providerContentType,
    binding.attemptId,
    binding.authorizationExpiresAt,
    binding.dispatchedAt,
    binding.lane,
    binding.operation,
    binding.profile,
    binding.reservedAtomic,
    binding.sessionId,
    binding.sourcePlane,
  ].join("\n");
  const digest = createHash("sha256").update(canonical, "utf8").digest("hex");
  return `${providerContentType};${VAULT_PROVENANCE_PARAMETER}=${digest}`;
}

function isExpectedBoundVaultMediaType(
  value: string,
  binding: Readonly<DurableNetworkAttemptBinding>,
): boolean {
  return (BASE_RPC_INGESTION_JSON_CONTENT_TYPES as readonly string[]).some(
    (contentType) => value === boundBaseRpcAnchorVaultMediaType(contentType, binding),
  );
}

function emptyAlchemyIdentifiers(): Extract<
  CaptureSourceIdentifiers,
  { readonly source: typeof BASE_RPC_INGESTION_SOURCE }
> {
  return Object.freeze({ identifiers: Object.freeze([]), source: BASE_RPC_INGESTION_SOURCE });
}

export function acceptedBaseRpcAnchorProjection(
  anchor: unknown,
): Readonly<BaseRpcAnchorCaptureProjection> {
  if (
    !isBaseRpcFinalizedAnchor(anchor) ||
    anchor.chainId !== "8453" ||
    anchor.network !== "base-mainnet" ||
    anchor.providerReportedFinalized !== true ||
    !/^(?:0|[1-9][0-9]{0,77})$/.test(anchor.blockNumber)
  ) {
    throw new Error("an authentic provider-reported Base finalized anchor is required");
  }
  return Object.freeze({
    anchorCount: 1 as const,
    failureCode: null,
    providerReportedFinalized: true as const,
    sourceIdentifiers: Object.freeze({
      identifiers: Object.freeze([
        Object.freeze({ kind: "block_number" as const, value: anchor.blockNumber }),
      ]),
      source: BASE_RPC_INGESTION_SOURCE,
    }),
    status: "accepted" as const,
  });
}

export function rejectedBaseRpcAnchorProjection(): Readonly<BaseRpcAnchorCaptureProjection> {
  return Object.freeze({
    anchorCount: null,
    failureCode: "INVALID_RESPONSE_SCHEMA" as const,
    providerReportedFinalized: null,
    sourceIdentifiers: emptyAlchemyIdentifiers(),
    status: "rejected" as const,
  });
}

function projectRecoveredCapture(
  bytes: Uint8Array,
  acquiredAt: string,
): BaseRpcAnchorCaptureProjection {
  try {
    return acceptedBaseRpcAnchorProjection(parseBaseRpcFinalizedAnchor(bytes, acquiredAt));
  } catch {
    return rejectedBaseRpcAnchorProjection();
  }
}

export function sameBaseRpcAnchorIdentifiers(
  left: CaptureSourceIdentifiers,
  right: CaptureSourceIdentifiers,
): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

export function assertBaseRpcAnchorProjectionMatchesCommit(
  projection: BaseRpcAnchorCaptureProjection,
  attempt: CommittedCaptureAttempt,
): void {
  if (!sameBaseRpcAnchorIdentifiers(projection.sourceIdentifiers, attempt.sourceIdentifiers)) {
    throw new SnapshotIntegrityError();
  }
}

function resultFromEvent(
  event: StoredEvent,
  context: BaseRpcAnchorIngestionContext,
): Readonly<BaseRpcAnchorIngestionResult> {
  if (
    event.aggregateId !== `session:${context.sessionId}` ||
    event.idempotencyKey !== baseRpcAnchorEventKey(context.attemptId) ||
    event.type !== CAPTURE_RECORDED_EVENT_TYPE
  ) {
    throw new Error("stored capture event does not match its attempt");
  }
  const { capture } = parseCaptureRecordedEventPayload(event.payload);
  if (
    capture.attemptId !== context.attemptId ||
    capture.expiresAt !== context.expiresAt ||
    capture.lane !== BASE_RPC_INGESTION_LANE ||
    capture.profile !== context.profile ||
    capture.sessionId !== context.sessionId ||
    capture.sourcePlane !== BASE_RPC_INGESTION_SOURCE_PLANE ||
    event.occurredAt !== capture.acquiredAt
  ) {
    throw new Error("stored capture event does not match its Base RPC ingestion context");
  }
  if (
    capture.status === "accepted" &&
    (capture.counts?.actorCount !== 0 ||
      capture.counts.editedRecordCount !== 0 ||
      capture.counts.recordCount !== 1)
  ) {
    throw new Error("stored capture event contains unsupported Base RPC projection counts");
  }
  if (capture.failureCode !== null && capture.failureCode !== "INVALID_RESPONSE_SCHEMA") {
    throw new Error("stored capture event contains an unsupported Base RPC failure code");
  }
  return Object.freeze({
    acquiredAt: capture.acquiredAt,
    adapterId: BASE_RPC_INGESTION_ADAPTER_ID,
    anchorCount: capture.status === "accepted" ? (1 as const) : null,
    byteLength: capture.byteLength,
    expiresAt: capture.expiresAt,
    failureCode: capture.failureCode,
    providerReportedFinalized: capture.status === "accepted" ? (true as const) : null,
    status: capture.status,
  });
}

function assertEventMatchesCommit(
  event: StoredEvent,
  context: BaseRpcAnchorIngestionContext,
  attempt: CommittedCaptureAttempt,
  minimumAcquiredAt?: string,
): Readonly<BaseRpcAnchorIngestionResult> {
  const result = resultFromEvent(event, context);
  const identifiers = attempt.sourceIdentifiers;
  if (
    identifiers.source !== BASE_RPC_INGESTION_SOURCE ||
    identifiers.identifiers.some((identifier) => identifier.kind !== "block_number") ||
    Date.parse(result.acquiredAt) < Date.parse(attempt.acquiredAt) ||
    Date.parse(result.acquiredAt) > Date.parse(attempt.committedAt) ||
    (minimumAcquiredAt !== undefined &&
      Date.parse(result.acquiredAt) < Date.parse(minimumAcquiredAt)) ||
    (result.status === "accepted" && identifiers.identifiers.length !== 1) ||
    (result.status === "rejected" && identifiers.identifiers.length !== 0)
  ) {
    throw new Error("stored capture event does not match its committed Base RPC capture");
  }
  return result;
}

function assertResultMatchesClosedAttempt(
  result: Readonly<BaseRpcAnchorIngestionResult>,
  binding: Readonly<DurableNetworkAttemptBinding>,
): void {
  if (binding.state !== "closed") return;
  // A parsed capture can still close as failed when the retained runtime
  // completion guard loses to STOP. Storage-only recovery cannot distinguish
  // that later runtime verdict, so accepted capture evidence permits either
  // succeeded or failed while rejected capture evidence permits only failed.
  const outcomeMatches =
    result.status === "accepted"
      ? binding.outcome === "succeeded" || binding.outcome === "failed"
      : binding.outcome === "failed";
  if (
    !outcomeMatches ||
    binding.closedAt === null ||
    Date.parse(binding.closedAt) < Date.parse(result.acquiredAt)
  ) {
    throw new SnapshotIntegrityError();
  }
}

export function assertBaseRpcAnchorCaptureMetadata(
  metadata: Readonly<{
    acquiredAt: string;
    expiresAt: string;
    mediaType: string;
    schemaVersion: number;
    source: string;
  }>,
  size: number,
  attempt: CommittedCaptureAttempt,
  binding: Readonly<DurableNetworkAttemptBinding>,
  eventResult?: BaseRpcAnchorIngestionResult,
  minimumAcquiredAt?: string,
): void {
  if (
    metadata.schemaVersion !== 1 ||
    metadata.source !== BASE_RPC_INGESTION_SOURCE ||
    metadata.expiresAt !== attempt.expiresAt ||
    Date.parse(metadata.acquiredAt) < Date.parse(attempt.acquiredAt) ||
    Date.parse(metadata.acquiredAt) > Date.parse(attempt.committedAt) ||
    Date.parse(metadata.acquiredAt) > Date.parse(attempt.expiresAt) ||
    (minimumAcquiredAt !== undefined &&
      Date.parse(metadata.acquiredAt) < Date.parse(minimumAcquiredAt)) ||
    !isExpectedBoundVaultMediaType(metadata.mediaType, binding) ||
    (eventResult !== undefined &&
      (metadata.acquiredAt !== eventResult.acquiredAt || size !== eventResult.byteLength))
  ) {
    throw new SnapshotIntegrityError();
  }
}

async function verifyCommittedEvent(
  dependencies: Readonly<BaseRpcAnchorStorageDependencies>,
  context: BaseRpcAnchorIngestionContext,
  attempt: CommittedCaptureAttempt,
  event: StoredEvent,
  binding: Readonly<DurableNetworkAttemptBinding>,
  minimumAcquiredAt?: string,
): Promise<Readonly<BaseRpcAnchorIngestionResult>> {
  const result = assertEventMatchesCommit(event, context, attempt, minimumAcquiredAt);
  assertResultMatchesClosedAttempt(result, binding);
  const capture = await dependencies.vault.verify(attempt.captureId);
  assertBaseRpcAnchorCaptureMetadata(
    capture.metadata,
    capture.size,
    attempt,
    binding,
    result,
    minimumAcquiredAt,
  );
  return result;
}

export function appendBaseRpcAnchorProjection(
  dependencies: Readonly<BaseRpcAnchorStorageDependencies>,
  context: BaseRpcAnchorIngestionContext,
  acquiredAt: string,
  byteLength: number,
  projection: BaseRpcAnchorCaptureProjection,
): Readonly<BaseRpcAnchorIngestionResult> {
  const event = appendCaptureRecordedEvent(dependencies.store, {
    acquiredAt,
    attemptId: context.attemptId,
    byteLength,
    counts:
      projection.status === "accepted"
        ? { actorCount: 0, editedRecordCount: 0, recordCount: 1 }
        : null,
    expiresAt: context.expiresAt,
    failureCode: projection.failureCode,
    lane: BASE_RPC_INGESTION_LANE,
    profile: context.profile,
    rawDisposition: "encrypted_ephemeral",
    schemaVersion: 2,
    sessionId: context.sessionId,
    sourcePlane: BASE_RPC_INGESTION_SOURCE_PLANE,
    status: projection.status,
  });
  return resultFromEvent(event, context);
}

export async function resumeBaseRpcAnchorCommittedAttempt(
  dependencies: Readonly<BaseRpcAnchorStorageDependencies>,
  context: BaseRpcAnchorIngestionContext,
  attempt: CommittedCaptureAttempt,
  binding: Readonly<DurableNetworkAttemptBinding>,
  minimumAcquiredAt?: string,
): Promise<Readonly<BaseRpcAnchorIngestionResult>> {
  const existingEvent = dependencies.store.getByIdempotencyKey(
    baseRpcAnchorEventKey(context.attemptId),
  );
  if (existingEvent !== undefined) {
    return verifyCommittedEvent(
      dependencies,
      context,
      attempt,
      existingEvent,
      binding,
      minimumAcquiredAt,
    );
  }

  if (binding.state === "closed") {
    throw new SnapshotIntegrityError();
  }

  const capture = await dependencies.vault.get(attempt.captureId);
  try {
    assertBaseRpcAnchorCaptureMetadata(
      capture.metadata,
      capture.size,
      attempt,
      binding,
      undefined,
      minimumAcquiredAt,
    );
    const projection = projectRecoveredCapture(capture.bytes, capture.metadata.acquiredAt);
    assertBaseRpcAnchorProjectionMatchesCommit(projection, attempt);
    return appendBaseRpcAnchorProjection(
      dependencies,
      context,
      capture.metadata.acquiredAt,
      capture.size,
      projection,
    );
  } finally {
    capture.bytes.fill(0);
  }
}

export async function recoverBaseRpcAnchorFromStorage(
  dependencies: Readonly<BaseRpcAnchorStorageDependencies>,
  context: BaseRpcAnchorIngestionContext,
): Promise<Readonly<BaseRpcAnchorIngestionResult>> {
  const existingEvent = dependencies.store.getByIdempotencyKey(
    baseRpcAnchorEventKey(context.attemptId),
  );
  const existingAttempt = dependencies.captureRegistry.getAttempt(context.attemptId);
  if (existingAttempt === undefined) {
    if (existingEvent !== undefined) {
      throw new Error("capture event exists without its authenticated registry record");
    }
    throw new Error("no durable Base RPC capture is available for recovery");
  }
  if (existingAttempt.state === "removed") {
    if (existingEvent === undefined) throw new Error("capture attempt is terminal");
    const durable = readBaseRpcAnchorDurableBinding(dependencies, context, "committed-resume");
    const result = resultFromEvent(existingEvent, context);
    assertResultMatchesClosedAttempt(result, durable);
    if (
      (existingAttempt.removalReason !== "capture_deleted_explicit" &&
        existingAttempt.removalReason !== "capture_deleted_expired") ||
      Date.parse(existingAttempt.removedAt) < Date.parse(result.acquiredAt) ||
      (durable.dispatchedAt !== null &&
        Date.parse(result.acquiredAt) < Date.parse(durable.dispatchedAt))
    ) {
      throw new SnapshotIntegrityError();
    }
    return result;
  }
  if (existingAttempt.state !== "committed") {
    throw new Error("no committed Base RPC capture is available for recovery");
  }
  const attempt = rebindBaseRpcAnchorAttempt(
    dependencies.captureRegistry,
    existingAttempt,
    context,
  );
  if (attempt.state !== "committed") throw new SnapshotIntegrityError();
  const durable = readBaseRpcAnchorDurableBinding(dependencies, context, "committed-resume");
  return resumeBaseRpcAnchorCommittedAttempt(
    dependencies,
    context,
    attempt,
    durable,
    durable.dispatchedAt ?? undefined,
  );
}
