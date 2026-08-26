import { createHash } from "node:crypto";

import {
  SqliteCaptureRegistry,
  isSqliteCaptureRegistry,
  type CaptureSourceIdentifiers,
  type CommittedCaptureAttempt,
  type PendingCaptureAttempt,
} from "@rsi/capture-registry";
import {
  OPENSEA_JSON_CONTENT_TYPES,
  OPENSEA_TRENDING_MAXIMUM_RESULTS,
  OPENSEA_TRENDING_OPERATION,
  OPENSEA_TRENDING_RESERVED_ATOMIC,
  isOpenSeaTrendingCollector,
  isQuarantinedOpenSeaTrendingResponse,
  parseOpenSeaTrendingQuarantine,
  prepareOpenSeaTrendingCollectorRequest,
  copyOpenSeaRateLimitReceipt,
  type OpenSeaRateLimitReceipt,
  type OpenSeaTrendingCollector,
  type PreparedOpenSeaTrendingCollectorRequest,
  type QuarantinedOpenSeaTrendingResponse,
} from "@rsi/opensea-collector";
import {
  CAPTURE_RECORDED_EVENT_TYPE,
  CanonicalTimestampSchema,
  OperationsProfileSchema,
  SqliteOperationsStore,
  UuidSchema,
  appendCaptureRecordedEvent,
  isNetworkAttemptDispatchReceipt,
  isSqliteOperationsStore,
  parseCaptureRecordedEventPayload,
  parseWithSchema,
  type DurableNetworkAttemptBinding,
  type OperationsProfile,
} from "@rsi/operations";
import { parseOpenSeaTrendingResponse } from "@rsi/source-contracts/opensea-trending";
import { isSqliteEventStore, type SqliteEventStore, type StoredEvent } from "@rsi/store";
import {
  SnapshotIntegrityError,
  isSnapshotVault,
  type CaptureId,
  type SnapshotVault,
} from "@rsi/vault";
import { z } from "zod";

export type OpenSeaTrendingCaptureStatus = "accepted" | "rejected";

export interface OpenSeaTrendingIngestionContext {
  readonly attemptId: string;
  readonly expiresAt: string;
  readonly lane: "marketplace";
  readonly profile: OperationsProfile;
  readonly sessionId: string;
}

export interface OpenSeaTrendingIngestionDependencies {
  readonly captureRegistry: SqliteCaptureRegistry;
  /** Required only while a pending attempt may perform the one authorized collection. */
  readonly collector?: OpenSeaTrendingCollector;
  /** Required only while a pending attempt may begin or commit. */
  readonly now?: () => string;
  /** Required for collection and collectorless recovery of every OpenSea attempt. */
  readonly operationsStore: SqliteOperationsStore;
  /** Best-effort cancellation before or during collection; ignored after bytes arrive. */
  readonly signal?: AbortSignal;
  readonly store: SqliteEventStore;
  readonly vault: SnapshotVault;
}

/**
 * A deliberately content-free result. Pagination and rate-limit state exist only
 * for the fresh response that supplied them and are never reconstructed.
 */
export interface OpenSeaTrendingIngestionResult {
  readonly acquiredAt: string;
  readonly adapterId: "opensea.trending";
  readonly byteLength: number;
  readonly collectionCount: number | null;
  readonly expiresAt: string;
  readonly failureCode: "INVALID_RESPONSE_SCHEMA" | null;
  readonly hasNextPage: boolean | null;
  readonly rateLimit: OpenSeaRateLimitReceipt | null;
  readonly status: OpenSeaTrendingCaptureStatus;
}

interface CaptureProjection {
  readonly collectionCount: number | null;
  readonly failureCode: "INVALID_RESPONSE_SCHEMA" | null;
  readonly hasNextPage: boolean | null;
  readonly sourceIdentifiers: Extract<CaptureSourceIdentifiers, { readonly source: "opensea" }>;
  readonly status: OpenSeaTrendingCaptureStatus;
}

const OpenSeaTrendingIngestionContextSchema = z.strictObject({
  attemptId: UuidSchema,
  expiresAt: CanonicalTimestampSchema,
  lane: z.literal("marketplace"),
  profile: OperationsProfileSchema,
  sessionId: UuidSchema,
});

function parseContext(value: unknown): OpenSeaTrendingIngestionContext {
  return parseWithSchema(
    OpenSeaTrendingIngestionContextSchema,
    value,
    "OpenSea trending ingestion context",
  );
}

function readNow(
  dependencies: Readonly<OpenSeaTrendingIngestionDependencies>,
  label: string,
): string {
  if (typeof dependencies.now !== "function") {
    throw new Error("an explicit ingestion clock is required");
  }
  return parseWithSchema(CanonicalTimestampSchema, dependencies.now(), label);
}

function sha256(value: Uint8Array): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

const VAULT_PROVENANCE_PARAMETER = "rsi-provenance" as const;

/**
 * CaptureMetadataV1 is intentionally closed. Its standards-compliant media
 * type parameter is the only private, authenticated extension point available
 * for binding exact raw bytes to the attempt that acquired them.
 */
function boundVaultMediaType(
  providerContentType: string,
  binding: Readonly<DurableNetworkAttemptBinding>,
  request: PreparedOpenSeaTrendingCollectorRequest,
): string {
  if (
    binding.dispatchedAt === null ||
    !(OPENSEA_JSON_CONTENT_TYPES as readonly string[]).includes(providerContentType)
  ) {
    throw new SnapshotIntegrityError();
  }
  const canonical = [
    "rsi.opensea-trending.capture-provenance.v1",
    request.fingerprint,
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
  request: PreparedOpenSeaTrendingCollectorRequest,
): boolean {
  return (OPENSEA_JSON_CONTENT_TYPES as readonly string[]).some(
    (contentType) => value === boundVaultMediaType(contentType, binding, request),
  );
}

function assertExactNetworkBinding(
  binding: DurableNetworkAttemptBinding | NonNullable<OpenSeaTrendingCollector["attemptBinding"]>,
  context: OpenSeaTrendingIngestionContext,
): void {
  if (
    binding.attemptId !== context.attemptId ||
    binding.authorizationExpiresAt !== context.expiresAt ||
    binding.lane !== "marketplace" ||
    binding.operation !== OPENSEA_TRENDING_OPERATION ||
    binding.profile !== context.profile ||
    binding.reservedAtomic !== OPENSEA_TRENDING_RESERVED_ATOMIC ||
    binding.sessionId !== context.sessionId ||
    binding.sourcePlane !== "marketplace"
  ) {
    throw new Error("OpenSea ingestion context does not match its reserved network attempt");
  }
}

function assertCollectorBinding(
  collector: OpenSeaTrendingCollector,
  context: OpenSeaTrendingIngestionContext,
): void {
  if (!isOpenSeaTrendingCollector(collector)) {
    throw new Error("an authentic OpenSea trending collector is required");
  }
  assertExactNetworkBinding(collector.attemptBinding, context);
}

type DurableBindingPhase = "committed-resume" | "post-response" | "pre-egress";

function assertConcreteStorageDependencies(
  dependencies: Readonly<OpenSeaTrendingIngestionDependencies>,
): void {
  if (!isSqliteCaptureRegistry(dependencies.captureRegistry)) {
    throw new Error("an authenticated capture registry is required");
  }
  if (!isSqliteEventStore(dependencies.store)) {
    throw new Error("an authenticated event store is required");
  }
  if (!isSnapshotVault(dependencies.vault)) {
    throw new Error("an authenticated snapshot vault is required");
  }
  if (!isSqliteOperationsStore(dependencies.operationsStore)) {
    throw new Error("OpenSea ingestion requires its authenticated operations store");
  }
  if (dependencies.signal !== undefined && !(dependencies.signal instanceof AbortSignal)) {
    throw new Error("an authentic AbortSignal is required");
  }
}

function readDurableNetworkBinding(
  dependencies: Readonly<OpenSeaTrendingIngestionDependencies>,
  context: OpenSeaTrendingIngestionContext,
  phase: DurableBindingPhase,
): Readonly<DurableNetworkAttemptBinding> {
  const binding = dependencies.operationsStore.readNetworkAttemptBinding(context.attemptId);
  assertExactNetworkBinding(binding, context);
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

function eventKey(attemptId: string): string {
  return `capture-recorded-v2:${attemptId}`;
}

function assertAttemptContext(
  attempt: PendingCaptureAttempt | CommittedCaptureAttempt,
  context: OpenSeaTrendingIngestionContext,
  request: PreparedOpenSeaTrendingCollectorRequest,
): void {
  if (
    attempt.expiresAt !== context.expiresAt ||
    attempt.lane !== "marketplace" ||
    attempt.profile !== context.profile ||
    attempt.requestFingerprint !== request.fingerprint ||
    attempt.sessionId !== context.sessionId ||
    attempt.source !== "opensea"
  ) {
    throw new Error("capture attempt does not match the OpenSea ingestion context");
  }
}

function rebindExistingAttempt(
  registry: SqliteCaptureRegistry,
  attempt: PendingCaptureAttempt | CommittedCaptureAttempt,
  context: OpenSeaTrendingIngestionContext,
  request: PreparedOpenSeaTrendingCollectorRequest,
): PendingCaptureAttempt | CommittedCaptureAttempt {
  const rebound = registry.beginAttempt({
    acquiredAt: attempt.acquiredAt,
    attemptId: context.attemptId,
    expiresAt: context.expiresAt,
    lane: "marketplace",
    profile: context.profile,
    requestFingerprint: request.fingerprint,
    sessionId: context.sessionId,
    source: "opensea",
  });
  if (rebound.state === "removed") throw new Error("capture attempt is terminal");
  assertAttemptContext(rebound, context, request);
  return rebound;
}

function beginNewAttempt(
  dependencies: Readonly<OpenSeaTrendingIngestionDependencies>,
  context: OpenSeaTrendingIngestionContext,
  request: PreparedOpenSeaTrendingCollectorRequest,
): PendingCaptureAttempt | CommittedCaptureAttempt {
  const begunAt = readNow(dependencies, "OpenSea ingestion begin time");
  const attempt = dependencies.captureRegistry.beginAttempt({
    acquiredAt: begunAt,
    attemptId: context.attemptId,
    expiresAt: context.expiresAt,
    lane: "marketplace",
    profile: context.profile,
    requestFingerprint: request.fingerprint,
    sessionId: context.sessionId,
    source: "opensea",
  });
  if (attempt.state === "removed") throw new Error("capture attempt is terminal");
  assertAttemptContext(attempt, context, request);
  return attempt;
}

function assertResponseBinding(
  response: QuarantinedOpenSeaTrendingResponse,
  attempt: PendingCaptureAttempt | CommittedCaptureAttempt,
  context: OpenSeaTrendingIngestionContext,
  request: PreparedOpenSeaTrendingCollectorRequest,
  durable: Readonly<DurableNetworkAttemptBinding>,
): void {
  const dispatched = response.metadata.networkAttempt;
  if (
    !isNetworkAttemptDispatchReceipt(dispatched) ||
    response.metadata.requestFingerprint !== request.fingerprint ||
    response.metadata.maximumResults !== OPENSEA_TRENDING_MAXIMUM_RESULTS ||
    dispatched.dispatchedAt !== durable.dispatchedAt ||
    dispatched.binding.attemptId !== context.attemptId ||
    dispatched.binding.attemptId !== durable.attemptId ||
    dispatched.binding.authorizationExpiresAt !== context.expiresAt ||
    dispatched.binding.authorizationExpiresAt !== durable.authorizationExpiresAt ||
    dispatched.binding.lane !== "marketplace" ||
    dispatched.binding.lane !== durable.lane ||
    dispatched.binding.operation !== OPENSEA_TRENDING_OPERATION ||
    dispatched.binding.operation !== durable.operation ||
    dispatched.binding.profile !== context.profile ||
    dispatched.binding.profile !== durable.profile ||
    dispatched.binding.reservedAtomic !== OPENSEA_TRENDING_RESERVED_ATOMIC ||
    dispatched.binding.reservedAtomic !== durable.reservedAtomic ||
    dispatched.binding.sessionId !== context.sessionId ||
    dispatched.binding.sessionId !== durable.sessionId ||
    dispatched.binding.sourcePlane !== "marketplace" ||
    dispatched.binding.sourcePlane !== durable.sourcePlane
  ) {
    throw new Error("quarantined response does not match its authorized OpenSea dispatch");
  }
  const begun = Date.parse(attempt.acquiredAt);
  const acquired = Date.parse(response.metadata.acquiredAt);
  const expires = Date.parse(context.expiresAt);
  if (acquired < begun || acquired > expires || expires - acquired > 2 * 60 * 60 * 1_000) {
    throw new Error("capture acquisition is outside its authorized window");
  }
}

function emptyOpenSeaIdentifiers(): Extract<
  CaptureSourceIdentifiers,
  { readonly source: "opensea" }
> {
  return Object.freeze({ identifiers: Object.freeze([]), source: "opensea" as const });
}

function projectResponse(response: QuarantinedOpenSeaTrendingResponse): CaptureProjection {
  try {
    const parsed = parseOpenSeaTrendingQuarantine(response);
    return acceptedProjection(parsed.evidence);
  } catch {
    return rejectedProjection();
  }
}

function acceptedProjection(
  evidence: ReturnType<typeof parseOpenSeaTrendingResponse>,
): CaptureProjection {
  return Object.freeze({
    collectionCount: evidence.collections.length,
    failureCode: null,
    hasNextPage: evidence.hasNextPage,
    sourceIdentifiers: Object.freeze({
      identifiers: Object.freeze(
        evidence.collections.map((collection) =>
          Object.freeze({ kind: "collection_slug" as const, value: collection.slug }),
        ),
      ),
      source: "opensea" as const,
    }),
    status: "accepted" as const,
  });
}

function rejectedProjection(): CaptureProjection {
  return Object.freeze({
    collectionCount: null,
    failureCode: "INVALID_RESPONSE_SCHEMA" as const,
    hasNextPage: null,
    sourceIdentifiers: emptyOpenSeaIdentifiers(),
    status: "rejected" as const,
  });
}

function projectRecoveredCapture(bytes: Uint8Array, acquiredAt: string): CaptureProjection {
  try {
    return acceptedProjection(parseOpenSeaTrendingResponse(bytes, acquiredAt));
  } catch {
    return rejectedProjection();
  }
}

function sameIdentifiers(left: CaptureSourceIdentifiers, right: CaptureSourceIdentifiers): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function assertProjectionMatchesCommit(
  projection: CaptureProjection,
  attempt: CommittedCaptureAttempt,
): void {
  if (!sameIdentifiers(projection.sourceIdentifiers, attempt.sourceIdentifiers)) {
    throw new SnapshotIntegrityError();
  }
}

function resultFromEvent(
  event: StoredEvent,
  context: OpenSeaTrendingIngestionContext,
): Readonly<OpenSeaTrendingIngestionResult> {
  if (
    event.aggregateId !== `session:${context.sessionId}` ||
    event.idempotencyKey !== eventKey(context.attemptId) ||
    event.type !== CAPTURE_RECORDED_EVENT_TYPE
  ) {
    throw new Error("stored capture event does not match its attempt");
  }
  const { capture } = parseCaptureRecordedEventPayload(event.payload);
  if (
    capture.attemptId !== context.attemptId ||
    capture.expiresAt !== context.expiresAt ||
    capture.lane !== "marketplace" ||
    capture.profile !== context.profile ||
    capture.sessionId !== context.sessionId ||
    capture.sourcePlane !== "marketplace" ||
    event.occurredAt !== capture.acquiredAt
  ) {
    throw new Error("stored capture event does not match its OpenSea ingestion context");
  }
  if (
    capture.status === "accepted" &&
    (capture.counts?.actorCount !== 0 || capture.counts.editedRecordCount !== 0)
  ) {
    throw new Error("stored capture event contains unsupported OpenSea projection counts");
  }
  if (capture.failureCode !== null && capture.failureCode !== "INVALID_RESPONSE_SCHEMA") {
    throw new Error("stored capture event contains an unsupported OpenSea failure code");
  }
  return Object.freeze({
    acquiredAt: capture.acquiredAt,
    adapterId: "opensea.trending" as const,
    byteLength: capture.byteLength,
    collectionCount: capture.counts?.recordCount ?? null,
    expiresAt: capture.expiresAt,
    failureCode: capture.failureCode,
    hasNextPage: null,
    rateLimit: null,
    status: capture.status,
  });
}

function withFreshProviderMetadata(
  result: Readonly<OpenSeaTrendingIngestionResult>,
  projection: CaptureProjection,
  rateLimit: OpenSeaRateLimitReceipt | undefined,
): Readonly<OpenSeaTrendingIngestionResult> {
  return Object.freeze({
    ...result,
    hasNextPage: projection.hasNextPage,
    rateLimit: copyOpenSeaRateLimitReceipt(rateLimit) ?? null,
  });
}

function assertEventMatchesCommit(
  event: StoredEvent,
  context: OpenSeaTrendingIngestionContext,
  attempt: CommittedCaptureAttempt,
  minimumAcquiredAt?: string,
): Readonly<OpenSeaTrendingIngestionResult> {
  const result = resultFromEvent(event, context);
  const identifiers = attempt.sourceIdentifiers;
  if (
    identifiers.source !== "opensea" ||
    identifiers.identifiers.some((identifier) => identifier.kind !== "collection_slug") ||
    Date.parse(result.acquiredAt) < Date.parse(attempt.acquiredAt) ||
    Date.parse(result.acquiredAt) > Date.parse(attempt.committedAt) ||
    (minimumAcquiredAt !== undefined &&
      Date.parse(result.acquiredAt) < Date.parse(minimumAcquiredAt)) ||
    (result.status === "accepted" && result.collectionCount !== identifiers.identifiers.length) ||
    (result.status === "rejected" && identifiers.identifiers.length !== 0)
  ) {
    throw new Error("stored capture event does not match its committed OpenSea capture");
  }
  return result;
}

function assertCaptureMetadata(
  metadata: Readonly<{
    acquiredAt: string;
    expiresAt: string;
    mediaType: string;
    schemaVersion: number;
    source: string;
  }>,
  size: number,
  attempt: CommittedCaptureAttempt,
  request: PreparedOpenSeaTrendingCollectorRequest,
  binding: Readonly<DurableNetworkAttemptBinding>,
  eventResult?: OpenSeaTrendingIngestionResult,
  minimumAcquiredAt?: string,
): void {
  if (
    metadata.schemaVersion !== 1 ||
    metadata.source !== "opensea" ||
    metadata.expiresAt !== attempt.expiresAt ||
    Date.parse(metadata.acquiredAt) < Date.parse(attempt.acquiredAt) ||
    Date.parse(metadata.acquiredAt) > Date.parse(attempt.committedAt) ||
    Date.parse(metadata.acquiredAt) > Date.parse(attempt.expiresAt) ||
    (minimumAcquiredAt !== undefined &&
      Date.parse(metadata.acquiredAt) < Date.parse(minimumAcquiredAt)) ||
    !isExpectedBoundVaultMediaType(metadata.mediaType, binding, request) ||
    (eventResult !== undefined &&
      (metadata.acquiredAt !== eventResult.acquiredAt || size !== eventResult.byteLength))
  ) {
    throw new SnapshotIntegrityError();
  }
}

async function verifyCommittedEvent(
  dependencies: Readonly<OpenSeaTrendingIngestionDependencies>,
  context: OpenSeaTrendingIngestionContext,
  attempt: CommittedCaptureAttempt,
  event: StoredEvent,
  request: PreparedOpenSeaTrendingCollectorRequest,
  binding: Readonly<DurableNetworkAttemptBinding>,
  minimumAcquiredAt?: string,
): Promise<Readonly<OpenSeaTrendingIngestionResult>> {
  const result = assertEventMatchesCommit(event, context, attempt, minimumAcquiredAt);
  const capture = await dependencies.vault.verify(attempt.captureId);
  assertCaptureMetadata(
    capture.metadata,
    capture.size,
    attempt,
    request,
    binding,
    result,
    minimumAcquiredAt,
  );
  return result;
}

function appendProjection(
  dependencies: Readonly<OpenSeaTrendingIngestionDependencies>,
  context: OpenSeaTrendingIngestionContext,
  acquiredAt: string,
  byteLength: number,
  projection: CaptureProjection,
): Readonly<OpenSeaTrendingIngestionResult> {
  const event = appendCaptureRecordedEvent(dependencies.store, {
    acquiredAt,
    attemptId: context.attemptId,
    byteLength,
    counts:
      projection.status === "accepted"
        ? {
            actorCount: 0,
            editedRecordCount: 0,
            recordCount: projection.collectionCount,
          }
        : null,
    expiresAt: context.expiresAt,
    failureCode: projection.failureCode,
    lane: "marketplace",
    profile: context.profile,
    rawDisposition: "encrypted_ephemeral",
    schemaVersion: 2,
    sessionId: context.sessionId,
    sourcePlane: "marketplace",
    status: projection.status,
  });
  return resultFromEvent(event, context);
}

async function resumeCommittedAttempt(
  dependencies: Readonly<OpenSeaTrendingIngestionDependencies>,
  context: OpenSeaTrendingIngestionContext,
  attempt: CommittedCaptureAttempt,
  request: PreparedOpenSeaTrendingCollectorRequest,
  binding: Readonly<DurableNetworkAttemptBinding>,
  minimumAcquiredAt?: string,
): Promise<Readonly<OpenSeaTrendingIngestionResult>> {
  const existingEvent = dependencies.store.getByIdempotencyKey(eventKey(context.attemptId));
  if (existingEvent !== undefined) {
    return verifyCommittedEvent(
      dependencies,
      context,
      attempt,
      existingEvent,
      request,
      binding,
      minimumAcquiredAt,
    );
  }

  // `attempt` has already been rebound to the fixed request fingerprint and
  // the authentic Vault lookup is by its registry-owned captureId. Recovery
  // never re-brands these bytes as a network response.
  const capture = await dependencies.vault.get(attempt.captureId);
  try {
    assertCaptureMetadata(
      capture.metadata,
      capture.size,
      attempt,
      request,
      binding,
      undefined,
      minimumAcquiredAt,
    );
    const projection = projectRecoveredCapture(capture.bytes, capture.metadata.acquiredAt);
    assertProjectionMatchesCommit(projection, attempt);
    return appendProjection(
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

async function assertResponseMatchesCommittedCapture(
  dependencies: Readonly<OpenSeaTrendingIngestionDependencies>,
  attempt: CommittedCaptureAttempt,
  response: QuarantinedOpenSeaTrendingResponse,
  request: PreparedOpenSeaTrendingCollectorRequest,
  binding: Readonly<DurableNetworkAttemptBinding>,
): Promise<void> {
  const capture = await dependencies.vault.get(attempt.captureId);
  try {
    assertCaptureMetadata(capture.metadata, capture.size, attempt, request, binding);
    if (
      capture.metadata.acquiredAt !== response.metadata.acquiredAt ||
      capture.metadata.mediaType !==
        boundVaultMediaType(response.metadata.contentType, binding, request) ||
      capture.size !== response.metadata.byteLength ||
      sha256(capture.bytes) !== response.metadata.responseHash
    ) {
      throw new Error("concurrent response does not match the committed OpenSea capture");
    }
  } finally {
    capture.bytes.fill(0);
  }
}

async function deleteUncommittedCapture(
  dependencies: Readonly<OpenSeaTrendingIngestionDependencies>,
  captureId: CaptureId,
  acquiredAt: string,
  primaryError: unknown,
): Promise<never> {
  try {
    await dependencies.vault.delete(captureId, {
      deletedAt: acquiredAt,
      reason: "explicit",
    });
  } catch (cleanupError) {
    throw new AggregateError(
      [primaryError, cleanupError],
      "ingestion failed and the uncommitted capture could not be crypto-shredded",
    );
  }
  throw primaryError;
}

async function captureAndCommit(
  dependencies: Readonly<OpenSeaTrendingIngestionDependencies>,
  context: OpenSeaTrendingIngestionContext,
  attempt: PendingCaptureAttempt,
  request: PreparedOpenSeaTrendingCollectorRequest,
  response: QuarantinedOpenSeaTrendingResponse,
  binding: Readonly<DurableNetworkAttemptBinding>,
): Promise<Readonly<OpenSeaTrendingIngestionResult>> {
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
        mediaType: boundVaultMediaType(response.metadata.contentType, binding, request),
        schemaVersion: 1,
        source: "opensea",
      },
    });
    captureId = capture.captureId;
    if (sha256(bytes) !== response.metadata.responseHash) {
      throw new Error("quarantined response failed its capture boundary");
    }

    // Parsing is deliberately below Vault capture: even malformed provider
    // content must first cross the encrypt-first evidence boundary.
    const projection = projectResponse(response);
    const committedAt = readNow(dependencies, "OpenSea ingestion commit time");
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
        assertAttemptContext(winner, context, request);
        if (winner.captureId === captureId) {
          committed = true;
          if (
            winner.committedAt !== committedAt ||
            !sameIdentifiers(winner.sourceIdentifiers, projection.sourceIdentifiers)
          ) {
            throw new SnapshotIntegrityError();
          }
          committedAttempt = winner;
        } else {
          await assertResponseMatchesCommittedCapture(
            dependencies,
            winner,
            response,
            request,
            binding,
          );
          await dependencies.vault.delete(captureId, {
            deletedAt: response.metadata.acquiredAt,
            reason: "explicit",
          });
          captureId = undefined;
          assertProjectionMatchesCommit(projection, winner);
          return withFreshProviderMetadata(
            await resumeCommittedAttempt(
              dependencies,
              context,
              winner,
              request,
              binding,
              binding.dispatchedAt ?? undefined,
            ),
            projection,
            response.metadata.rateLimit,
          );
        }
      } else {
        throw error;
      }
    }

    assertProjectionMatchesCommit(projection, committedAttempt);
    return withFreshProviderMetadata(
      appendProjection(
        dependencies,
        context,
        response.metadata.acquiredAt,
        response.metadata.byteLength,
        projection,
      ),
      projection,
      response.metadata.rateLimit,
    );
  } catch (error) {
    if (captureId !== undefined && !committed && !commitOutcomeAmbiguous) {
      return deleteUncommittedCapture(dependencies, captureId, response.metadata.acquiredAt, error);
    }
    throw error;
  } finally {
    bytes.fill(0);
  }
}

/**
 * Bind the fixed one-shot intent before egress, encrypt the bytes before any
 * OpenSea schema parsing, and persist only collection identifiers plus a
 * content-free event. Exact retries recover without a collector or API key.
 */
export async function ingestOpenSeaTrending(
  dependencies: Readonly<OpenSeaTrendingIngestionDependencies>,
  contextInput: unknown,
): Promise<Readonly<OpenSeaTrendingIngestionResult>> {
  if (arguments.length !== 2) {
    throw new Error("OpenSea trending ingestion accepts no request input");
  }
  const context = parseContext(contextInput);
  assertConcreteStorageDependencies(dependencies);
  const request = prepareOpenSeaTrendingCollectorRequest();
  const existingEvent = dependencies.store.getByIdempotencyKey(eventKey(context.attemptId));
  const existingAttempt = dependencies.captureRegistry.getAttempt(context.attemptId);

  if (existingAttempt === undefined && existingEvent !== undefined) {
    throw new Error("capture event exists without its authenticated registry record");
  }
  if (existingAttempt?.state === "removed") {
    if (existingEvent === undefined) throw new Error("capture attempt is terminal");
    const durable = readDurableNetworkBinding(dependencies, context, "committed-resume");
    const result = resultFromEvent(existingEvent, context);
    if (
      durable.dispatchedAt !== null &&
      Date.parse(result.acquiredAt) < Date.parse(durable.dispatchedAt)
    ) {
      throw new SnapshotIntegrityError();
    }
    return result;
  }

  if (existingAttempt?.state === "committed") {
    const attempt = rebindExistingAttempt(
      dependencies.captureRegistry,
      existingAttempt,
      context,
      request,
    );
    if (attempt.state !== "committed") throw new SnapshotIntegrityError();
    const durable = readDurableNetworkBinding(dependencies, context, "committed-resume");
    return resumeCommittedAttempt(
      dependencies,
      context,
      attempt,
      request,
      durable,
      durable.dispatchedAt ?? undefined,
    );
  }
  if (existingEvent !== undefined) {
    throw new Error("capture event exists before its registry commit");
  }

  const collector = dependencies.collector;
  if (!isOpenSeaTrendingCollector(collector)) {
    throw new Error("an authentic OpenSea trending collector is required before collection");
  }
  assertCollectorBinding(collector, context);
  readDurableNetworkBinding(dependencies, context, "pre-egress");
  const attempt =
    existingAttempt === undefined
      ? beginNewAttempt(dependencies, context, request)
      : rebindExistingAttempt(dependencies.captureRegistry, existingAttempt, context, request);
  if (attempt.state !== "pending") throw new SnapshotIntegrityError();

  let response: QuarantinedOpenSeaTrendingResponse | undefined;
  try {
    response = await collector.collectRaw(
      dependencies.signal === undefined ? undefined : { signal: dependencies.signal },
    );
    if (!isQuarantinedOpenSeaTrendingResponse(response)) {
      throw new Error("collector returned an invalid OpenSea quarantine object");
    }
    const durable = readDurableNetworkBinding(dependencies, context, "post-response");
    assertResponseBinding(response, attempt, context, request, durable);
    if (
      durable.dispatchedAt === null ||
      Date.parse(durable.dispatchedAt) < Date.parse(attempt.acquiredAt) ||
      Date.parse(durable.dispatchedAt) > Date.parse(response.metadata.acquiredAt)
    ) {
      throw new Error("network dispatch is outside its OpenSea capture window");
    }

    const current = dependencies.captureRegistry.getAttempt(context.attemptId);
    if (current?.state === "committed") {
      assertAttemptContext(current, context, request);
      await assertResponseMatchesCommittedCapture(
        dependencies,
        current,
        response,
        request,
        durable,
      );
      const projection = projectResponse(response);
      assertProjectionMatchesCommit(projection, current);
      return withFreshProviderMetadata(
        await resumeCommittedAttempt(
          dependencies,
          context,
          current,
          request,
          durable,
          durable.dispatchedAt,
        ),
        projection,
        response.metadata.rateLimit,
      );
    }
    if (current?.state !== "pending") throw new Error("capture attempt became terminal");

    return await captureAndCommit(dependencies, context, current, request, response, durable);
  } finally {
    response?.destroy();
  }
}
