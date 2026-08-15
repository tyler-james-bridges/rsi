import { createHash } from "node:crypto";

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
  ResearchLaneSchema,
  SqliteOperationsStore,
  UuidSchema,
  appendCaptureRecordedEvent,
  isSqliteOperationsStore,
  parseCaptureRecordedEventPayload,
  parseWithSchema,
  type OperationsProfile,
  type ResearchLane,
  type DurableNetworkAttemptBinding,
} from "@rsi/operations";
import { isSqliteEventStore, type SqliteEventStore, type StoredEvent } from "@rsi/store";
import {
  SnapshotIntegrityError,
  isSnapshotVault,
  type CaptureId,
  type SnapshotVault,
} from "@rsi/vault";
import {
  QuarantinedXRecentSearchResponse,
  XCollectorError,
  X_JSON_CONTENT_TYPES,
  isXRecentSearchCollector,
  parseXRecentSearchResponse,
  prepareRecentSearchRequest,
  quarantineNetworkResponse,
  type PreparedXRecentSearchRequest,
  type XRecentSearchCollector,
  type XRecentSearchResult,
} from "@rsi/x-collector";
import { z } from "zod";

export type XCaptureStatus = "accepted" | "rejected";

export interface XIngestionContext {
  readonly attemptId: string;
  readonly expiresAt: string;
  readonly lane: ResearchLane;
  readonly profile: OperationsProfile;
  readonly sessionId: string;
}

export interface XIngestionDependencies {
  readonly captureRegistry: SqliteCaptureRegistry;
  /** Required only while a pending attempt may perform collection. */
  readonly collector?: XRecentSearchCollector;
  /** A caller-owned canonical UTC clock. It is read before egress and again before commit. */
  /** Required only while a pending attempt may begin or commit. */
  readonly now?: () => string;
  /** Required for every non-dev attempt, including collectorless crash recovery. */
  readonly operationsStore?: SqliteOperationsStore;
  readonly store: SqliteEventStore;
  readonly vault: SnapshotVault;
}

export interface XIngestionResult {
  readonly acquiredAt: string;
  readonly adapterId: "x.research";
  readonly authorCount: number | null;
  readonly byteLength: number;
  readonly eventHash: string;
  readonly eventId: string;
  readonly eventSequence: number;
  readonly expiresAt: string;
  readonly failureCode: string | null;
  readonly postCount: number | null;
  readonly status: XCaptureStatus;
}

interface CaptureProjection {
  readonly authorCount: number | null;
  readonly editedPostCount: number | null;
  readonly failureCode: string | null;
  readonly postCount: number | null;
  readonly sourceIdentifiers: Extract<CaptureSourceIdentifiers, { readonly source: "x" }>;
  readonly status: XCaptureStatus;
}

const XIngestionContextSchema = z.strictObject({
  attemptId: UuidSchema,
  expiresAt: CanonicalTimestampSchema,
  lane: ResearchLaneSchema,
  profile: OperationsProfileSchema,
  sessionId: UuidSchema,
});

function parseContext(value: unknown): XIngestionContext {
  return parseWithSchema(XIngestionContextSchema, value, "X ingestion context");
}

function readNow(dependencies: Readonly<XIngestionDependencies>, label: string): string {
  if (typeof dependencies.now !== "function")
    throw new Error("an explicit ingestion clock is required");
  return parseWithSchema(CanonicalTimestampSchema, dependencies.now(), label);
}

function safeFailureCode(error: unknown): string {
  return error instanceof XCollectorError ? error.code : "INVALID_RESPONSE_SCHEMA";
}

function sha256(value: Uint8Array): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function assertExactNetworkBinding(
  binding: DurableNetworkAttemptBinding | NonNullable<XRecentSearchCollector["attemptBinding"]>,
  context: XIngestionContext,
): void {
  if (
    binding.attemptId !== context.attemptId ||
    binding.authorizationExpiresAt !== context.expiresAt ||
    binding.lane !== context.lane ||
    binding.operation !== "x.recent-search.v1" ||
    binding.profile !== context.profile ||
    binding.reservedAtomic !== "150000" ||
    binding.sessionId !== context.sessionId ||
    binding.sourcePlane !== "social"
  ) {
    throw new Error("X ingestion context does not match its reserved network attempt");
  }
}

function assertCollectorBinding(
  collector: XRecentSearchCollector,
  context: XIngestionContext,
): void {
  if (!isXRecentSearchCollector(collector)) {
    throw new Error("an authentic X recent-search collector is required");
  }
  if (collector.mode === "replay") {
    if (collector.attemptBinding !== null || context.profile !== "dev") {
      throw new Error("replay ingestion is restricted to the dev profile");
    }
    return;
  }
  const binding = collector.attemptBinding;
  if (binding === null || context.profile === "dev") {
    throw new Error("live ingestion requires a non-dev reserved network attempt");
  }
  assertExactNetworkBinding(binding, context);
}

type DurableBindingPhase = "committed-resume" | "post-response" | "pre-egress";

function assertConcreteStorageDependencies(
  dependencies: Readonly<XIngestionDependencies>,
  context: XIngestionContext,
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
  if (
    (context.profile !== "dev" || dependencies.operationsStore !== undefined) &&
    !isSqliteOperationsStore(dependencies.operationsStore)
  ) {
    throw new Error("live ingestion requires its authenticated operations store");
  }
}

function readDurableNetworkBinding(
  dependencies: Readonly<XIngestionDependencies>,
  context: XIngestionContext,
  phase: DurableBindingPhase,
): Readonly<DurableNetworkAttemptBinding> | undefined {
  if (context.profile === "dev") return undefined;
  if (!isSqliteOperationsStore(dependencies.operationsStore)) {
    throw new Error("live ingestion requires its authenticated operations store");
  }
  const binding = dependencies.operationsStore.readNetworkAttemptBinding(context.attemptId);
  assertExactNetworkBinding(binding, context);
  const validState =
    phase === "pre-egress"
      ? binding.state === "reserved" && binding.dispatchedAt === null
      : phase === "post-response"
        ? binding.state === "dispatched" && binding.dispatchedAt !== null
        : (binding.state === "dispatched" || binding.state === "closed") &&
          binding.dispatchedAt !== null;
  if (!validState) {
    throw new Error(`network attempt is not valid for ${phase}`);
  }
  return binding;
}

function eventKey(attemptId: string): string {
  return `capture-recorded-v2:${attemptId}`;
}

function assertAttemptContext(
  attempt: PendingCaptureAttempt | CommittedCaptureAttempt,
  context: XIngestionContext,
  request: PreparedXRecentSearchRequest,
): void {
  if (
    attempt.expiresAt !== context.expiresAt ||
    attempt.lane !== context.lane ||
    attempt.profile !== context.profile ||
    attempt.requestFingerprint !== request.fingerprint ||
    attempt.sessionId !== context.sessionId ||
    attempt.source !== "x"
  ) {
    throw new Error("capture attempt does not match the ingestion context");
  }
}

function rebindExistingAttempt(
  registry: SqliteCaptureRegistry,
  attempt: PendingCaptureAttempt | CommittedCaptureAttempt,
  context: XIngestionContext,
  request: PreparedXRecentSearchRequest,
): PendingCaptureAttempt | CommittedCaptureAttempt {
  const rebound = registry.beginAttempt({
    acquiredAt: attempt.acquiredAt,
    attemptId: context.attemptId,
    expiresAt: context.expiresAt,
    lane: context.lane,
    profile: context.profile,
    requestFingerprint: request.fingerprint,
    sessionId: context.sessionId,
    source: "x",
  });
  if (rebound.state === "removed") throw new Error("capture attempt is terminal");
  assertAttemptContext(rebound, context, request);
  return rebound;
}

function beginNewAttempt(
  dependencies: Readonly<XIngestionDependencies>,
  context: XIngestionContext,
  request: PreparedXRecentSearchRequest,
): PendingCaptureAttempt | CommittedCaptureAttempt {
  const begunAt = readNow(dependencies, "X ingestion begin time");
  const attempt = dependencies.captureRegistry.beginAttempt({
    acquiredAt: begunAt,
    attemptId: context.attemptId,
    expiresAt: context.expiresAt,
    lane: context.lane,
    profile: context.profile,
    requestFingerprint: request.fingerprint,
    sessionId: context.sessionId,
    source: "x",
  });
  if (attempt.state === "removed") throw new Error("capture attempt is terminal");
  assertAttemptContext(attempt, context, request);
  return attempt;
}

function assertResponseBinding(
  response: QuarantinedXRecentSearchResponse,
  attempt: PendingCaptureAttempt | CommittedCaptureAttempt,
  context: XIngestionContext,
  request: PreparedXRecentSearchRequest,
): void {
  if (
    response.metadata.requestFingerprint !== request.fingerprint ||
    response.metadata.maxResults !== request.query.maxResults
  ) {
    throw new Error("quarantined response does not match its prepared request");
  }
  const begun = Date.parse(attempt.acquiredAt);
  const acquired = Date.parse(response.metadata.acquiredAt);
  const expires = Date.parse(context.expiresAt);
  if (acquired < begun || acquired > expires || expires - acquired > 2 * 60 * 60 * 1_000) {
    throw new Error("capture acquisition is outside its authorized window");
  }
}

function emptyXIdentifiers(): Extract<CaptureSourceIdentifiers, { readonly source: "x" }> {
  return Object.freeze({
    editIds: Object.freeze([]),
    nextToken: null,
    postIds: Object.freeze([]),
    source: "x" as const,
    userIds: Object.freeze([]),
  });
}

function identifiersFromParsed(
  parsed: XRecentSearchResult,
): Extract<CaptureSourceIdentifiers, { readonly source: "x" }> {
  return Object.freeze({
    editIds: Object.freeze([
      ...new Set(parsed.posts.flatMap((post) => post.edit_history_post_ids)),
    ]),
    nextToken: parsed.meta.next_token ?? null,
    postIds: Object.freeze(parsed.posts.map((post) => post.id)),
    source: "x" as const,
    userIds: Object.freeze(parsed.users.map((user) => user.id)),
  });
}

function projectResponse(response: QuarantinedXRecentSearchResponse): CaptureProjection {
  try {
    const parsed = parseXRecentSearchResponse(response);
    return Object.freeze({
      authorCount: parsed.users.length,
      editedPostCount: parsed.posts.filter((post) => post.edit_history_post_ids.length > 1).length,
      failureCode: null,
      postCount: parsed.posts.length,
      sourceIdentifiers: identifiersFromParsed(parsed),
      status: "accepted" as const,
    });
  } catch (error) {
    return Object.freeze({
      authorCount: null,
      editedPostCount: null,
      failureCode: safeFailureCode(error),
      postCount: null,
      sourceIdentifiers: emptyXIdentifiers(),
      status: "rejected" as const,
    });
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
  context: XIngestionContext,
): Readonly<XIngestionResult> {
  const expectedKey = eventKey(context.attemptId);
  if (
    event.aggregateId !== `session:${context.sessionId}` ||
    event.idempotencyKey !== expectedKey ||
    event.type !== CAPTURE_RECORDED_EVENT_TYPE
  ) {
    throw new Error("stored capture event does not match its attempt");
  }
  const { capture } = parseCaptureRecordedEventPayload(event.payload);
  if (
    capture.attemptId !== context.attemptId ||
    capture.expiresAt !== context.expiresAt ||
    capture.lane !== context.lane ||
    capture.profile !== context.profile ||
    capture.sessionId !== context.sessionId ||
    capture.sourcePlane !== "social" ||
    event.occurredAt !== capture.acquiredAt
  ) {
    throw new Error("stored capture event does not match its ingestion context");
  }
  return Object.freeze({
    acquiredAt: capture.acquiredAt,
    adapterId: "x.research" as const,
    authorCount: capture.counts?.actorCount ?? null,
    byteLength: capture.byteLength,
    eventHash: event.eventHash,
    eventId: event.eventId,
    eventSequence: event.sequence,
    expiresAt: capture.expiresAt,
    failureCode: capture.failureCode,
    postCount: capture.counts?.recordCount ?? null,
    status: capture.status,
  });
}

function assertEventMatchesCommit(
  event: StoredEvent,
  context: XIngestionContext,
  attempt: CommittedCaptureAttempt,
  minimumAcquiredAt?: string,
): Readonly<XIngestionResult> {
  const result = resultFromEvent(event, context);
  const identifiers = attempt.sourceIdentifiers;
  if (
    identifiers.source !== "x" ||
    Date.parse(result.acquiredAt) < Date.parse(attempt.acquiredAt) ||
    Date.parse(result.acquiredAt) > Date.parse(attempt.committedAt) ||
    (minimumAcquiredAt !== undefined &&
      Date.parse(result.acquiredAt) < Date.parse(minimumAcquiredAt)) ||
    (result.status === "accepted" &&
      (result.postCount !== identifiers.postIds.length ||
        result.authorCount !== identifiers.userIds.length ||
        identifiers.postIds.some((postId) => !identifiers.editIds.includes(postId)))) ||
    (result.status === "rejected" &&
      (identifiers.postIds.length !== 0 ||
        identifiers.userIds.length !== 0 ||
        identifiers.editIds.length !== 0 ||
        identifiers.nextToken !== null))
  ) {
    throw new Error("stored capture event does not match its committed capture");
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
  eventResult?: XIngestionResult,
  minimumAcquiredAt?: string,
): void {
  if (
    metadata.schemaVersion !== 1 ||
    metadata.source !== "x" ||
    metadata.expiresAt !== attempt.expiresAt ||
    Date.parse(metadata.acquiredAt) < Date.parse(attempt.acquiredAt) ||
    Date.parse(metadata.acquiredAt) > Date.parse(attempt.committedAt) ||
    Date.parse(metadata.acquiredAt) > Date.parse(attempt.expiresAt) ||
    (minimumAcquiredAt !== undefined &&
      Date.parse(metadata.acquiredAt) < Date.parse(minimumAcquiredAt)) ||
    !(X_JSON_CONTENT_TYPES as readonly string[]).includes(metadata.mediaType) ||
    (eventResult !== undefined &&
      (metadata.acquiredAt !== eventResult.acquiredAt || size !== eventResult.byteLength))
  ) {
    throw new SnapshotIntegrityError();
  }
}

async function verifyCommittedEvent(
  dependencies: Readonly<XIngestionDependencies>,
  context: XIngestionContext,
  attempt: CommittedCaptureAttempt,
  event: StoredEvent,
  minimumAcquiredAt?: string,
): Promise<Readonly<XIngestionResult>> {
  const result = assertEventMatchesCommit(event, context, attempt, minimumAcquiredAt);
  const capture = await dependencies.vault.verify(attempt.captureId);
  assertCaptureMetadata(capture.metadata, capture.size, attempt, result, minimumAcquiredAt);
  return result;
}

function appendProjection(
  dependencies: Readonly<XIngestionDependencies>,
  context: XIngestionContext,
  acquiredAt: string,
  byteLength: number,
  projection: CaptureProjection,
): Readonly<XIngestionResult> {
  const event = appendCaptureRecordedEvent(dependencies.store, {
    acquiredAt,
    attemptId: context.attemptId,
    byteLength,
    counts:
      projection.status === "accepted"
        ? {
            actorCount: projection.authorCount,
            editedRecordCount: projection.editedPostCount,
            recordCount: projection.postCount,
          }
        : null,
    expiresAt: context.expiresAt,
    failureCode: projection.failureCode,
    lane: context.lane,
    profile: context.profile,
    rawDisposition: "encrypted_ephemeral",
    schemaVersion: 2,
    sessionId: context.sessionId,
    sourcePlane: "social",
    status: projection.status,
  });
  return resultFromEvent(event, context);
}

async function quarantineCommittedCapture(
  dependencies: Readonly<XIngestionDependencies>,
  attempt: CommittedCaptureAttempt,
  request: PreparedXRecentSearchRequest,
  minimumAcquiredAt?: string,
): Promise<QuarantinedXRecentSearchResponse> {
  const capture = await dependencies.vault.get(attempt.captureId);
  try {
    assertCaptureMetadata(capture.metadata, capture.size, attempt, undefined, minimumAcquiredAt);
    return quarantineNetworkResponse(
      request,
      200,
      capture.metadata.mediaType,
      capture.bytes,
      capture.metadata.acquiredAt,
    );
  } finally {
    capture.bytes.fill(0);
  }
}

async function resumeCommittedAttempt(
  dependencies: Readonly<XIngestionDependencies>,
  context: XIngestionContext,
  attempt: CommittedCaptureAttempt,
  request: PreparedXRecentSearchRequest,
  minimumAcquiredAt?: string,
): Promise<Readonly<XIngestionResult>> {
  const existingEvent = dependencies.store.getByIdempotencyKey(eventKey(context.attemptId));
  if (existingEvent !== undefined) {
    return verifyCommittedEvent(dependencies, context, attempt, existingEvent, minimumAcquiredAt);
  }

  const response = await quarantineCommittedCapture(
    dependencies,
    attempt,
    request,
    minimumAcquiredAt,
  );
  try {
    const projection = projectResponse(response);
    assertProjectionMatchesCommit(projection, attempt);
    return appendProjection(
      dependencies,
      context,
      response.metadata.acquiredAt,
      response.metadata.byteLength,
      projection,
    );
  } finally {
    response.destroy();
  }
}

async function assertResponseMatchesCommittedCapture(
  dependencies: Readonly<XIngestionDependencies>,
  attempt: CommittedCaptureAttempt,
  response: QuarantinedXRecentSearchResponse,
): Promise<void> {
  const capture = await dependencies.vault.get(attempt.captureId);
  try {
    assertCaptureMetadata(capture.metadata, capture.size, attempt);
    if (
      capture.metadata.acquiredAt !== response.metadata.acquiredAt ||
      capture.metadata.mediaType !== response.metadata.contentType ||
      capture.size !== response.metadata.byteLength ||
      sha256(capture.bytes) !== response.metadata.responseHash
    ) {
      throw new Error("concurrent capture response does not match the committed attempt");
    }
  } finally {
    capture.bytes.fill(0);
  }
}

async function deleteUncommittedCapture(
  dependencies: Readonly<XIngestionDependencies>,
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
  dependencies: Readonly<XIngestionDependencies>,
  context: XIngestionContext,
  attempt: PendingCaptureAttempt,
  request: PreparedXRecentSearchRequest,
  response: QuarantinedXRecentSearchResponse,
  minimumAcquiredAt?: string,
): Promise<Readonly<XIngestionResult>> {
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
        mediaType: response.metadata.contentType,
        schemaVersion: 1,
        source: "x",
      },
    });
    captureId = capture.captureId;
    if (sha256(bytes) !== response.metadata.responseHash) {
      throw new Error("quarantined response failed its capture boundary");
    }

    const projection = projectResponse(response);
    const committedAt = readNow(dependencies, "X ingestion commit time");
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
        // commitCapture may throw after SQLite COMMIT while performing its
        // post-commit filesystem identity check. An unreadable outcome is
        // ambiguous, so retaining the encrypted capture is safer than
        // destroying a capture that the durable registry may reference.
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
          await assertResponseMatchesCommittedCapture(dependencies, winner, response);
          await dependencies.vault.delete(captureId, {
            deletedAt: response.metadata.acquiredAt,
            reason: "explicit",
          });
          captureId = undefined;
          assertProjectionMatchesCommit(projection, winner);
          return resumeCommittedAttempt(dependencies, context, winner, request, minimumAcquiredAt);
        }
      } else {
        throw error;
      }
    }

    assertProjectionMatchesCommit(projection, committedAttempt);
    return appendProjection(
      dependencies,
      context,
      response.metadata.acquiredAt,
      response.metadata.byteLength,
      projection,
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
 * Binds a one-shot capture intent before egress, captures bytes before parsing,
 * and persists only the closed content-free event projection. Exact retries
 * resume from the authenticated registry and Vault without another collection.
 */
export async function ingestXRecentSearch(
  dependencies: Readonly<XIngestionDependencies>,
  contextInput: unknown,
  query: unknown,
): Promise<Readonly<XIngestionResult>> {
  const context = parseContext(contextInput);
  assertConcreteStorageDependencies(dependencies, context);
  const request = prepareRecentSearchRequest(query);
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
      durable?.dispatchedAt !== undefined &&
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
      durable?.dispatchedAt ?? undefined,
    );
  }
  if (existingEvent !== undefined) {
    throw new Error("capture event exists before its registry commit");
  }

  const collector = dependencies.collector;
  if (!isXRecentSearchCollector(collector)) {
    throw new Error("an authentic X recent-search collector is required before collection");
  }
  assertCollectorBinding(collector, context);
  if (collector.mode === "live") {
    readDurableNetworkBinding(dependencies, context, "pre-egress");
  }
  const attempt =
    existingAttempt === undefined
      ? beginNewAttempt(dependencies, context, request)
      : rebindExistingAttempt(dependencies.captureRegistry, existingAttempt, context, request);
  if (attempt.state !== "pending") throw new SnapshotIntegrityError();

  let response: QuarantinedXRecentSearchResponse | undefined;
  try {
    response = await collector.collectRaw(query);
    if (!(response instanceof QuarantinedXRecentSearchResponse)) {
      throw new Error("collector returned an invalid quarantine object");
    }
    assertResponseBinding(response, attempt, context, request);
    const durable =
      collector.mode === "live"
        ? readDurableNetworkBinding(dependencies, context, "post-response")
        : undefined;
    if (
      durable?.dispatchedAt !== undefined &&
      durable.dispatchedAt !== null &&
      (Date.parse(durable.dispatchedAt) < Date.parse(attempt.acquiredAt) ||
        Date.parse(durable.dispatchedAt) > Date.parse(response.metadata.acquiredAt))
    ) {
      throw new Error("network dispatch is outside its capture window");
    }

    // A concurrent caller can commit while this request is in flight. Resolve
    // the winner before publishing a second Vault capture whenever possible.
    const current = dependencies.captureRegistry.getAttempt(context.attemptId);
    if (current?.state === "committed") {
      assertAttemptContext(current, context, request);
      await assertResponseMatchesCommittedCapture(dependencies, current, response);
      return resumeCommittedAttempt(
        dependencies,
        context,
        current,
        request,
        durable?.dispatchedAt ?? undefined,
      );
    }
    if (current?.state !== "pending") throw new Error("capture attempt became terminal");

    return await captureAndCommit(
      dependencies,
      context,
      current,
      request,
      response,
      durable?.dispatchedAt ?? undefined,
    );
  } finally {
    response?.destroy();
  }
}
