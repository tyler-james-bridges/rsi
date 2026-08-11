import type { JsonValue, SqliteEventStore, StoredEvent } from "@rsi/store";
import type { SnapshotAddress, SnapshotVault } from "@rsi/vault";
import {
  X_RECENT_SEARCH_API_CONTRACT_VERSION,
  X_RECENT_SEARCH_ENDPOINT,
  XCollectorError,
  parseXRecentSearchResponse,
  type QuarantinedXRecentSearchResponse,
  type XRecentSearchCollector,
} from "@rsi/x-collector";

export const X_ARCHIVE_EVENT_TYPE = "source.x.archived" as const;
export const X_ARCHIVE_EVENT_SCHEMA_VERSION = 1 as const;

export type XArchiveStatus = "accepted" | "rejected";

export interface XIngestionDependencies {
  readonly collector: XRecentSearchCollector;
  readonly store: SqliteEventStore;
  readonly vault: SnapshotVault;
}

export interface XIngestionResult {
  readonly acquiredAt: string;
  readonly adapterId: "x.research";
  readonly authorCount: number | null;
  readonly eventHash: string;
  readonly eventId: string;
  readonly eventSequence: number;
  readonly failureCode: string | null;
  readonly postCount: number | null;
  readonly requestFingerprint: string;
  readonly responseHash: string;
  readonly snapshotAddress: SnapshotAddress;
  readonly snapshotCreated: boolean;
  readonly status: XArchiveStatus;
}

interface SafeArchiveProjection {
  readonly schemaVersion: typeof X_ARCHIVE_EVENT_SCHEMA_VERSION;
  readonly adapterId: "x.research";
  readonly apiContractVersion: typeof X_RECENT_SEARCH_API_CONTRACT_VERSION;
  readonly endpoint: typeof X_RECENT_SEARCH_ENDPOINT;
  readonly acquiredAt: string;
  readonly requestFingerprint: string;
  readonly responseHash: string;
  readonly snapshotAddress: string;
  readonly contentType: string;
  readonly byteLength: number;
  readonly provenance: "network" | "cassette";
  readonly rawContentPersisted: true;
  readonly rawContentEncrypted: true;
  readonly status: XArchiveStatus;
  readonly postCount: number | null;
  readonly authorCount: number | null;
  readonly editedPostCount: number | null;
  readonly failureCode: string | null;
}

function jsonValue(value: unknown): JsonValue {
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw new Error("archive projection is not JSON serializable");
  return JSON.parse(encoded) as JsonValue;
}

function safeFailureCode(error: unknown): string {
  return error instanceof XCollectorError ? error.code : "INVALID_RESPONSE_SCHEMA";
}

function idempotencyKey(response: QuarantinedXRecentSearchResponse): string {
  return [
    "x-archive-v1",
    response.metadata.requestFingerprint,
    response.metadata.responseHash,
    response.metadata.acquiredAt,
  ].join(":");
}

function appendArchiveEvent(
  store: SqliteEventStore,
  response: QuarantinedXRecentSearchResponse,
  projection: SafeArchiveProjection,
): StoredEvent {
  return store.append({
    aggregateId: `source:x.research:${response.metadata.requestFingerprint}`,
    idempotencyKey: idempotencyKey(response),
    occurredAt: response.metadata.acquiredAt,
    payload: jsonValue({ archive: projection }),
    type: X_ARCHIVE_EVENT_TYPE,
  });
}

function resultFor(
  event: StoredEvent,
  response: QuarantinedXRecentSearchResponse,
  snapshotAddress: SnapshotAddress,
  snapshotCreated: boolean,
  status: XArchiveStatus,
  postCount: number | null,
  authorCount: number | null,
  failureCode: string | null,
): Readonly<XIngestionResult> {
  return Object.freeze({
    acquiredAt: response.metadata.acquiredAt,
    adapterId: "x.research" as const,
    authorCount,
    eventHash: event.eventHash,
    eventId: event.eventId,
    eventSequence: event.sequence,
    failureCode,
    postCount,
    requestFingerprint: response.metadata.requestFingerprint,
    responseHash: response.metadata.responseHash,
    snapshotAddress,
    snapshotCreated,
    status,
  });
}

/**
 * Collects one bounded X recent-search response, encrypts its bytes before typed
 * parsing, and persists only a closed safe projection. Raw post text and the
 * canonical query never enter SQLite or the returned result.
 */
export async function ingestXRecentSearch(
  dependencies: Readonly<XIngestionDependencies>,
  query: unknown,
): Promise<Readonly<XIngestionResult>> {
  if (dependencies.collector.mode !== "live" && dependencies.collector.mode !== "replay") {
    throw new Error(
      "encrypt-first ingestion accepts only live or replay collectors; record mode can persist before the vault",
    );
  }
  const response = await dependencies.collector.collectRaw(query);
  const bytes = response.copyBytes();
  const snapshot = await dependencies.vault.put(bytes, {
    metadata: {
      format: X_RECENT_SEARCH_API_CONTRACT_VERSION,
      schemaVersion: X_ARCHIVE_EVENT_SCHEMA_VERSION,
    },
  });
  const expectedResponseHash = `sha256:${snapshot.address}`;
  if (expectedResponseHash !== response.metadata.responseHash) {
    throw new Error("snapshot address does not match quarantined response hash");
  }

  let status: XArchiveStatus = "accepted";
  let postCount: number | null = null;
  let authorCount: number | null = null;
  let editedPostCount: number | null = null;
  let failureCode: string | null = null;

  try {
    const parsed = parseXRecentSearchResponse(response);
    postCount = parsed.posts.length;
    authorCount = parsed.users.length;
    editedPostCount = parsed.posts.filter((post) => post.edit_history_post_ids.length > 1).length;
  } catch (error) {
    status = "rejected";
    failureCode = safeFailureCode(error);
  }

  const projection: SafeArchiveProjection = Object.freeze({
    schemaVersion: X_ARCHIVE_EVENT_SCHEMA_VERSION,
    adapterId: "x.research",
    apiContractVersion: X_RECENT_SEARCH_API_CONTRACT_VERSION,
    endpoint: X_RECENT_SEARCH_ENDPOINT,
    acquiredAt: response.metadata.acquiredAt,
    requestFingerprint: response.metadata.requestFingerprint,
    responseHash: response.metadata.responseHash,
    snapshotAddress: snapshot.address,
    contentType: response.metadata.contentType,
    byteLength: response.metadata.byteLength,
    provenance: response.metadata.provenance,
    rawContentPersisted: true,
    rawContentEncrypted: true,
    status,
    postCount,
    authorCount,
    editedPostCount,
    failureCode,
  });
  const event = appendArchiveEvent(dependencies.store, response, projection);
  return resultFor(
    event,
    response,
    snapshot.address,
    snapshot.created,
    status,
    postCount,
    authorCount,
    failureCode,
  );
}
