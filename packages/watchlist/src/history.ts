import { isRuntimeBoundaryAuthorization, type RuntimeBoundaryAuthorization } from "@rsi/runtime";
import { canonicalJson, SqliteEventStore } from "@rsi/store";
import { z } from "zod";

import {
  assertPlainData,
  compareSnapshots,
  parseOfflineBaseWatchlistSnapshot,
  SnapshotSchema,
  SnapshotIdSchema,
  snapshotId,
  Timestamp,
  WatchlistConflictError,
  type NormalizedOfflineBaseWatchlistSnapshotV1,
  type SnapshotId,
  type WatchlistRow,
} from "./snapshot.js";

const Uuid = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
const Revision = z.number().int().min(1).max(Number.MAX_SAFE_INTEGER);
export const PreviewContextSchema = z.strictObject({
  processInstanceId: Uuid,
  modeRevision: Revision,
  evaluatedAt: Timestamp,
});
export const PreviewBindingSchema = z.strictObject({
  snapshotId: SnapshotIdSchema,
  predecessorId: SnapshotIdSchema.nullable(),
  processInstanceId: Uuid,
  modeRevision: Revision,
});
export type PreviewContext = z.infer<typeof PreviewContextSchema>;
export type WatchlistPreviewBinding = z.infer<typeof PreviewBindingSchema>;

const RecordedSchema = z.strictObject({
  snapshotId: SnapshotIdSchema,
  predecessorId: SnapshotIdSchema.nullable(),
  snapshot: SnapshotSchema,
  importedAt: Timestamp,
  authorization: z.strictObject({
    boundary: z.literal("watchlist_import"),
    authorizationId: Uuid,
    processInstanceId: Uuid,
    mode: z.literal("RESEARCH"),
    modeRevision: Revision,
    checkedAt: Timestamp,
    eventHash: z.string().regex(/^[0-9a-f]{64}$/),
  }),
});
type Recorded = Omit<z.infer<typeof RecordedSchema>, "snapshot"> & {
  readonly snapshot: NormalizedOfflineBaseWatchlistSnapshotV1;
};

export interface WatchlistImportPreview {
  readonly binding: WatchlistPreviewBinding;
  readonly snapshot: NormalizedOfflineBaseWatchlistSnapshotV1;
  readonly rows: readonly WatchlistRow[];
  readonly stale: boolean;
  readonly partial: boolean;
}
export interface WatchlistImportCommand {
  readonly input: unknown;
  readonly expected: WatchlistPreviewBinding;
  readonly authorization: RuntimeBoundaryAuthorization<"watchlist_import">;
}
export interface WatchlistImportResult {
  readonly snapshotId: SnapshotId;
  readonly predecessorId: SnapshotId | null;
  readonly importedAt: string;
  readonly duplicate: boolean;
}
export interface WatchlistView {
  readonly schemaVersion: 1;
  readonly provenance: "operator_supplied_unverified";
  readonly evaluatedAt: string;
  readonly head: SnapshotId | null;
  readonly stale: boolean;
  readonly partial: boolean;
  readonly rows: readonly WatchlistRow[];
  readonly history: readonly Readonly<{
    snapshotId: SnapshotId;
    predecessorId: SnapshotId | null;
    acquiredAt: string;
    validUntil: string;
    importedAt: string;
    hasNextPage: boolean;
  }>[];
}

function serialize(snapshot: NormalizedOfflineBaseWatchlistSnapshotV1): string {
  return canonicalJson({
    ...snapshot,
    collections: snapshot.collections.map((row) => ({
      ...row,
      baseAddresses: [...row.baseAddresses],
    })),
  });
}

function replay(store: SqliteEventStore): readonly Recorded[] {
  const events = store.list();
  if (events.length > 1000) throw new WatchlistConflictError("Watchlist history exceeds its bound");
  const records: Recorded[] = [];
  const ids = new Set<string>();
  const authorizations = new Set<string>();
  for (const event of events) {
    const parsed = RecordedSchema.parse(event.payload);
    const snapshot = parseOfflineBaseWatchlistSnapshot(parsed.snapshot);
    const prior = records.at(-1);
    if (
      event.type !== "watchlist.snapshot.recorded.v1" ||
      event.aggregateId !== "watchlist:base" ||
      event.idempotencyKey !== `watchlist-snapshot-v1:${parsed.snapshotId}` ||
      event.occurredAt !== parsed.importedAt ||
      parsed.authorization.checkedAt !== parsed.importedAt ||
      parsed.snapshotId !== snapshotId(snapshot) ||
      serialize(snapshot) !== canonicalJson(parsed.snapshot) ||
      parsed.predecessorId !== (prior?.snapshotId ?? null) ||
      (prior !== undefined && snapshot.acquiredAt <= prior.snapshot.acquiredAt) ||
      ids.has(parsed.snapshotId) ||
      authorizations.has(parsed.authorization.authorizationId)
    ) {
      throw new WatchlistConflictError("Watchlist history is inconsistent");
    }
    ids.add(parsed.snapshotId);
    authorizations.add(parsed.authorization.authorizationId);
    records.push(
      Object.freeze({ ...parsed, authorization: Object.freeze(parsed.authorization), snapshot }),
    );
  }
  return records;
}

export class OfflineBaseWatchlist {
  readonly #store: SqliteEventStore;
  static open(path: string): OfflineBaseWatchlist {
    const store = new SqliteEventStore(path);
    try {
      store.withExclusiveTransaction(() => replay(store));
      return new OfflineBaseWatchlist(store);
    } catch (error) {
      store.close();
      throw error;
    }
  }
  private constructor(store: SqliteEventStore) {
    this.#store = store;
  }

  preview(input: unknown, context: PreviewContext): WatchlistImportPreview {
    const snapshot = parseOfflineBaseWatchlistSnapshot(input);
    assertPlainData(context);
    const parsedContext = PreviewContextSchema.parse(context);
    return this.#store.withExclusiveTransaction(() => {
      const records = replay(this.#store);
      const previous = records.at(-1);
      return Object.freeze({
        binding: Object.freeze({
          snapshotId: snapshotId(snapshot),
          predecessorId: previous?.snapshotId ?? null,
          processInstanceId: parsedContext.processInstanceId,
          modeRevision: parsedContext.modeRevision,
        }),
        snapshot,
        rows: compareSnapshots(snapshot, previous?.snapshot ?? null),
        stale: parsedContext.evaluatedAt >= snapshot.validUntil,
        partial: snapshot.hasNextPage,
      });
    });
  }

  import(command: WatchlistImportCommand): WatchlistImportResult {
    const descriptors = Object.getOwnPropertyDescriptors(command);
    if (
      Reflect.ownKeys(command).length !== 3 ||
      !["input", "expected", "authorization"].every(
        (key) => descriptors[key]?.enumerable && "value" in descriptors[key]!,
      )
    )
      throw new TypeError("Invalid watchlist command");
    const snapshot = parseOfflineBaseWatchlistSnapshot(command.input);
    assertPlainData(command.expected);
    const expected = PreviewBindingSchema.parse(command.expected);
    const authorization = command.authorization;
    if (
      !isRuntimeBoundaryAuthorization(authorization) ||
      authorization.boundary !== "watchlist_import" ||
      authorization.actionId !== snapshotId(snapshot) ||
      expected.snapshotId !== snapshotId(snapshot) ||
      authorization.processInstanceId !== expected.processInstanceId ||
      authorization.requestedRevision !== expected.modeRevision ||
      authorization.requestedMode !== "RESEARCH"
    ) {
      throw new WatchlistConflictError(
        "Watchlist confirmation does not match its preview authority",
      );
    }
    let result: WatchlistImportResult | undefined;
    authorization.consumeAndCommit((receipt) => {
      result = this.#store.withExclusiveTransaction(() => {
        const records = replay(this.#store);
        const existing = records.find((record) => record.snapshotId === expected.snapshotId);
        if (existing !== undefined) {
          if (
            existing.predecessorId !== expected.predecessorId ||
            serialize(existing.snapshot) !== serialize(snapshot)
          )
            throw new WatchlistConflictError("Snapshot identity was reused");
          return Object.freeze({
            snapshotId: existing.snapshotId,
            predecessorId: existing.predecessorId,
            importedAt: existing.importedAt,
            duplicate: true,
          });
        }
        const head = records.at(-1);
        if (expected.predecessorId !== (head?.snapshotId ?? null))
          throw new WatchlistConflictError("Watchlist preview head is stale");
        if (head !== undefined && snapshot.acquiredAt <= head.snapshot.acquiredAt)
          throw new WatchlistConflictError("Acquisition time must increase");
        if (records.length >= 1000) throw new WatchlistConflictError("Watchlist history is full");
        const payload = RecordedSchema.parse({
          snapshotId: expected.snapshotId,
          predecessorId: expected.predecessorId,
          snapshot,
          importedAt: receipt.checkedAt,
          authorization: {
            boundary: receipt.boundary,
            authorizationId: receipt.authorizationId,
            processInstanceId: receipt.processInstanceId,
            mode: receipt.mode,
            modeRevision: receipt.modeRevision,
            checkedAt: receipt.checkedAt,
            eventHash: receipt.eventHash,
          },
        });
        this.#store.append({
          type: "watchlist.snapshot.recorded.v1",
          aggregateId: "watchlist:base",
          idempotencyKey: `watchlist-snapshot-v1:${expected.snapshotId}`,
          occurredAt: payload.importedAt,
          payload,
        });
        return Object.freeze({
          snapshotId: payload.snapshotId,
          predecessorId: payload.predecessorId,
          importedAt: payload.importedAt,
          duplicate: false,
        });
      });
    });
    if (result === undefined) throw new WatchlistConflictError("Watchlist commit did not run");
    return result;
  }

  read(evaluatedAt: string): WatchlistView {
    Timestamp.parse(evaluatedAt);
    return this.#store.withExclusiveTransaction(() => {
      const records = replay(this.#store);
      const current = records.at(-1);
      return Object.freeze({
        schemaVersion: 1,
        provenance: "operator_supplied_unverified",
        evaluatedAt,
        head: current?.snapshotId ?? null,
        stale: current !== undefined && evaluatedAt >= current.snapshot.validUntil,
        partial: current?.snapshot.hasNextPage ?? false,
        rows:
          current === undefined
            ? Object.freeze([])
            : compareSnapshots(current.snapshot, records.at(-2)?.snapshot ?? null),
        history: Object.freeze(
          records
            .slice(-20)
            .reverse()
            .map((record) =>
              Object.freeze({
                snapshotId: record.snapshotId,
                predecessorId: record.predecessorId,
                acquiredAt: record.snapshot.acquiredAt,
                validUntil: record.snapshot.validUntil,
                importedAt: record.importedAt,
                hasNextPage: record.snapshot.hasNextPage,
              }),
            ),
        ),
      });
    });
  }
  close(): void {
    this.#store.close();
  }
}
