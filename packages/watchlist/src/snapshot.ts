import { createHash } from "node:crypto";
import { types as utilTypes } from "node:util";

import { OPENSEA_TRENDING_CONTRACT_VERSION } from "@rsi/source-contracts/opensea-trending-version";
import { canonicalJson } from "@rsi/store";
import { z } from "zod";

export class WatchlistConflictError extends Error {}

export const Timestamp = z
  .string()
  .max(32)
  .refine((value) => {
    const time = Date.parse(value);
    return Number.isFinite(time) && new Date(time).toISOString() === value;
  });
export const SnapshotIdSchema = z
  .string()
  .regex(/^[0-9a-f]{64}$/)
  .brand<"SnapshotId">();
export const CollectionIdSchema = z
  .string()
  .regex(/^[0-9a-f]{64}$/)
  .brand<"CollectionId">();
export type SnapshotId = z.infer<typeof SnapshotIdSchema>;
export type CollectionId = z.infer<typeof CollectionIdSchema>;

const Collection = z.strictObject({
  rank: z.number().int().min(1).max(10),
  slug: z.string().regex(/^[a-z0-9][a-z0-9-]{0,127}$/),
  baseAddresses: z
    .array(z.string().regex(/^0x[0-9a-fA-F]{40}$/))
    .min(1)
    .max(16),
});
export const SnapshotSchema = z.strictObject({
  schemaVersion: z.literal(1),
  kind: z.literal("offline_opensea_trending"),
  sourceContractVersion: z.literal(OPENSEA_TRENDING_CONTRACT_VERSION),
  acquiredAt: Timestamp,
  validUntil: Timestamp,
  hasNextPage: z.boolean(),
  collections: z.array(Collection).max(10),
});

export type OfflineBaseWatchlistSnapshotV1 = z.infer<typeof SnapshotSchema>;
export type NormalizedOfflineBaseWatchlistSnapshotV1 = Readonly<
  Omit<OfflineBaseWatchlistSnapshotV1, "collections"> & {
    collections: readonly Readonly<{
      rank: number;
      slug: string;
      baseAddresses: readonly string[];
    }>[];
  }
>;

export function assertPlainData(value: unknown, depth = 0): void {
  if (depth > 12) throw new TypeError("Watchlist data is too deeply nested");
  if (value === null || typeof value !== "object") return;
  if (utilTypes.isProxy(value)) throw new TypeError("Watchlist data must be plain");
  const array = Array.isArray(value);
  if (array && Object.getPrototypeOf(value) !== Array.prototype) {
    throw new TypeError("Watchlist arrays must be plain");
  }
  if (
    !array &&
    Object.getPrototypeOf(value) !== Object.prototype &&
    Object.getPrototypeOf(value) !== null
  ) {
    throw new TypeError("Watchlist data must be plain");
  }
  const keys = Reflect.ownKeys(value);
  if (array && (value.length > 1000 || keys.length !== value.length + 1)) {
    throw new TypeError("Watchlist arrays must be dense and bounded");
  }
  for (const key of keys) {
    if (array && key === "length") continue;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      typeof key !== "string" ||
      !descriptor ||
      !("value" in descriptor) ||
      !descriptor.enumerable ||
      (array && (!/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= value.length))
    ) {
      throw new TypeError("Watchlist data must contain only plain values");
    }
    assertPlainData(descriptor.value, depth + 1);
  }
}

export function parseOfflineBaseWatchlistSnapshot(
  input: unknown,
): NormalizedOfflineBaseWatchlistSnapshotV1 {
  assertPlainData(input);
  const parsed = SnapshotSchema.parse(input);
  if (Date.parse(parsed.validUntil) - Date.parse(parsed.acquiredAt) !== 120_000) {
    throw new TypeError("Watchlist validity must be exactly 120 seconds");
  }
  const slugs = new Set<string>();
  const addresses = new Set<string>();
  const collections = parsed.collections.map((collection, index) => {
    if (collection.rank !== index + 1 || slugs.has(collection.slug)) {
      throw new TypeError("Watchlist ranks and slugs must be unique and ordered");
    }
    slugs.add(collection.slug);
    const baseAddresses = collection.baseAddresses.map((address) => address.toLowerCase()).sort();
    for (const address of baseAddresses) {
      if (addresses.has(address)) throw new TypeError("Watchlist contract groups must not overlap");
      addresses.add(address);
    }
    return Object.freeze({ ...collection, baseAddresses: Object.freeze(baseAddresses) });
  });
  return Object.freeze({ ...parsed, collections: Object.freeze(collections) });
}

export function collectionId(
  collection: NormalizedOfflineBaseWatchlistSnapshotV1["collections"][number],
): CollectionId {
  return CollectionIdSchema.parse(
    createHash("sha256")
      .update("rsi-watchlist-collection-v1\0")
      .update(canonicalJson([...collection.baseAddresses]))
      .digest("hex"),
  );
}

export function snapshotId(snapshot: NormalizedOfflineBaseWatchlistSnapshotV1): SnapshotId {
  return SnapshotIdSchema.parse(
    createHash("sha256")
      .update("rsi-watchlist-snapshot-v1\0")
      .update(
        canonicalJson({
          ...snapshot,
          collections: snapshot.collections.map((row) => ({
            ...row,
            baseAddresses: [...row.baseAddresses],
          })),
        }),
      )
      .digest("hex"),
  );
}

export interface WatchlistRow {
  readonly collectionId: CollectionId;
  readonly slug: string;
  readonly baseAddresses: readonly string[];
  readonly rank: number;
  readonly previousRank: number | null;
  readonly change: "new" | "rank_changed" | "unchanged" | "left_window";
}

export function compareSnapshots(
  current: NormalizedOfflineBaseWatchlistSnapshotV1,
  previous: NormalizedOfflineBaseWatchlistSnapshotV1 | null,
): readonly WatchlistRow[] {
  const prior = new Map(previous?.collections.map((row) => [collectionId(row), row]));
  const rows: WatchlistRow[] = current.collections.map((row) => {
    const id = collectionId(row);
    const before = prior.get(id);
    prior.delete(id);
    return Object.freeze({
      ...row,
      collectionId: id,
      previousRank: before?.rank ?? null,
      change:
        before === undefined ? "new" : before.rank === row.rank ? "unchanged" : "rank_changed",
    });
  });
  rows.sort((a, b) => a.rank - b.rank || a.collectionId.localeCompare(b.collectionId));
  const left = [...prior].map(([id, row]): WatchlistRow =>
    Object.freeze({ ...row, collectionId: id, previousRank: row.rank, change: "left_window" }),
  );
  left.sort((a, b) => a.rank - b.rank || a.collectionId.localeCompare(b.collectionId));
  return Object.freeze([...rows, ...left]);
}
