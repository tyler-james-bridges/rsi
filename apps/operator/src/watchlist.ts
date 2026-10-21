import { types as utilTypes } from "node:util";

import { z } from "zod";
import {
  parseOfflineBaseWatchlistSnapshot,
  parseWatchlistPreviewBinding,
  snapshotId,
  type WatchlistPreviewBinding,
} from "@rsi/watchlist";

const Timestamp = z.string().refine((value) => {
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString() === value;
});
const Hash = z.string().regex(/^[0-9a-f]{64}$/);
const Snapshot = z.unknown().transform((value) => parseOfflineBaseWatchlistSnapshot(value));
const Binding = z.unknown().transform((value) => parseWatchlistPreviewBinding(value));
const Row = z.strictObject({
  collectionId: Hash,
  slug: z.string().regex(/^[a-z0-9][a-z0-9-]{0,127}$/),
  baseAddresses: z
    .array(z.string().regex(/^0x[0-9a-f]{40}$/))
    .min(1)
    .max(16),
  rank: z.number().int().min(1).max(10),
  previousRank: z.number().int().min(1).max(10).nullable(),
  change: z.enum(["new", "rank_changed", "unchanged", "left_window"]),
});
const Preview = z
  .strictObject({
    binding: Binding,
    snapshot: Snapshot,
    rows: z.array(Row).max(20),
    stale: z.boolean(),
    partial: z.boolean(),
  })
  .refine(
    (value) =>
      snapshotId(value.snapshot) === value.binding.snapshotId &&
      value.partial === value.snapshot.hasNextPage,
  );
const Result = z.strictObject({
  snapshotId: Hash,
  predecessorId: Hash.nullable(),
  importedAt: Timestamp,
  duplicate: z.boolean(),
});
const View = z.strictObject({
  schemaVersion: z.literal(1),
  provenance: z.literal("operator_supplied_unverified"),
  evaluatedAt: Timestamp,
  head: Hash.nullable(),
  stale: z.boolean(),
  partial: z.boolean(),
  rows: z.array(Row).max(20),
  history: z
    .array(
      z.strictObject({
        snapshotId: Hash,
        predecessorId: Hash.nullable(),
        acquiredAt: Timestamp,
        validUntil: Timestamp,
        importedAt: Timestamp,
        hasNextPage: z.boolean(),
      }),
    )
    .max(20),
});
const PreviewCommand = z.strictObject({ input: Snapshot });
const ConfirmCommand = z.strictObject({ input: Snapshot, expected: Binding });

export interface OperatorWatchlistProvider {
  previewWatchlist(input: unknown): unknown;
  confirmWatchlist(input: unknown, expected: WatchlistPreviewBinding): unknown;
  readWatchlist(): unknown;
}
function assertPlainResponse(input: unknown, depth = 0): void {
  if (depth > 12) throw new TypeError("Watchlist response is too deeply nested");
  if (input === null || typeof input !== "object") return;
  if (utilTypes.isProxy(input)) throw new TypeError("Watchlist response must be plain data");
  const array = Array.isArray(input);
  if (
    Object.getPrototypeOf(input) !== (array ? Array.prototype : Object.prototype) &&
    !(Object.getPrototypeOf(input) === null && !array)
  )
    throw new TypeError("Watchlist response must be plain data");
  const keys = Reflect.ownKeys(input);
  if (keys.length > 1000 || (array && keys.length !== input.length + 1))
    throw new TypeError("Watchlist response exceeds its bounds");
  for (const key of keys) {
    if (array && key === "length") continue;
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (
      typeof key !== "string" ||
      descriptor === undefined ||
      !("value" in descriptor) ||
      !descriptor.enumerable
    )
      throw new TypeError("Watchlist response must be plain data");
    assertPlainResponse(descriptor.value, depth + 1);
  }
}
function parse<T>(schema: z.ZodType<T>, input: unknown): T {
  assertPlainResponse(input);
  return schema.parse(input);
}
export const parseWatchlistPreviewCommand = (input: unknown) => parse(PreviewCommand, input);
export const parseWatchlistConfirmCommand = (input: unknown) => parse(ConfirmCommand, input);
export const parseWatchlistPreview = (input: unknown) => parse(Preview, input);
export const parseWatchlistResult = (input: unknown) => parse(Result, input);
export const parseWatchlistView = (input: unknown) => parse(View, input);
