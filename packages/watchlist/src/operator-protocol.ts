import { z } from "zod";

import { parseWatchlistPreviewBinding } from "./history.js";
import { assertPlainData, parseOfflineBaseWatchlistSnapshot, snapshotId } from "./snapshot.js";

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

function parse<T>(schema: z.ZodType<T>, input: unknown): T {
  assertPlainData(input);
  return schema.parse(input);
}

export const parseWatchlistPreviewCommand = (input: unknown) => parse(PreviewCommand, input);
export const parseWatchlistConfirmCommand = (input: unknown) => parse(ConfirmCommand, input);
export const parseWatchlistPreview = (input: unknown) => parse(Preview, input);
export const parseWatchlistResult = (input: unknown) => parse(Result, input);
export const parseWatchlistView = (input: unknown) => parse(View, input);
