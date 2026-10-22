import { z } from "zod";

import {
  AttentionPreviewBindingSchema,
  AttentionPreviewSchema,
  AttentionRecordResultSchema,
  AttentionViewSchema,
} from "./history-schemas.js";
import { assertPlainAttentionData, deepFreeze, RecordedAttentionBundleSchema } from "./schemas.js";

export const AttentionPreviewCommandSchema = z.strictObject({
  input: RecordedAttentionBundleSchema,
});
export const AttentionRecordCommandSchema = z.strictObject({
  input: RecordedAttentionBundleSchema,
  expected: AttentionPreviewBindingSchema,
});

function parse<T>(schema: z.ZodType<T>, input: unknown): T {
  assertPlainAttentionData(input);
  return deepFreeze(schema.parse(input));
}

export const parseAttentionPreviewCommand = (input: unknown) =>
  parse(AttentionPreviewCommandSchema, input);
export const parseAttentionRecordCommand = (input: unknown) =>
  parse(AttentionRecordCommandSchema, input);
export const parseAttentionPreviewBinding = (input: unknown) =>
  parse(AttentionPreviewBindingSchema, input);
export const parseAttentionPreview = (input: unknown) => parse(AttentionPreviewSchema, input);
export const parseAttentionResult = (input: unknown) => parse(AttentionRecordResultSchema, input);
export const parseAttentionView = (input: unknown) => parse(AttentionViewSchema, input);
