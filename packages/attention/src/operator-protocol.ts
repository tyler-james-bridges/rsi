import { z } from "zod";

import {
  AttentionAuditHeadSchema,
  AttentionHistoryHeaderSchema,
  AttentionPreviewBindingSchema,
  AttentionPreviewSchema,
  AttentionRecordResultSchema,
  AttentionViewRowSchema,
  AttentionViewSchema,
  effectiveRow,
  serialize,
  type AttentionPreview,
  type AttentionRecordResult,
  type AttentionView,
} from "./history-schemas.js";
import {
  assertPlainAttentionData,
  CanonicalTimeSchema,
  CollectionAttentionAssessmentSchema,
  deepFreeze,
  RecordedAttentionBundleSchema,
} from "./schemas.js";

export const AttentionPreviewCommandSchema = z.strictObject({
  input: RecordedAttentionBundleSchema,
});
export const AttentionRecordCommandSchema = z.strictObject({
  input: RecordedAttentionBundleSchema,
  expected: AttentionPreviewBindingSchema,
});

export const AttentionOperatorResultSchema = z
  .strictObject({
    schemaVersion: z.literal(2),
    kind: z.literal("recorded_attention_result"),
    binding: AttentionPreviewBindingSchema,
    assessment: CollectionAttentionAssessmentSchema,
    checkpointAt: CanonicalTimeSchema,
  })
  .refine(({ binding, assessment, checkpointAt }) => {
    return (
      assessment.policyVersion === binding.policyVersion &&
      assessment.bundleId === binding.bundleId &&
      assessment.refreshId === binding.refreshId &&
      assessment.predecessorId === (binding.auditHead?.refreshId ?? null) &&
      assessment.evaluatedAt === binding.evaluatedAt &&
      Date.parse(binding.evaluatedAt) <= Date.parse(checkpointAt) &&
      Date.parse(checkpointAt) < Date.parse(binding.deadline)
    );
  }, "attention operator result is inconsistent");

export const AttentionOperatorPreviewSchema = z.discriminatedUnion("kind", [
  z
    .strictObject({
      schemaVersion: z.literal(2),
      kind: z.literal("preview"),
      binding: AttentionPreviewBindingSchema,
      assessment: CollectionAttentionAssessmentSchema,
    })
    .refine(
      ({ binding, assessment }) =>
        assessment.bundleId === binding.bundleId &&
        assessment.refreshId === binding.refreshId &&
        assessment.predecessorId === (binding.auditHead?.refreshId ?? null) &&
        assessment.evaluatedAt === binding.evaluatedAt,
      "attention operator preview is inconsistent",
    ),
  z.strictObject({
    schemaVersion: z.literal(2),
    kind: z.literal("already_recorded"),
    result: AttentionOperatorResultSchema,
  }),
]);

export const AttentionOperatorViewSchema = z.discriminatedUnion("kind", [
  z
    .strictObject({
      schemaVersion: z.literal(1),
      kind: z.literal("available"),
      provenance: z.literal("operator_supplied_unverified"),
      evaluatedAt: CanonicalTimeSchema,
      auditHead: AttentionAuditHeadSchema.nullable(),
      latest: AttentionOperatorResultSchema.nullable(),
      rows: z.array(AttentionViewRowSchema).max(20),
      history: z.array(AttentionHistoryHeaderSchema).max(20),
    })
    .superRefine((view, context) => {
      if (view.latest === null) {
        if (view.auditHead !== null || view.rows.length !== 0 || view.history.length !== 0) {
          context.addIssue({ code: "custom", message: "empty attention view is inconsistent" });
        }
        return;
      }
      if (
        Date.parse(view.evaluatedAt) < Date.parse(view.latest.checkpointAt) ||
        view.auditHead?.refreshId !== view.latest.assessment.refreshId ||
        serialize(view.auditHead) !== serialize(view.history[0]?.head ?? null) ||
        serialize(view.rows) !==
          serialize(
            view.latest.assessment.rows.map((saved) => effectiveRow(saved, view.evaluatedAt)),
          )
      ) {
        context.addIssue({ code: "custom", message: "attention view is inconsistent" });
      }
    }),
  z
    .strictObject({
      schemaVersion: z.literal(1),
      kind: z.literal("unavailable"),
      reason: z.literal("clock_regressed"),
      evaluatedAt: CanonicalTimeSchema,
      latestCheckpointAt: CanonicalTimeSchema,
    })
    .refine((view) => Date.parse(view.evaluatedAt) < Date.parse(view.latestCheckpointAt)),
]);

export type AttentionOperatorResult = z.infer<typeof AttentionOperatorResultSchema>;
export type AttentionOperatorPreview = z.infer<typeof AttentionOperatorPreviewSchema>;
export type AttentionOperatorView = z.infer<typeof AttentionOperatorViewSchema>;

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

function projectResult(result: AttentionRecordResult): AttentionOperatorResult {
  return AttentionOperatorResultSchema.parse({
    schemaVersion: result.schemaVersion,
    kind: result.kind,
    binding: result.binding,
    assessment: result.assessment,
    checkpointAt: result.checkpointAt,
  });
}

export function projectAttentionOperatorResult(input: unknown): AttentionOperatorResult {
  assertPlainAttentionData(input);
  const projected = AttentionOperatorResultSchema.safeParse(input);
  if (projected.success) return deepFreeze(projected.data);
  return deepFreeze(projectResult(AttentionRecordResultSchema.parse(input)));
}

export function projectAttentionOperatorPreview(input: unknown): AttentionOperatorPreview {
  assertPlainAttentionData(input);
  const projected = AttentionOperatorPreviewSchema.safeParse(input);
  if (projected.success) return deepFreeze(projected.data);
  const preview: AttentionPreview = AttentionPreviewSchema.parse(input);
  return deepFreeze(
    AttentionOperatorPreviewSchema.parse(
      preview.kind === "preview"
        ? preview
        : {
            schemaVersion: preview.schemaVersion,
            kind: preview.kind,
            result: projectResult(preview.result),
          },
    ),
  );
}

export function projectAttentionOperatorView(input: unknown): AttentionOperatorView {
  assertPlainAttentionData(input);
  const projected = AttentionOperatorViewSchema.safeParse(input);
  if (projected.success) return deepFreeze(projected.data);
  const view: AttentionView = AttentionViewSchema.parse(input);
  return deepFreeze(
    AttentionOperatorViewSchema.parse(
      view.kind === "unavailable"
        ? view
        : {
            ...view,
            latest: view.latest === null ? null : projectResult(view.latest),
          },
    ),
  );
}
