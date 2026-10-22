import { RuntimeAllowedAttentionRefreshReceiptSchema, RuntimeUuidSchema } from "@rsi/runtime";
import { z } from "zod";

import { canonicalJson, hashCanonical } from "./hash.js";
import { toJsonValue } from "./json-types.js";
import {
  ATTENTION_POLICY_VERSION,
  AssessmentRowSchema,
  BundleIdSchema,
  CanonicalTimeSchema,
  CollectionAttentionAssessmentSchema,
  HashSchema,
  NextActionSchema,
  OutcomeSchema,
  RecordedAttentionFactsSchema,
  RefreshIdSchema,
  SanitizedRecordedBundleSchema,
  type RecordedAttentionAssessmentResultV1,
} from "./schemas.js";

export const ATTENTION_PREVIEW_TTL_MS = 30_000;
export const MAX_ATTENTION_HISTORY = 1_000;
export const MAX_ATTENTION_EVENT_BYTES = 524_288;
const Sequence = z.number().int().min(1).max(Number.MAX_SAFE_INTEGER);

export const AttentionAuditHeadSchema = z.strictObject({
  refreshId: RefreshIdSchema,
  eventHash: HashSchema,
  sequence: Sequence,
});

export const AttentionPreviewContextSchema = z.strictObject({
  processInstanceId: RuntimeUuidSchema,
  modeRevision: Sequence,
  evaluatedAt: CanonicalTimeSchema,
});

export const AttentionPreviewBindingSchema = z
  .strictObject({
    policyVersion: z.literal(ATTENTION_POLICY_VERSION),
    bundleId: BundleIdSchema,
    refreshId: RefreshIdSchema,
    auditHead: AttentionAuditHeadSchema.nullable(),
    processInstanceId: RuntimeUuidSchema,
    modeRevision: Sequence,
    evaluatedAt: CanonicalTimeSchema,
    deadline: CanonicalTimeSchema,
    decisionHash: HashSchema,
  })
  .refine(
    (binding) =>
      Date.parse(binding.deadline) - Date.parse(binding.evaluatedAt) === ATTENTION_PREVIEW_TTL_MS,
    "attention preview deadline must be exactly 30 seconds",
  );

export const AttentionReceiptSchema = RuntimeAllowedAttentionRefreshReceiptSchema.extend({
  actionId: RefreshIdSchema,
  checkedAt: CanonicalTimeSchema,
});

export const AttentionRecordResultSchema = z
  .strictObject({
    schemaVersion: z.literal(1),
    kind: z.literal("recorded_attention_result"),
    binding: AttentionPreviewBindingSchema,
    assessment: CollectionAttentionAssessmentSchema,
    authorization: AttentionReceiptSchema,
    checkpointAt: CanonicalTimeSchema,
  })
  .refine((value) => {
    const { binding, assessment, authorization, checkpointAt } = value;
    return (
      assessment.policyVersion === binding.policyVersion &&
      assessment.bundleId === binding.bundleId &&
      assessment.refreshId === binding.refreshId &&
      assessment.predecessorId === (binding.auditHead?.refreshId ?? null) &&
      assessment.evaluatedAt === binding.evaluatedAt &&
      authorization.actionId === binding.refreshId &&
      authorization.processInstanceId === binding.processInstanceId &&
      authorization.modeRevision === binding.modeRevision &&
      Date.parse(binding.evaluatedAt) <= Date.parse(authorization.checkedAt) &&
      Date.parse(authorization.checkedAt) <= Date.parse(checkpointAt) &&
      Date.parse(checkpointAt) < Date.parse(binding.deadline)
    );
  }, "attention record binding is inconsistent");

export const AttentionRecordedEventSchema = z.strictObject({
  result: AttentionRecordResultSchema,
  sourceFacts: SanitizedRecordedBundleSchema,
  nextFacts: RecordedAttentionFactsSchema,
});

export const AttentionPreviewSchema = z.discriminatedUnion("kind", [
  z
    .strictObject({
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
    ),
  z.strictObject({ kind: z.literal("already_recorded"), result: AttentionRecordResultSchema }),
]);

export const AttentionHistoryHeaderSchema = z.strictObject({
  head: AttentionAuditHeadSchema,
  bundleId: BundleIdSchema,
  predecessorId: RefreshIdSchema.nullable(),
  acquiredAt: CanonicalTimeSchema,
  validUntil: CanonicalTimeSchema,
  evaluatedAt: CanonicalTimeSchema,
  checkpointAt: CanonicalTimeSchema,
  usableRankWindow: z.boolean(),
});

export const AttentionViewRowSchema = z.strictObject({
  saved: AssessmentRowSchema,
  expired: z.boolean(),
  effectiveOutcome: OutcomeSchema,
  effectiveNextAction: NextActionSchema,
});

export const AttentionViewSchema = z.discriminatedUnion("kind", [
  z
    .strictObject({
      schemaVersion: z.literal(1),
      kind: z.literal("available"),
      provenance: z.literal("operator_supplied_unverified"),
      evaluatedAt: CanonicalTimeSchema,
      auditHead: AttentionAuditHeadSchema.nullable(),
      latest: AttentionRecordResultSchema.nullable(),
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
      )
        context.addIssue({ code: "custom", message: "attention view is inconsistent" });
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

export type AttentionPreviewContext = z.infer<typeof AttentionPreviewContextSchema>;
export type AttentionPreviewBinding = z.infer<typeof AttentionPreviewBindingSchema>;
export type AttentionPreview = z.infer<typeof AttentionPreviewSchema>;
export type AttentionRecordResult = z.infer<typeof AttentionRecordResultSchema>;
export type AttentionView = z.infer<typeof AttentionViewSchema>;
export type AttentionRecordedEvent = z.infer<typeof AttentionRecordedEventSchema>;
export type AttentionAuditHead = z.infer<typeof AttentionAuditHeadSchema>;

export function effectiveRow(
  saved: z.infer<typeof AssessmentRowSchema>,
  evaluatedAt: string,
): z.infer<typeof AttentionViewRowSchema> {
  const expired = Date.parse(evaluatedAt) >= Date.parse(saved.expiresAt);
  const overlay = expired && saved.outcome.kind !== "rejected";
  return {
    saved,
    expired,
    effectiveOutcome: overlay
      ? { kind: "watch", reasons: ["ASSESSMENT_EXPIRED"], priority: 0 }
      : saved.outcome,
    effectiveNextAction: overlay ? "supply_new_recorded_rank_window" : saved.nextAction,
  };
}

export function decisionHash(result: RecordedAttentionAssessmentResultV1): string {
  const { evaluatedAt, ...assessment } = result.assessment;
  return hashCanonical(
    "rsi-attention-decision-v1\0",
    toJsonValue({
      assessment: {
        ...assessment,
        rows: assessment.rows.map(({ assessedAt: _assessedAt, ...row }) => ({
          ...row,
          expired: Date.parse(evaluatedAt) >= Date.parse(row.expiresAt),
        })),
      },
      nextFacts: result.nextFacts,
    }),
  );
}

export function serialize(value: unknown): string {
  return canonicalJson(toJsonValue(value));
}
