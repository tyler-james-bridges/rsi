import type { JsonValue, SqliteEventStore, StoredEvent } from "@rsi/store";
import { z } from "zod";

import {
  CanonicalTimestampSchema,
  OperationsProfileSchema,
  ResearchLaneSchema,
  SourcePlaneSchema,
  UuidSchema,
  parseWithSchema,
} from "./schemas.js";

export const CAPTURE_RECORDED_EVENT_TYPE = "source.capture.recorded.v2" as const;
export const CAPTURE_DELETED_EVENT_TYPE = "source.capture.deleted.v1" as const;

const CountSchema = z.number().int().min(0).max(100_000);

const CaptureCountsSchema = z
  .strictObject({
    actorCount: CountSchema,
    editedRecordCount: CountSchema,
    recordCount: CountSchema,
  })
  .superRefine((value, context) => {
    if (value.editedRecordCount > value.recordCount) {
      context.addIssue({
        code: "custom",
        path: ["editedRecordCount"],
        message: "cannot exceed recordCount",
      });
    }
  });

export const CaptureFailureCodeSchema = z.enum([
  "ABORTED",
  "CONTENT_LENGTH_MISMATCH",
  "CREDENTIAL_IN_RESPONSE",
  "HTTP_STATUS",
  "INVALID_RESPONSE_SCHEMA",
  "MALFORMED_JSON",
  "RESPONSE_TOO_LARGE",
  "TIMEOUT",
  "TRANSPORT_FAILURE",
  "UNSUPPORTED_CONTENT_ENCODING",
  "UNSUPPORTED_CONTENT_TYPE",
]);

export const CaptureRecordedPayloadSchema = z
  .strictObject({
    acquiredAt: CanonicalTimestampSchema,
    attemptId: UuidSchema,
    byteLength: z.number().int().min(0).max(2_097_152),
    counts: CaptureCountsSchema.nullable(),
    expiresAt: CanonicalTimestampSchema,
    failureCode: CaptureFailureCodeSchema.nullable(),
    lane: ResearchLaneSchema,
    profile: OperationsProfileSchema,
    rawDisposition: z.literal("encrypted_ephemeral"),
    schemaVersion: z.literal(2),
    sessionId: UuidSchema,
    sourcePlane: SourcePlaneSchema,
    status: z.enum(["accepted", "rejected"]),
  })
  .superRefine((value, context) => {
    const acquired = Date.parse(value.acquiredAt);
    const expires = Date.parse(value.expiresAt);
    const maximumBytes = value.sourcePlane === "marketplace" ? 2_097_152 : 1_048_576;
    if (value.byteLength > maximumBytes) {
      context.addIssue({
        code: "custom",
        path: ["byteLength"],
        message: `${value.sourcePlane} captures cannot exceed ${maximumBytes} bytes`,
      });
    }
    if (expires < acquired || expires - acquired > 2 * 60 * 60 * 1_000) {
      context.addIssue({
        code: "custom",
        path: ["expiresAt"],
        message: "must be between acquiredAt and two hours after acquiredAt",
      });
    }
    if (value.status === "accepted" && (value.counts === null || value.failureCode !== null)) {
      context.addIssue({
        code: "custom",
        message: "accepted captures require counts and no failureCode",
      });
    }
    if (value.status === "rejected" && (value.counts !== null || value.failureCode === null)) {
      context.addIssue({
        code: "custom",
        message: "rejected captures require a failureCode and no counts",
      });
    }
  });

export const CaptureDeletedPayloadSchema = z.strictObject({
  deletedAt: CanonicalTimestampSchema,
  deletionId: UuidSchema,
  expiredCount: CountSchema,
  explicitCount: CountSchema,
  orphanCount: CountSchema,
  profile: OperationsProfileSchema,
  schemaVersion: z.literal(1),
  sessionId: UuidSchema,
  sourcePlane: SourcePlaneSchema,
  status: z.literal("verified"),
});

export const CaptureRecordedEventPayloadSchema = z.strictObject({
  capture: CaptureRecordedPayloadSchema,
});

export const CaptureDeletedEventPayloadSchema = z.strictObject({
  deletion: CaptureDeletedPayloadSchema,
});

export type CaptureRecordedPayload = z.infer<typeof CaptureRecordedPayloadSchema>;
export type CaptureDeletedPayload = z.infer<typeof CaptureDeletedPayloadSchema>;
export type CaptureRecordedEventPayload = z.infer<typeof CaptureRecordedEventPayloadSchema>;
export type CaptureDeletedEventPayload = z.infer<typeof CaptureDeletedEventPayloadSchema>;

function toJson(value: unknown): JsonValue {
  return JSON.parse(JSON.stringify(value)) as JsonValue;
}

export function parseCaptureRecordedPayload(value: unknown): CaptureRecordedPayload {
  return parseWithSchema(CaptureRecordedPayloadSchema, value, "capture recorded payload");
}

export function parseCaptureDeletedPayload(value: unknown): CaptureDeletedPayload {
  return parseWithSchema(CaptureDeletedPayloadSchema, value, "capture deleted payload");
}

export function parseCaptureRecordedEventPayload(value: unknown): CaptureRecordedEventPayload {
  return parseWithSchema(
    CaptureRecordedEventPayloadSchema,
    value,
    "capture recorded event payload",
  );
}

export function parseCaptureDeletedEventPayload(value: unknown): CaptureDeletedEventPayload {
  return parseWithSchema(CaptureDeletedEventPayloadSchema, value, "capture deleted event payload");
}

export function appendCaptureRecordedEvent(store: SqliteEventStore, value: unknown): StoredEvent {
  const payload = parseCaptureRecordedPayload(value);
  return store.append({
    aggregateId: `session:${payload.sessionId}`,
    idempotencyKey: `capture-recorded-v2:${payload.attemptId}`,
    occurredAt: payload.acquiredAt,
    payload: toJson(CaptureRecordedEventPayloadSchema.parse({ capture: payload })),
    type: CAPTURE_RECORDED_EVENT_TYPE,
  });
}

export function appendCaptureDeletedEvent(store: SqliteEventStore, value: unknown): StoredEvent {
  const payload = parseCaptureDeletedPayload(value);
  return store.append({
    aggregateId: `session:${payload.sessionId}`,
    idempotencyKey: `capture-deleted-v1:${payload.deletionId}`,
    occurredAt: payload.deletedAt,
    payload: toJson(CaptureDeletedEventPayloadSchema.parse({ deletion: payload })),
    type: CAPTURE_DELETED_EVENT_TYPE,
  });
}
