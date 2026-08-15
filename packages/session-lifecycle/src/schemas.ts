import { types as utilTypes } from "node:util";

import { z } from "zod";

import { SessionLifecycleValidationError } from "./errors.js";

export const CanonicalTimestampSchema = z
  .string()
  .max(32)
  .refine((value) => {
    const milliseconds = Date.parse(value);
    return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
  }, "must be a canonical UTC timestamp with milliseconds");

export const QualificationDateSchema = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/)
  .refine((value) => {
    const milliseconds = Date.parse(`${value}T00:00:00.000Z`);
    return (
      Number.isFinite(milliseconds) && new Date(milliseconds).toISOString().slice(0, 10) === value
    );
  });

export const UuidSchema = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
export const EvidenceHashSchema = z.string().regex(/^[0-9a-f]{64}$/);
export const SessionProfileSchema = z.enum(["canary", "production-observer"]);
export const SessionStateSchema = z.enum([
  "planned",
  "preflighted",
  "running",
  "stopping",
  "locally_verified",
  "externally_verified",
  "cost_pending",
  "accepted",
  "invalid",
]);
export const SessionInvalidationReasonSchema = z.enum([
  "operator-abort",
  "crash-recovery",
  "preflight-failed",
  "clock-violation",
  "bound-violation",
  "supervision-expired",
  "missed-supervision-acknowledgement",
  "source-incomplete",
  "purge-failed",
  "local-verification-failed",
  "external-verification-failed",
  "cost-reconciliation-failed",
  "cost-over-reservation",
  "cost-reconciliation-late",
  "incident-detected",
  "qualification-date-conflict",
]);

const PreflightCheckStatusSchema = z.enum(["fail", "pass", "unknown"]);
const ClosureStatusSchema = z.enum(["closed", "failed", "unknown"]);
const VerificationStatusSchema = z.enum(["failed", "unknown", "verified"]);
const CleanlinessStatusSchema = z.enum(["clean", "failed", "unknown"]);
const AtomicAmountSchema = z.string().regex(/^(0|[1-9][0-9]{0,29})$/);

function recoveryArtifactSchema<const TStatus extends string>(verifiedStatus: TStatus) {
  return z.discriminatedUnion("status", [
    z.strictObject({ archiveSha256: z.null(), status: z.enum(["failed", "unknown"]) }),
    z.strictObject({ archiveSha256: EvidenceHashSchema, status: z.literal(verifiedStatus) }),
  ]);
}

const SessionRecoveryArtifactEvidenceSchema = z.strictObject({
  sanitizedStateEvidence: recoveryArtifactSchema("verified-evidence-component"),
  sanitizedEventArchive: recoveryArtifactSchema("verified-restorable-event-archive"),
  signedReleaseBundle: recoveryArtifactSchema("verified-restorable-release-component"),
});

export const SessionPreflightEvidenceSchema = z.strictObject({
  schemaVersion: z.literal(1),
  evidenceHash: EvidenceHashSchema,
  profile: SessionProfileSchema,
  observedAt: CanonicalTimestampSchema,
  ready: z.boolean(),
  checks: z.strictObject({
    alertPath: PreflightCheckStatusSchema,
    backupTarget: PreflightCheckStatusSchema,
    budgetReservations: PreflightCheckStatusSchema,
    clock: PreflightCheckStatusSchema,
    credentialScopes: PreflightCheckStatusSchema,
    databaseIntegrity: PreflightCheckStatusSchema,
    disk: PreflightCheckStatusSchema,
    externalAnchor: PreflightCheckStatusSchema,
    financialAdaptersDisabled: PreflightCheckStatusSchema,
    networkAllowlist: PreflightCheckStatusSchema,
    releaseConfiguration: PreflightCheckStatusSchema,
    runtime: PreflightCheckStatusSchema,
  }),
});

export const SessionLocalVerificationEvidenceSchema = z.strictObject({
  schemaVersion: z.literal(1),
  evidenceHash: EvidenceHashSchema,
  xLanes: z.strictObject({
    contract: ClosureStatusSchema,
    discovery: ClosureStatusSchema,
    marketplace: ClosureStatusSchema,
    official: ClosureStatusSchema,
    security: ClosureStatusSchema,
  }),
  openSea: z.strictObject({
    rest: ClosureStatusSchema,
    stream: ClosureStatusSchema,
  }),
  canonicalChain: ClosureStatusSchema,
  eventIntegrity: VerificationStatusSchema,
  digestIntegrity: VerificationStatusSchema,
  purge: z.strictObject({
    captureKeys: z.enum(["destroyed", "failed", "unknown"]),
    encryptedIndexes: CleanlinessStatusSchema,
    orphanScan: CleanlinessStatusSchema,
    rawCaptures: CleanlinessStatusSchema,
  }),
  localCheckpoint: VerificationStatusSchema,
  recoveryArtifacts: SessionRecoveryArtifactEvidenceSchema,
  alertCheck: z.enum(["failed", "healthy", "unknown"]),
  explicitClose: z.enum(["complete", "failed", "unknown"]),
  incidentCount: z.number().int().min(0).max(1_000),
});

export const SessionExternalVerificationEvidenceSchema = z.strictObject({
  schemaVersion: z.literal(1),
  evidenceHash: EvidenceHashSchema,
  externalAnchor: VerificationStatusSchema,
  retainedSuffix: VerificationStatusSchema,
  macBookVerification: VerificationStatusSchema,
});

export const SessionCostEvidenceSchema = z.strictObject({
  schemaVersion: z.literal(1),
  evidenceHash: EvidenceHashSchema,
  billingStatus: z.enum(["complete", "missing", "unknown"]),
  currency: z.literal("USD_MICRO"),
  outstandingAtomic: AtomicAmountSchema,
  reconciledAtomic: AtomicAmountSchema,
  reservedAtomic: AtomicAmountSchema,
});

export const SessionAcceptanceEvidenceSchema = z.strictObject({
  schemaVersion: z.literal(1),
  preflight: z.literal("pass"),
  xLanes: z.strictObject({
    contract: z.literal("closed"),
    discovery: z.literal("closed"),
    marketplace: z.literal("closed"),
    official: z.literal("closed"),
    security: z.literal("closed"),
  }),
  openSea: z.strictObject({ rest: z.literal("closed"), stream: z.literal("closed") }),
  canonicalChain: z.literal("closed"),
  eventIntegrity: z.literal("verified"),
  digestIntegrity: z.literal("verified"),
  purge: z.strictObject({
    captureKeys: z.literal("destroyed"),
    encryptedIndexes: z.literal("clean"),
    orphanScan: z.literal("clean"),
    rawCaptures: z.literal("clean"),
  }),
  localCheckpoint: z.literal("verified"),
  externalAnchor: z.literal("verified"),
  retainedSuffix: z.literal("verified"),
  macBookVerification: z.literal("verified"),
  recoveryArtifacts: z.strictObject({
    sanitizedStateEvidence: z.strictObject({
      archiveSha256: EvidenceHashSchema,
      status: z.literal("verified-evidence-component"),
    }),
    sanitizedEventArchive: z.strictObject({
      archiveSha256: EvidenceHashSchema,
      status: z.literal("verified-restorable-event-archive"),
    }),
    signedReleaseBundle: z.strictObject({
      archiveSha256: EvidenceHashSchema,
      status: z.literal("verified-restorable-release-component"),
    }),
  }),
  alertCheck: z.literal("healthy"),
  explicitClose: z.literal("complete"),
  costs: z.strictObject({
    billingStatus: z.literal("complete"),
    currency: z.literal("USD_MICRO"),
    outstandingAtomic: z.literal("0"),
    reconciledAtomic: AtomicAmountSchema,
    reservedAtomic: AtomicAmountSchema,
  }),
  incidents: z.literal("zero"),
  evidenceHashes: z.strictObject({
    cost: EvidenceHashSchema,
    external: EvidenceHashSchema,
    local: EvidenceHashSchema,
    preflight: EvidenceHashSchema,
  }),
  supervision: z.strictObject({
    minute45: z.literal("acknowledged"),
    minute90: z.literal("acknowledged"),
    observerOnly: z.literal("acknowledged"),
    typedSessionId: z.literal("acknowledged"),
    duration: z.literal("within-limit"),
  }),
});

const NullableTimestampSchema = CanonicalTimestampSchema.nullable();

export const SessionRecordSchema = z.strictObject({
  schemaVersion: z.literal(1),
  sessionId: UuidSchema,
  profile: SessionProfileSchema,
  qualificationDate: QualificationDateSchema,
  state: SessionStateSchema,
  egressStatus: z.enum(["blocked", "eligible"]),
  plannedAt: CanonicalTimestampSchema,
  supervisedUntil: CanonicalTimestampSchema,
  updatedAt: CanonicalTimestampSchema,
  preflightedAt: NullableTimestampSchema,
  preflightEvidence: SessionPreflightEvidenceSchema.nullable(),
  startedAt: NullableTimestampSchema,
  startAcknowledgements: z
    .strictObject({
      observerOnly: z.literal("acknowledged"),
      typedSessionId: z.literal("acknowledged"),
    })
    .nullable(),
  minute45AcknowledgedAt: NullableTimestampSchema,
  minute90AcknowledgedAt: NullableTimestampSchema,
  stoppedAt: NullableTimestampSchema,
  locallyVerifiedAt: NullableTimestampSchema,
  localEvidence: SessionLocalVerificationEvidenceSchema.nullable(),
  externallyVerifiedAt: NullableTimestampSchema,
  externalEvidence: SessionExternalVerificationEvidenceSchema.nullable(),
  costReconciledAt: NullableTimestampSchema,
  costEvidence: SessionCostEvidenceSchema.nullable(),
  acceptedAt: NullableTimestampSchema,
  acceptanceEvidence: SessionAcceptanceEvidenceSchema.nullable(),
  invalidatedAt: NullableTimestampSchema,
  invalidationReason: SessionInvalidationReasonSchema.nullable(),
});

export const SessionLifecycleTrustedHeadSchema = z.strictObject({
  auditMac: EvidenceHashSchema,
  auditSequence: z.number().int().min(0).max(100_000),
  profile: SessionProfileSchema,
  schemaVersion: z.literal(1),
});

const ExactStateKeySchema = z.custom<Uint8Array>((value) => {
  if (
    !(value instanceof Uint8Array) ||
    Object.getPrototypeOf(value) !== Uint8Array.prototype ||
    !(value.buffer instanceof ArrayBuffer) ||
    Object.getPrototypeOf(value.buffer) !== ArrayBuffer.prototype ||
    value.byteLength !== 32
  ) {
    return false;
  }
  return Reflect.ownKeys(value).every(
    (key) => typeof key === "string" && /^(0|[1-9][0-9]*)$/.test(key),
  );
});

export const OpenSessionCoordinatorOptionsSchema = z.strictObject({
  expectedProfile: SessionProfileSchema,
  path: z.string().min(1).max(4_096),
  recoveredAt: CanonicalTimestampSchema,
  stateKey: ExactStateKeySchema,
  trustedHead: SessionLifecycleTrustedHeadSchema.optional(),
});

export const PlanSessionInputSchema = z.strictObject({
  plannedAt: CanonicalTimestampSchema,
  qualificationDate: QualificationDateSchema,
  sessionId: UuidSchema,
  supervisedUntil: CanonicalTimestampSchema,
});

export const RecordSessionPreflightInputSchema = z.strictObject({
  evidence: SessionPreflightEvidenceSchema,
  recordedAt: CanonicalTimestampSchema,
  sessionId: UuidSchema,
});

export const StartSessionInputSchema = z.strictObject({
  observerOnlyAcknowledgement: z.literal(true),
  sessionId: UuidSchema,
  startedAt: CanonicalTimestampSchema,
  typedSessionIdAcknowledgement: UuidSchema,
});

export const RecordSupervisionAcknowledgementInputSchema = z.strictObject({
  acknowledgedAt: CanonicalTimestampSchema,
  checkpoint: z.enum(["minute-45", "minute-90"]),
  sessionId: UuidSchema,
});

export const StopSessionInputSchema = z.strictObject({
  sessionId: UuidSchema,
  stoppedAt: CanonicalTimestampSchema,
});

export const RecordLocalVerificationInputSchema = z.strictObject({
  evidence: SessionLocalVerificationEvidenceSchema,
  sessionId: UuidSchema,
  verifiedAt: CanonicalTimestampSchema,
});

export const RecordExternalVerificationInputSchema = z.strictObject({
  evidence: SessionExternalVerificationEvidenceSchema,
  sessionId: UuidSchema,
  verifiedAt: CanonicalTimestampSchema,
});

export const RecordCostReconciliationInputSchema = z.strictObject({
  evidence: SessionCostEvidenceSchema,
  reconciledAt: CanonicalTimestampSchema,
  sessionId: UuidSchema,
});

export const AcceptSessionInputSchema = z.strictObject({
  acceptedAt: CanonicalTimestampSchema,
  sessionId: UuidSchema,
});

export const InvalidateSessionInputSchema = z.strictObject({
  invalidatedAt: CanonicalTimestampSchema,
  reason: SessionInvalidationReasonSchema,
  sessionId: UuidSchema,
});

export function parseSessionInput<T>(schema: z.ZodType<T>, value: unknown): T {
  let result: ReturnType<typeof schema.safeParse>;
  try {
    assertPlainDataGraph(value, new WeakSet<object>());
    result = schema.safeParse(value);
  } catch (error) {
    if (error instanceof SessionLifecycleValidationError) throw error;
    throw new SessionLifecycleValidationError();
  }
  if (!result.success) throw new SessionLifecycleValidationError();
  return result.data;
}

function assertPlainDataGraph(value: unknown, ancestors: WeakSet<object>): void {
  if (value === null || typeof value !== "object") return;
  if (utilTypes.isProxy(value)) throw new SessionLifecycleValidationError();
  if (value instanceof Uint8Array) {
    if (
      Reflect.ownKeys(value).some(
        (key) => typeof key !== "string" || !/^(0|[1-9][0-9]*)$/.test(key),
      )
    ) {
      throw new SessionLifecycleValidationError();
    }
    return;
  }
  if (ancestors.has(value)) throw new SessionLifecycleValidationError();
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const keys = Reflect.ownKeys(value);
      if (
        keys.some(
          (key) => typeof key !== "string" || (key !== "length" && !/^(0|[1-9][0-9]*)$/.test(key)),
        )
      ) {
        throw new SessionLifecycleValidationError();
      }
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
          throw new SessionLifecycleValidationError();
        }
        assertPlainDataGraph(descriptor.value, ancestors);
      }
      return;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new SessionLifecycleValidationError();
    }
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string") throw new SessionLifecycleValidationError();
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
        throw new SessionLifecycleValidationError();
      }
      assertPlainDataGraph(descriptor.value, ancestors);
    }
  } finally {
    ancestors.delete(value);
  }
}
