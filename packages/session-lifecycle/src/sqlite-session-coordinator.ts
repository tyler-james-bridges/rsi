import { createHmac, hkdfSync, timingSafeEqual } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { z } from "zod";

import {
  SessionLifecycleClosedError,
  SessionLifecycleConflictError,
  SessionLifecycleError,
  SessionLifecycleIntegrityError,
  SessionLifecycleValidationError,
} from "./errors.js";
import {
  AcceptSessionInputSchema,
  CanonicalTimestampSchema,
  InvalidateSessionInputSchema,
  OpenSessionCoordinatorOptionsSchema,
  PlanSessionInputSchema,
  RecordCostReconciliationInputSchema,
  RecordExternalVerificationInputSchema,
  RecordLocalVerificationInputSchema,
  RecordSessionPreflightInputSchema,
  RecordSupervisionAcknowledgementInputSchema,
  SessionLocalVerificationEvidenceSchema,
  SessionRecordSchema,
  StartSessionInputSchema,
  StopSessionInputSchema,
  UuidSchema,
  parseSessionInput,
} from "./schemas.js";
import {
  SESSION_STATES,
  type AcceptSessionInput,
  type InvalidateSessionInput,
  type OpenSessionCoordinatorOptions,
  type PlanSessionInput,
  type RecordCostReconciliationInput,
  type RecordExternalVerificationInput,
  type RecordLocalVerificationInput,
  type RecordSessionPreflightInput,
  type RecordSupervisionAcknowledgementInput,
  type SessionAcceptanceEvidenceV1,
  type SessionCostEvidenceV1,
  type SessionExternalVerificationEvidenceV1,
  type SessionInvalidationReason,
  type SessionLifecycleIntegrityReportV1,
  type SessionLifecycleSummaryV1,
  type SessionLifecycleTrustedHeadV1,
  type SessionLocalVerificationEvidenceV1,
  type SessionPreflightEvidenceV1,
  type SessionProfile,
  type SessionRecordV1,
  type SessionRecoveryReceiptV1,
  type SessionState,
  type StartSessionInput,
  type StopSessionInput,
} from "./types.js";

const SCHEMA_VERSION = 1;
const MAX_SESSION_RECORDS = 10_000;
const MAX_AUDIT_RECORDS = 100_000;
const MAX_SUPERVISED_MILLISECONDS = 120 * 60 * 1_000;
const SUPERVISION_ACKNOWLEDGEMENT_GRACE_MILLISECONDS = 5 * 60 * 1_000;
const MAX_COST_RECONCILIATION_MILLISECONDS = 48 * 60 * 60 * 1_000;
const GENESIS_MAC = "0".repeat(64);
const OPEN_PATHS = new Set<string>();
const authenticCoordinators = new WeakSet<object>();
const COORDINATOR_CONSTRUCTION_TOKEN = Object.freeze({});

const AUDIT_ACTIONS = [
  "plan",
  "preflight",
  "start",
  "ack-minute-45",
  "ack-minute-90",
  "stop",
  "local-verification",
  "external-verification",
  "cost-reconciliation",
  "accept",
  "invalidate",
  "crash-recovery",
] as const;
type AuditAction = (typeof AUDIT_ACTIONS)[number];

const CrashRecoveryInputSchema = z.strictObject({
  reason: z.literal("crash-recovery"),
  recoveredAt: CanonicalTimestampSchema,
  sessionId: UuidSchema,
});

interface MetadataRow {
  active_count: number;
  audit_head_mac: string;
  key_check_mac: string;
  latest_occurred_at: string | null;
  metadata_mac: string;
  next_audit_sequence: number;
  profile: SessionProfile;
  rows_mac: string;
  schema_projection_mac: string;
  schema_version: number;
  session_count: number;
  singleton: number;
}

interface SessionRow {
  active_profile: SessionProfile | null;
  profile: SessionProfile;
  qualification_date: string;
  record_json: string;
  row_mac: string;
  session_id: string;
  state: SessionState;
}

interface AuditRow {
  action: AuditAction;
  from_state: SessionState | null;
  input_json: string;
  occurred_at: string;
  previous_mac: string;
  record_json: string;
  row_mac: string;
  sequence: number;
  session_id: string;
  to_state: SessionState;
}

const CREATE_SCHEMA_SQL = `
  CREATE TABLE IF NOT EXISTS rsi_session_lifecycle_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL,
    profile TEXT NOT NULL CHECK (profile IN ('canary', 'production-observer')),
    key_check_mac TEXT NOT NULL,
    next_audit_sequence INTEGER NOT NULL,
    session_count INTEGER NOT NULL,
    active_count INTEGER NOT NULL,
    latest_occurred_at TEXT,
    rows_mac TEXT NOT NULL,
    audit_head_mac TEXT NOT NULL,
    schema_projection_mac TEXT NOT NULL,
    metadata_mac TEXT NOT NULL
  ) STRICT;

  CREATE TABLE IF NOT EXISTS rsi_session_lifecycle_sessions (
    session_id TEXT PRIMARY KEY,
    profile TEXT NOT NULL CHECK (profile IN ('canary', 'production-observer')),
    qualification_date TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
      'planned', 'preflighted', 'running', 'stopping', 'locally_verified',
      'externally_verified', 'cost_pending', 'accepted', 'invalid'
    )),
    active_profile TEXT CHECK (
      active_profile IS NULL OR active_profile IN ('canary', 'production-observer')
    ),
    record_json TEXT NOT NULL,
    row_mac TEXT NOT NULL
  ) STRICT;

  CREATE UNIQUE INDEX IF NOT EXISTS rsi_session_lifecycle_one_active
    ON rsi_session_lifecycle_sessions(active_profile)
    WHERE active_profile IS NOT NULL;

  CREATE UNIQUE INDEX IF NOT EXISTS rsi_session_lifecycle_accepted_date
    ON rsi_session_lifecycle_sessions(profile, qualification_date)
    WHERE state = 'accepted';

  CREATE TABLE IF NOT EXISTS rsi_session_lifecycle_audit (
    sequence INTEGER PRIMARY KEY,
    session_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN (
      'plan', 'preflight', 'start', 'ack-minute-45', 'ack-minute-90', 'stop',
      'local-verification', 'external-verification', 'cost-reconciliation',
      'accept', 'invalidate', 'crash-recovery'
    )),
    occurred_at TEXT NOT NULL,
    from_state TEXT CHECK (from_state IS NULL OR from_state IN (
      'planned', 'preflighted', 'running', 'stopping', 'locally_verified',
      'externally_verified', 'cost_pending', 'accepted', 'invalid'
    )),
    to_state TEXT NOT NULL CHECK (to_state IN (
      'planned', 'preflighted', 'running', 'stopping', 'locally_verified',
      'externally_verified', 'cost_pending', 'accepted', 'invalid'
    )),
    input_json TEXT NOT NULL,
    record_json TEXT NOT NULL,
    previous_mac TEXT NOT NULL,
    row_mac TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES rsi_session_lifecycle_sessions(session_id),
    UNIQUE (session_id, action)
  ) STRICT;
`;

function milliseconds(value: string): number {
  return Date.parse(value);
}

function isTerminal(state: SessionState): boolean {
  return state === "accepted" || state === "invalid";
}

function activeProfile(record: SessionRecordV1): SessionProfile | null {
  return isTerminal(record.state) ? null : record.profile;
}

function qualificationDateInPhoenix(timestamp: string): string {
  const parts = new Intl.DateTimeFormat("en-US", {
    day: "2-digit",
    month: "2-digit",
    timeZone: "America/Phoenix",
    year: "numeric",
  }).formatToParts(new Date(timestamp));
  const values = new Map(parts.map((part) => [part.type, part.value]));
  return `${values.get("year")}-${values.get("month")}-${values.get("day")}`;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new SessionLifecycleIntegrityError();
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
  if (typeof value !== "object") throw new SessionLifecycleIntegrityError();
  const entries = Object.entries(value as Record<string, unknown>).sort(([left], [right]) =>
    left.localeCompare(right),
  );
  return `{${entries
    .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
    .join(",")}}`;
}

function deepFreeze<T>(value: T): Readonly<T> {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function secureEqual(left: string, right: string): boolean {
  if (!/^[0-9a-f]{64}$/.test(left) || !/^[0-9a-f]{64}$/.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function deriveMacKey(stateKey: Uint8Array, profile: SessionProfile): Buffer {
  const copied = Buffer.from(stateKey);
  try {
    return Buffer.from(
      hkdfSync(
        "sha256",
        copied,
        Buffer.from("rsi.session-lifecycle.hkdf-sha256.salt.v1\0", "ascii"),
        Buffer.from(`rsi.session-lifecycle.mac.v1\0${profile}`, "utf8"),
        32,
      ),
    );
  } finally {
    copied.fill(0);
  }
}

function mac(key: Uint8Array, domain: string, value: unknown): string {
  return createHmac("sha256", key)
    .update(`rsi.session-lifecycle.${domain}.v1\0`, "utf8")
    .update(canonicalJson(value), "utf8")
    .digest("hex");
}

function allPreflightChecksPass(evidence: SessionPreflightEvidenceV1): boolean {
  return evidence.ready && Object.values(evidence.checks).every((status) => status === "pass");
}

function localFailureReason(
  evidence: SessionLocalVerificationEvidenceV1,
): SessionInvalidationReason | null {
  if (evidence.incidentCount !== 0) return "incident-detected";
  if (
    evidence.purge.captureKeys !== "destroyed" ||
    evidence.purge.encryptedIndexes !== "clean" ||
    evidence.purge.orphanScan !== "clean" ||
    evidence.purge.rawCaptures !== "clean"
  ) {
    return "purge-failed";
  }
  if (
    Object.values(evidence.xLanes).some((status) => status !== "closed") ||
    evidence.openSea.rest !== "closed" ||
    evidence.openSea.stream !== "closed" ||
    evidence.canonicalChain !== "closed"
  ) {
    return "source-incomplete";
  }
  if (
    evidence.eventIntegrity !== "verified" ||
    evidence.digestIntegrity !== "verified" ||
    evidence.localCheckpoint !== "verified" ||
    evidence.recoveryArtifacts.sanitizedStateEvidence.status !== "verified-evidence-component" ||
    evidence.recoveryArtifacts.sanitizedEventArchive.status !==
      "verified-restorable-event-archive" ||
    evidence.recoveryArtifacts.signedReleaseBundle.status !==
      "verified-restorable-release-component" ||
    evidence.alertCheck !== "healthy" ||
    evidence.explicitClose !== "complete"
  ) {
    return "local-verification-failed";
  }
  return null;
}

function externalEvidencePasses(evidence: SessionExternalVerificationEvidenceV1): boolean {
  return (
    evidence.externalAnchor === "verified" &&
    evidence.retainedSuffix === "verified" &&
    evidence.macBookVerification === "verified"
  );
}

function costFailureReason(evidence: SessionCostEvidenceV1): SessionInvalidationReason | null {
  if (BigInt(evidence.reconciledAtomic) > BigInt(evidence.reservedAtomic)) {
    return "cost-over-reservation";
  }
  if (evidence.billingStatus !== "complete" || evidence.outstandingAtomic !== "0") {
    return "cost-reconciliation-failed";
  }
  return null;
}

function acceptanceEvidence(record: SessionRecordV1): SessionAcceptanceEvidenceV1 {
  const local = record.localEvidence;
  const external = record.externalEvidence;
  const costs = record.costEvidence;
  if (
    record.preflightEvidence === null ||
    !allPreflightChecksPass(record.preflightEvidence) ||
    local === null ||
    localFailureReason(local) !== null ||
    external === null ||
    !externalEvidencePasses(external) ||
    costs === null ||
    costFailureReason(costs) !== null ||
    record.minute45AcknowledgedAt === null ||
    record.minute90AcknowledgedAt === null ||
    record.startAcknowledgements === null ||
    record.startedAt === null ||
    record.stoppedAt === null ||
    milliseconds(record.stoppedAt) - milliseconds(record.startedAt) > MAX_SUPERVISED_MILLISECONDS
  ) {
    throw new SessionLifecycleIntegrityError();
  }
  const stateEvidenceArchiveSha256 = local.recoveryArtifacts.sanitizedStateEvidence.archiveSha256;
  const eventArchiveSha256 = local.recoveryArtifacts.sanitizedEventArchive.archiveSha256;
  const releaseBundleArchiveSha256 = local.recoveryArtifacts.signedReleaseBundle.archiveSha256;
  if (
    stateEvidenceArchiveSha256 === null ||
    eventArchiveSha256 === null ||
    releaseBundleArchiveSha256 === null
  ) {
    throw new SessionLifecycleIntegrityError();
  }
  return {
    schemaVersion: 1,
    preflight: "pass",
    xLanes: {
      contract: "closed",
      discovery: "closed",
      marketplace: "closed",
      official: "closed",
      security: "closed",
    },
    openSea: { rest: "closed", stream: "closed" },
    canonicalChain: "closed",
    eventIntegrity: "verified",
    digestIntegrity: "verified",
    purge: {
      captureKeys: "destroyed",
      encryptedIndexes: "clean",
      orphanScan: "clean",
      rawCaptures: "clean",
    },
    localCheckpoint: "verified",
    externalAnchor: "verified",
    retainedSuffix: "verified",
    macBookVerification: "verified",
    recoveryArtifacts: {
      sanitizedStateEvidence: {
        archiveSha256: stateEvidenceArchiveSha256,
        status: "verified-evidence-component",
      },
      sanitizedEventArchive: {
        archiveSha256: eventArchiveSha256,
        status: "verified-restorable-event-archive",
      },
      signedReleaseBundle: {
        archiveSha256: releaseBundleArchiveSha256,
        status: "verified-restorable-release-component",
      },
    },
    alertCheck: "healthy",
    explicitClose: "complete",
    costs: {
      billingStatus: "complete",
      currency: "USD_MICRO",
      outstandingAtomic: "0",
      reconciledAtomic: costs.reconciledAtomic,
      reservedAtomic: costs.reservedAtomic,
    },
    incidents: "zero",
    evidenceHashes: {
      cost: costs.evidenceHash,
      external: external.evidenceHash,
      local: local.evidenceHash,
      preflight: record.preflightEvidence.evidenceHash,
    },
    supervision: {
      minute45: "acknowledged",
      minute90: "acknowledged",
      observerOnly: "acknowledged",
      typedSessionId: "acknowledged",
      duration: "within-limit",
    },
  };
}

function invalidRecord(
  record: SessionRecordV1,
  invalidatedAt: string,
  reason: SessionInvalidationReason,
): SessionRecordV1 {
  return {
    ...record,
    acceptanceEvidence: null,
    acceptedAt: null,
    egressStatus: "blocked",
    invalidatedAt,
    invalidationReason: reason,
    state: "invalid",
    updatedAt: invalidatedAt,
  };
}

function parseRecordJson(value: string): Readonly<SessionRecordV1> {
  try {
    const parsedJson: unknown = JSON.parse(value);
    const record = parseSessionInput(SessionRecordSchema, parsedJson);
    if (canonicalJson(record) !== value) throw new SessionLifecycleIntegrityError();
    assertRecordSemantics(record);
    return deepFreeze(record);
  } catch (error) {
    if (error instanceof SessionLifecycleIntegrityError) throw error;
    throw new SessionLifecycleIntegrityError();
  }
}

function assertRecordSemantics(record: SessionRecordV1): void {
  const planned = milliseconds(record.plannedAt);
  const supervisedUntil = milliseconds(record.supervisedUntil);
  if (
    planned > supervisedUntil ||
    record.qualificationDate !== qualificationDateInPhoenix(record.plannedAt) ||
    record.egressStatus !== (record.state === "running" ? "eligible" : "blocked") ||
    (record.preflightedAt === null) !== (record.preflightEvidence === null) ||
    (record.startedAt === null) !== (record.startAcknowledgements === null) ||
    (record.locallyVerifiedAt === null) !== (record.localEvidence === null) ||
    (record.externallyVerifiedAt === null) !== (record.externalEvidence === null) ||
    (record.costReconciledAt === null) !== (record.costEvidence === null) ||
    (record.acceptedAt === null) !== (record.acceptanceEvidence === null) ||
    (record.invalidatedAt === null) !== (record.invalidationReason === null)
  ) {
    throw new SessionLifecycleIntegrityError();
  }
  if (
    record.preflightEvidence?.profile !== undefined &&
    record.preflightEvidence.profile !== record.profile
  ) {
    throw new SessionLifecycleIntegrityError();
  }
  if (record.minute90AcknowledgedAt !== null && record.minute45AcknowledgedAt === null) {
    throw new SessionLifecycleIntegrityError();
  }

  const ordered = [
    record.plannedAt,
    record.preflightEvidence?.observedAt ?? null,
    record.preflightedAt,
    record.startedAt,
    record.minute45AcknowledgedAt,
    record.minute90AcknowledgedAt,
    record.stoppedAt,
    record.locallyVerifiedAt,
    record.externallyVerifiedAt,
    record.costReconciledAt,
    record.acceptedAt,
  ].filter((value): value is string => value !== null);
  for (let index = 1; index < ordered.length; index += 1) {
    if (milliseconds(ordered[index]!) < milliseconds(ordered[index - 1]!)) {
      throw new SessionLifecycleIntegrityError();
    }
  }
  for (const timestamp of [
    record.startedAt,
    record.minute45AcknowledgedAt,
    record.minute90AcknowledgedAt,
  ]) {
    if (timestamp !== null && milliseconds(timestamp) > supervisedUntil) {
      if (record.state !== "invalid") throw new SessionLifecycleIntegrityError();
    }
  }
  if (
    record.stoppedAt !== null &&
    record.startedAt !== null &&
    (milliseconds(record.stoppedAt) > supervisedUntil ||
      milliseconds(record.stoppedAt) - milliseconds(record.startedAt) >
        MAX_SUPERVISED_MILLISECONDS) &&
    record.state !== "invalid"
  ) {
    throw new SessionLifecycleIntegrityError();
  }
  if (record.state === "invalid") {
    if (
      record.invalidatedAt === null ||
      record.invalidationReason === null ||
      record.acceptedAt !== null ||
      record.acceptanceEvidence !== null ||
      milliseconds(record.invalidatedAt) < milliseconds(record.updatedAt) ||
      record.updatedAt !== record.invalidatedAt
    ) {
      throw new SessionLifecycleIntegrityError();
    }
    return;
  }
  if (record.invalidatedAt !== null || record.invalidationReason !== null) {
    throw new SessionLifecycleIntegrityError();
  }
  if (
    record.startedAt !== null &&
    qualificationDateInPhoenix(record.startedAt) !== record.qualificationDate
  ) {
    throw new SessionLifecycleIntegrityError();
  }
  if (record.startedAt !== null) {
    for (const [acknowledgedAt, expectedMinutes] of [
      [record.minute45AcknowledgedAt, 45],
      [record.minute90AcknowledgedAt, 90],
    ] as const) {
      if (acknowledgedAt === null) continue;
      const offset = milliseconds(acknowledgedAt) - milliseconds(record.startedAt);
      if (
        offset < expectedMinutes * 60 * 1_000 ||
        offset > expectedMinutes * 60 * 1_000 + SUPERVISION_ACKNOWLEDGEMENT_GRACE_MILLISECONDS
      ) {
        throw new SessionLifecycleIntegrityError();
      }
    }
  }
  const rank: Record<Exclude<SessionState, "invalid">, number> = {
    planned: 0,
    preflighted: 1,
    running: 2,
    stopping: 3,
    locally_verified: 4,
    externally_verified: 5,
    cost_pending: 6,
    accepted: 7,
  };
  const currentRank = rank[record.state];
  const required = [
    record.preflightedAt,
    record.startedAt,
    record.stoppedAt,
    record.locallyVerifiedAt,
    record.externallyVerifiedAt,
    record.costReconciledAt,
    record.acceptedAt,
  ];
  for (let index = 0; index < required.length; index += 1) {
    if ((required[index] !== null) !== currentRank >= index + 1) {
      throw new SessionLifecycleIntegrityError();
    }
  }
  if (
    currentRank >= 3 &&
    (record.minute45AcknowledgedAt === null || record.minute90AcknowledgedAt === null)
  ) {
    throw new SessionLifecycleIntegrityError();
  }
  if (currentRank >= 1 && !allPreflightChecksPass(record.preflightEvidence!)) {
    throw new SessionLifecycleIntegrityError();
  }
  if (currentRank >= 4 && localFailureReason(record.localEvidence!) !== null) {
    throw new SessionLifecycleIntegrityError();
  }
  if (currentRank >= 5 && !externalEvidencePasses(record.externalEvidence!)) {
    throw new SessionLifecycleIntegrityError();
  }
  if (currentRank >= 6 && costFailureReason(record.costEvidence!) !== null) {
    throw new SessionLifecycleIntegrityError();
  }
  const expectedUpdated =
    record.acceptedAt ??
    record.costReconciledAt ??
    record.externallyVerifiedAt ??
    record.locallyVerifiedAt ??
    record.stoppedAt ??
    record.minute90AcknowledgedAt ??
    record.minute45AcknowledgedAt ??
    record.startedAt ??
    record.preflightedAt ??
    record.plannedAt;
  if (record.updatedAt !== expectedUpdated) throw new SessionLifecycleIntegrityError();
  if (record.state === "accepted") {
    if (canonicalJson(record.acceptanceEvidence) !== canonicalJson(acceptanceEvidence(record))) {
      throw new SessionLifecycleIntegrityError();
    }
  }
}

function assertTransition(action: AuditAction, from: SessionState | null, to: SessionState): void {
  const valid =
    (action === "plan" && from === null && to === "planned") ||
    (action === "preflight" && from === "planned" && (to === "preflighted" || to === "invalid")) ||
    (action === "start" && from === "preflighted" && (to === "running" || to === "invalid")) ||
    ((action === "ack-minute-45" || action === "ack-minute-90") &&
      from === "running" &&
      (to === "running" || to === "invalid")) ||
    (action === "stop" && from === "running" && (to === "stopping" || to === "invalid")) ||
    (action === "local-verification" &&
      from === "stopping" &&
      (to === "locally_verified" || to === "invalid")) ||
    (action === "external-verification" &&
      from === "locally_verified" &&
      (to === "externally_verified" || to === "invalid")) ||
    (action === "cost-reconciliation" &&
      from === "externally_verified" &&
      (to === "cost_pending" || to === "invalid")) ||
    (action === "accept" && from === "cost_pending" && (to === "accepted" || to === "invalid")) ||
    ((action === "invalidate" || action === "crash-recovery") &&
      from !== null &&
      !isTerminal(from) &&
      to === "invalid");
  if (!valid) throw new SessionLifecycleIntegrityError();
}

function auditInputSchema(action: AuditAction): z.ZodType<unknown> {
  switch (action) {
    case "plan":
      return PlanSessionInputSchema;
    case "preflight":
      return RecordSessionPreflightInputSchema;
    case "start":
      return StartSessionInputSchema;
    case "ack-minute-45":
    case "ack-minute-90":
      return RecordSupervisionAcknowledgementInputSchema;
    case "stop":
      return StopSessionInputSchema;
    case "local-verification":
      return RecordLocalVerificationInputSchema;
    case "external-verification":
      return RecordExternalVerificationInputSchema;
    case "cost-reconciliation":
      return RecordCostReconciliationInputSchema;
    case "accept":
      return AcceptSessionInputSchema;
    case "invalidate":
      return InvalidateSessionInputSchema;
    case "crash-recovery":
      return CrashRecoveryInputSchema;
  }
}

function parseAuditInput(row: AuditRow): Readonly<Record<string, unknown>> {
  try {
    const input: unknown = JSON.parse(row.input_json);
    const parsed = parseSessionInput(auditInputSchema(row.action), input) as Record<
      string,
      unknown
    >;
    if (canonicalJson(parsed) !== row.input_json || parsed.sessionId !== row.session_id) {
      throw new SessionLifecycleIntegrityError();
    }
    const actionTime =
      parsed.plannedAt ??
      parsed.recordedAt ??
      parsed.startedAt ??
      parsed.acknowledgedAt ??
      parsed.stoppedAt ??
      parsed.verifiedAt ??
      parsed.reconciledAt ??
      parsed.acceptedAt ??
      parsed.invalidatedAt ??
      parsed.recoveredAt;
    if (actionTime !== row.occurred_at) throw new SessionLifecycleIntegrityError();
    if (
      (row.action === "ack-minute-45" && parsed.checkpoint !== "minute-45") ||
      (row.action === "ack-minute-90" && parsed.checkpoint !== "minute-90")
    ) {
      throw new SessionLifecycleIntegrityError();
    }
    return deepFreeze(parsed);
  } catch (error) {
    if (error instanceof SessionLifecycleIntegrityError) throw error;
    throw new SessionLifecycleIntegrityError();
  }
}

export class SqliteSessionCoordinator {
  readonly path: string;
  readonly profile: SessionProfile;

  private closed = false;
  private readonly database: DatabaseSync;
  private readonly macKey: Buffer;

  private constructor(
    path: string,
    profile: SessionProfile,
    macKey: Buffer,
    constructionToken: unknown,
  ) {
    if (constructionToken !== COORDINATOR_CONSTRUCTION_TOKEN) {
      throw new SessionLifecycleIntegrityError();
    }
    this.path = path;
    this.profile = profile;
    this.macKey = macKey;
    this.database = new DatabaseSync(path);
  }

  static open(optionsInput: OpenSessionCoordinatorOptions): Readonly<{
    coordinator: SqliteSessionCoordinator;
    recovery: Readonly<SessionRecoveryReceiptV1>;
  }> {
    const options = parseSessionInput(OpenSessionCoordinatorOptionsSchema, optionsInput);
    const path = resolve(options.path);
    const pathExisted = existsSync(path);
    if (OPEN_PATHS.has(path)) {
      throw new SessionLifecycleConflictError(
        "WRITER_CONFLICT",
        "A session lifecycle writer is already open",
      );
    }
    mkdirSync(dirname(path), { mode: 0o700, recursive: true });
    if (existsSync(path) && lstatSync(path).isSymbolicLink()) {
      throw new SessionLifecycleIntegrityError();
    }
    const macKey = deriveMacKey(options.stateKey, options.expectedProfile);
    let coordinator: SqliteSessionCoordinator | undefined;
    try {
      OPEN_PATHS.add(path);
      coordinator = new SqliteSessionCoordinator(
        path,
        options.expectedProfile,
        macKey,
        COORDINATOR_CONSTRUCTION_TOKEN,
      );
      coordinator.configureDatabase();
      const namespaceWasEmpty = coordinator.schemaProjection().length === 0;
      if (namespaceWasEmpty) coordinator.initializeSchema();
      if (!pathExisted || namespaceWasEmpty) chmodSync(path, 0o600);
      coordinator.initializeOrVerifyMetadata(namespaceWasEmpty);
      if (!namespaceWasEmpty && options.trustedHead === undefined) {
        throw new SessionLifecycleIntegrityError(
          "An independently retained lifecycle head is required for reopen",
        );
      }
      if (options.trustedHead !== undefined) coordinator.verifyTrustedHead(options.trustedHead);
      authenticCoordinators.add(coordinator);
      const recovery = coordinator.recoverNonterminalSessions(options.recoveredAt);
      coordinator.verifyIntegrityInternal();
      return Object.freeze({ coordinator, recovery });
    } catch (error) {
      if (coordinator !== undefined) coordinator.closeAfterFailedOpen();
      else {
        macKey.fill(0);
        OPEN_PATHS.delete(path);
      }
      if (error instanceof SessionLifecycleError) throw error;
      throw new SessionLifecycleIntegrityError();
    }
  }

  planSession(inputValue: PlanSessionInput): Readonly<SessionRecordV1> {
    const input = parseSessionInput(PlanSessionInputSchema, inputValue);
    if (
      input.qualificationDate !== qualificationDateInPhoenix(input.plannedAt) ||
      milliseconds(input.supervisedUntil) < milliseconds(input.plannedAt)
    ) {
      throw new SessionLifecycleValidationError();
    }
    return this.mutate("plan", input, input.plannedAt, null, () => {
      const active = this.database
        .prepare("SELECT session_id FROM rsi_session_lifecycle_sessions WHERE active_profile = ?")
        .get(this.profile) as { session_id: string } | undefined;
      if (active !== undefined) {
        throw new SessionLifecycleConflictError(
          "ACTIVE_SESSION_CONFLICT",
          "The profile already has an active session",
        );
      }
      return {
        schemaVersion: 1,
        sessionId: input.sessionId,
        profile: this.profile,
        qualificationDate: input.qualificationDate,
        state: "planned",
        egressStatus: "blocked",
        plannedAt: input.plannedAt,
        supervisedUntil: input.supervisedUntil,
        updatedAt: input.plannedAt,
        preflightedAt: null,
        preflightEvidence: null,
        startedAt: null,
        startAcknowledgements: null,
        minute45AcknowledgedAt: null,
        minute90AcknowledgedAt: null,
        stoppedAt: null,
        locallyVerifiedAt: null,
        localEvidence: null,
        externallyVerifiedAt: null,
        externalEvidence: null,
        costReconciledAt: null,
        costEvidence: null,
        acceptedAt: null,
        acceptanceEvidence: null,
        invalidatedAt: null,
        invalidationReason: null,
      };
    });
  }

  recordPreflight(inputValue: RecordSessionPreflightInput): Readonly<SessionRecordV1> {
    const input = parseSessionInput(RecordSessionPreflightInputSchema, inputValue);
    return this.mutate("preflight", input, input.recordedAt, "planned", (record) => {
      if (
        input.evidence.profile !== record.profile ||
        milliseconds(input.evidence.observedAt) < milliseconds(record.plannedAt) ||
        milliseconds(input.evidence.observedAt) > milliseconds(input.recordedAt)
      ) {
        throw new SessionLifecycleValidationError();
      }
      const candidate: SessionRecordV1 = {
        ...record,
        preflightEvidence: input.evidence,
        preflightedAt: input.recordedAt,
        updatedAt: input.recordedAt,
      };
      if (
        milliseconds(input.recordedAt) > milliseconds(record.supervisedUntil) ||
        !allPreflightChecksPass(input.evidence)
      ) {
        return invalidRecord(
          candidate,
          input.recordedAt,
          milliseconds(input.recordedAt) > milliseconds(record.supervisedUntil)
            ? "supervision-expired"
            : "preflight-failed",
        );
      }
      return { ...candidate, state: "preflighted" };
    });
  }

  startSession(inputValue: StartSessionInput): Readonly<SessionRecordV1> {
    const input = parseSessionInput(StartSessionInputSchema, inputValue);
    if (input.typedSessionIdAcknowledgement !== input.sessionId) {
      throw new SessionLifecycleValidationError();
    }
    return this.mutate("start", input, input.startedAt, "preflighted", (record) => {
      const candidate: SessionRecordV1 = {
        ...record,
        egressStatus: "eligible",
        startAcknowledgements: {
          observerOnly: "acknowledged",
          typedSessionId: "acknowledged",
        },
        startedAt: input.startedAt,
        updatedAt: input.startedAt,
      };
      if (
        milliseconds(input.startedAt) > milliseconds(record.supervisedUntil) ||
        milliseconds(record.supervisedUntil) - milliseconds(input.startedAt) >
          MAX_SUPERVISED_MILLISECONDS ||
        qualificationDateInPhoenix(input.startedAt) !== record.qualificationDate
      ) {
        return invalidRecord(
          candidate,
          input.startedAt,
          qualificationDateInPhoenix(input.startedAt) !== record.qualificationDate
            ? "bound-violation"
            : "supervision-expired",
        );
      }
      return { ...candidate, state: "running" };
    });
  }

  recordSupervisionAcknowledgement(
    inputValue: RecordSupervisionAcknowledgementInput,
  ): Readonly<SessionRecordV1> {
    const input = parseSessionInput(RecordSupervisionAcknowledgementInputSchema, inputValue);
    const action = input.checkpoint === "minute-45" ? "ack-minute-45" : "ack-minute-90";
    return this.mutate(action, input, input.acknowledgedAt, "running", (record) => {
      if (record.startedAt === null) throw new SessionLifecycleIntegrityError();
      const acknowledgementOffset =
        milliseconds(input.acknowledgedAt) - milliseconds(record.startedAt);
      const expectedOffset = input.checkpoint === "minute-45" ? 45 * 60 * 1_000 : 90 * 60 * 1_000;
      if (acknowledgementOffset < expectedOffset) {
        throw new SessionLifecycleValidationError();
      }
      if (input.checkpoint === "minute-90" && record.minute45AcknowledgedAt === null) {
        throw new SessionLifecycleConflictError(
          "TRANSITION_CONFLICT",
          "The earlier supervision acknowledgement is missing",
        );
      }
      if (
        input.checkpoint === "minute-90" &&
        milliseconds(input.acknowledgedAt) < milliseconds(record.minute45AcknowledgedAt!)
      ) {
        throw new SessionLifecycleValidationError();
      }
      const candidate: SessionRecordV1 = {
        ...record,
        ...(input.checkpoint === "minute-45"
          ? { minute45AcknowledgedAt: input.acknowledgedAt }
          : { minute90AcknowledgedAt: input.acknowledgedAt }),
        updatedAt: input.acknowledgedAt,
      };
      if (
        acknowledgementOffset > expectedOffset + SUPERVISION_ACKNOWLEDGEMENT_GRACE_MILLISECONDS ||
        milliseconds(input.acknowledgedAt) > milliseconds(record.supervisedUntil)
      ) {
        return invalidRecord(candidate, input.acknowledgedAt, "missed-supervision-acknowledgement");
      }
      return candidate;
    });
  }

  stopSession(inputValue: StopSessionInput): Readonly<SessionRecordV1> {
    const input = parseSessionInput(StopSessionInputSchema, inputValue);
    return this.mutate("stop", input, input.stoppedAt, "running", (record) => {
      if (record.startedAt === null) throw new SessionLifecycleIntegrityError();
      const candidate: SessionRecordV1 = {
        ...record,
        egressStatus: "blocked",
        stoppedAt: input.stoppedAt,
        updatedAt: input.stoppedAt,
      };
      if (
        milliseconds(input.stoppedAt) > milliseconds(record.supervisedUntil) ||
        milliseconds(input.stoppedAt) - milliseconds(record.startedAt) > MAX_SUPERVISED_MILLISECONDS
      ) {
        return invalidRecord(candidate, input.stoppedAt, "bound-violation");
      }
      if (record.minute45AcknowledgedAt === null || record.minute90AcknowledgedAt === null) {
        return invalidRecord(candidate, input.stoppedAt, "missed-supervision-acknowledgement");
      }
      return { ...candidate, state: "stopping" };
    });
  }

  recordLocalVerification(inputValue: RecordLocalVerificationInput): Readonly<SessionRecordV1> {
    const input = parseSessionInput(RecordLocalVerificationInputSchema, inputValue);
    return this.mutate("local-verification", input, input.verifiedAt, "stopping", (record) => {
      const candidate: SessionRecordV1 = {
        ...record,
        localEvidence: input.evidence,
        locallyVerifiedAt: input.verifiedAt,
        updatedAt: input.verifiedAt,
      };
      const reason = localFailureReason(input.evidence);
      return reason === null
        ? { ...candidate, state: "locally_verified" }
        : invalidRecord(candidate, input.verifiedAt, reason);
    });
  }

  recordExternalVerification(
    inputValue: RecordExternalVerificationInput,
  ): Readonly<SessionRecordV1> {
    const input = parseSessionInput(RecordExternalVerificationInputSchema, inputValue);
    return this.mutate(
      "external-verification",
      input,
      input.verifiedAt,
      "locally_verified",
      (record) => {
        const candidate: SessionRecordV1 = {
          ...record,
          externalEvidence: input.evidence,
          externallyVerifiedAt: input.verifiedAt,
          updatedAt: input.verifiedAt,
        };
        return externalEvidencePasses(input.evidence)
          ? { ...candidate, state: "externally_verified" }
          : invalidRecord(candidate, input.verifiedAt, "external-verification-failed");
      },
    );
  }

  recordCostReconciliation(inputValue: RecordCostReconciliationInput): Readonly<SessionRecordV1> {
    const input = parseSessionInput(RecordCostReconciliationInputSchema, inputValue);
    return this.mutate(
      "cost-reconciliation",
      input,
      input.reconciledAt,
      "externally_verified",
      (record) => {
        if (record.stoppedAt === null) throw new SessionLifecycleIntegrityError();
        const candidate: SessionRecordV1 = {
          ...record,
          costEvidence: input.evidence,
          costReconciledAt: input.reconciledAt,
          updatedAt: input.reconciledAt,
        };
        if (
          milliseconds(input.reconciledAt) - milliseconds(record.stoppedAt) >
          MAX_COST_RECONCILIATION_MILLISECONDS
        ) {
          return invalidRecord(candidate, input.reconciledAt, "cost-reconciliation-late");
        }
        const reason = costFailureReason(input.evidence);
        return reason === null
          ? { ...candidate, state: "cost_pending" }
          : invalidRecord(candidate, input.reconciledAt, reason);
      },
    );
  }

  acceptSession(inputValue: AcceptSessionInput): Readonly<SessionRecordV1> {
    const input = parseSessionInput(AcceptSessionInputSchema, inputValue);
    return this.mutate("accept", input, input.acceptedAt, "cost_pending", (record) => {
      if (
        record.costReconciledAt === null ||
        milliseconds(input.acceptedAt) < milliseconds(record.costReconciledAt)
      ) {
        throw new SessionLifecycleValidationError();
      }
      const duplicateDate = this.database
        .prepare(
          `SELECT session_id FROM rsi_session_lifecycle_sessions
             WHERE profile = ? AND qualification_date = ? AND state = 'accepted'
             LIMIT 1`,
        )
        .get(record.profile, record.qualificationDate) as { session_id: string } | undefined;
      if (duplicateDate !== undefined && duplicateDate.session_id !== record.sessionId) {
        return invalidRecord(record, input.acceptedAt, "qualification-date-conflict");
      }
      const evidence = acceptanceEvidence(record);
      return {
        ...record,
        acceptanceEvidence: evidence,
        acceptedAt: input.acceptedAt,
        egressStatus: "blocked",
        state: "accepted",
        updatedAt: input.acceptedAt,
      };
    });
  }

  invalidateSession(inputValue: InvalidateSessionInput): Readonly<SessionRecordV1> {
    const input = parseSessionInput(InvalidateSessionInputSchema, inputValue);
    return this.mutate("invalidate", input, input.invalidatedAt, undefined, (record) => {
      if (isTerminal(record.state)) {
        throw new SessionLifecycleConflictError(
          "TERMINAL_SESSION",
          "A terminal session cannot be invalidated",
        );
      }
      return invalidRecord(record, input.invalidatedAt, input.reason);
    });
  }

  getSession(sessionIdInput: unknown): Readonly<SessionRecordV1> | undefined {
    const sessionId = parseSessionInput(UuidSchema, sessionIdInput);
    return this.readTransaction(() => {
      const row = this.getSessionRow(sessionId);
      return row === undefined ? undefined : parseRecordJson(row.record_json);
    });
  }

  getSummary(): Readonly<SessionLifecycleSummaryV1> {
    return this.readTransaction(() => {
      const rows = this.database
        .prepare(
          "SELECT state, COUNT(*) AS count FROM rsi_session_lifecycle_sessions GROUP BY state",
        )
        .all() as unknown as { count: number; state: SessionState }[];
      const states = Object.fromEntries(SESSION_STATES.map((state) => [state, 0])) as Record<
        SessionState,
        number
      >;
      for (const row of rows) states[row.state] = row.count;
      const metadata = this.getMetadata();
      return deepFreeze({
        activeSessionCount: metadata.active_count,
        auditEntryCount: metadata.next_audit_sequence - 1,
        profile: this.profile,
        schemaVersion: 1 as const,
        sessionCount: metadata.session_count,
        states,
      });
    });
  }

  getTrustedHead(): Readonly<SessionLifecycleTrustedHeadV1> {
    return this.readTransaction(() => {
      const metadata = this.getMetadata();
      return Object.freeze({
        auditMac: metadata.audit_head_mac,
        auditSequence: metadata.next_audit_sequence - 1,
        profile: this.profile,
        schemaVersion: 1 as const,
      });
    });
  }

  verifyIntegrity(): Readonly<SessionLifecycleIntegrityReportV1> {
    return this.readTransaction(() => {
      const metadata = this.getMetadata();
      return Object.freeze({
        activeSessionCount: metadata.active_count,
        auditEntryCount: metadata.next_audit_sequence - 1,
        profile: this.profile,
        schemaVersion: 1 as const,
        sessionCount: metadata.session_count,
        valid: true as const,
      });
    });
  }

  close(): void {
    this.assertAuthentic();
    if (this.closed) return;
    this.closed = true;
    try {
      this.database.close();
    } finally {
      this.macKey.fill(0);
      OPEN_PATHS.delete(this.path);
    }
  }

  private configureDatabase(): void {
    this.database.exec("PRAGMA foreign_keys = ON");
    this.database.exec("PRAGMA trusted_schema = OFF");
    this.database.exec("PRAGMA recursive_triggers = OFF");
    this.database.exec("PRAGMA busy_timeout = 0");
    this.database.exec("PRAGMA journal_mode = DELETE");
    this.database.exec("PRAGMA synchronous = FULL");
    this.database.exec("PRAGMA locking_mode = EXCLUSIVE");
    this.database.exec("BEGIN EXCLUSIVE");
    this.database.exec("COMMIT");
  }

  private initializeSchema(): void {
    this.database.exec(CREATE_SCHEMA_SQL);
  }

  private initializeOrVerifyMetadata(namespaceWasEmpty: boolean): void {
    const row = this.database
      .prepare("SELECT * FROM rsi_session_lifecycle_metadata WHERE singleton = 1")
      .get() as unknown as MetadataRow | undefined;
    if (row !== undefined) {
      this.verifyIntegrityInternal();
      return;
    }
    if (!namespaceWasEmpty) throw new SessionLifecycleIntegrityError();
    const sessions = (
      this.database
        .prepare("SELECT COUNT(*) AS count FROM rsi_session_lifecycle_sessions")
        .get() as {
        count: number;
      }
    ).count;
    const audit = (
      this.database.prepare("SELECT COUNT(*) AS count FROM rsi_session_lifecycle_audit").get() as {
        count: number;
      }
    ).count;
    if (sessions !== 0 || audit !== 0) throw new SessionLifecycleIntegrityError();
    const projection = this.schemaProjection();
    const metadata = {
      active_count: 0,
      audit_head_mac: GENESIS_MAC,
      key_check_mac: this.keyCheckMac(),
      latest_occurred_at: null,
      next_audit_sequence: 1,
      profile: this.profile,
      rows_mac: this.rowsMac([]),
      schema_projection_mac: mac(this.macKey, "schema-projection", projection),
      schema_version: SCHEMA_VERSION,
      session_count: 0,
      singleton: 1,
    };
    const metadataMac = this.metadataMac(metadata);
    this.database
      .prepare(
        `INSERT INTO rsi_session_lifecycle_metadata (
          singleton, schema_version, profile, key_check_mac, next_audit_sequence,
          session_count, active_count, latest_occurred_at, rows_mac, audit_head_mac,
          schema_projection_mac, metadata_mac
        ) VALUES (1, ?, ?, ?, 1, 0, 0, NULL, ?, ?, ?, ?)`,
      )
      .run(
        SCHEMA_VERSION,
        this.profile,
        metadata.key_check_mac,
        metadata.rows_mac,
        metadata.audit_head_mac,
        metadata.schema_projection_mac,
        metadataMac,
      );
    this.verifyIntegrityInternal();
  }

  private recoverNonterminalSessions(recoveredAt: string): Readonly<SessionRecoveryReceiptV1> {
    return this.writeTransaction(() => {
      const metadata = this.getMetadata();
      if (
        metadata.latest_occurred_at !== null &&
        milliseconds(recoveredAt) < milliseconds(metadata.latest_occurred_at)
      ) {
        throw new SessionLifecycleValidationError();
      }
      const rows = this.database
        .prepare(
          `SELECT * FROM rsi_session_lifecycle_sessions
             WHERE state NOT IN ('accepted', 'invalid') ORDER BY session_id`,
        )
        .all() as unknown as SessionRow[];
      for (const row of rows) {
        const record = parseRecordJson(row.record_json);
        if (milliseconds(recoveredAt) < milliseconds(record.updatedAt)) {
          throw new SessionLifecycleValidationError();
        }
      }
      for (const row of rows) {
        const record = parseRecordJson(row.record_json);
        const input = {
          reason: "crash-recovery" as const,
          recoveredAt,
          sessionId: record.sessionId,
        };
        const invalid = invalidRecord(record, recoveredAt, "crash-recovery");
        this.putSession(invalid);
        this.appendAudit("crash-recovery", input, record.state, invalid);
      }
      return Object.freeze({
        cleanupRequired: rows.length > 0,
        invalidatedSessionCount: rows.length,
        schemaVersion: 1 as const,
      });
    });
  }

  private mutate<T extends { sessionId: string }>(
    action: AuditAction,
    input: T,
    occurredAt: string,
    expectedState: SessionState | null | undefined,
    change: (record: SessionRecordV1) => SessionRecordV1,
  ): Readonly<SessionRecordV1> {
    return this.writeTransaction(() => {
      const inputJson = canonicalJson(input);
      const prior = this.getAuditByAction(input.sessionId, action);
      if (prior !== undefined) {
        if (prior.input_json !== inputJson) {
          throw new SessionLifecycleConflictError(
            "RETRY_CONFLICT",
            "A lifecycle transition was retried with different input",
          );
        }
        return parseRecordJson(prior.record_json);
      }
      const metadata = this.getMetadata();
      if (
        metadata.latest_occurred_at !== null &&
        milliseconds(occurredAt) < milliseconds(metadata.latest_occurred_at)
      ) {
        throw new SessionLifecycleValidationError();
      }
      const row = this.getSessionRow(input.sessionId);
      if (expectedState === null) {
        if (row !== undefined) {
          throw new SessionLifecycleConflictError(
            "RETRY_CONFLICT",
            "A session identifier was reused with different input",
          );
        }
        const record = change(undefined as never);
        assertRecordSemantics(record);
        this.putSession(record);
        this.appendAudit(action, input, null, record);
        return deepFreeze(record);
      }
      if (row === undefined) {
        throw new SessionLifecycleConflictError("SESSION_NOT_FOUND", "The session does not exist");
      }
      const current = parseRecordJson(row.record_json);
      if (milliseconds(occurredAt) < milliseconds(current.updatedAt)) {
        throw new SessionLifecycleValidationError();
      }
      if (expectedState !== undefined && current.state !== expectedState) {
        throw new SessionLifecycleConflictError(
          isTerminal(current.state) ? "TERMINAL_SESSION" : "TRANSITION_CONFLICT",
          "The lifecycle transition is not valid from the current state",
        );
      }
      const record = change(current);
      assertRecordSemantics(record);
      this.putSession(record);
      this.appendAudit(action, input, current.state, record);
      return deepFreeze(record);
    });
  }

  private putSession(record: SessionRecordV1): void {
    const recordJson = canonicalJson(record);
    const row = {
      active_profile: activeProfile(record),
      profile: record.profile,
      qualification_date: record.qualificationDate,
      record_json: recordJson,
      session_id: record.sessionId,
      state: record.state,
    };
    const rowMac = this.sessionRowMac(row);
    this.database
      .prepare(
        `INSERT INTO rsi_session_lifecycle_sessions (
          session_id, profile, qualification_date, state, active_profile, record_json, row_mac
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(session_id) DO UPDATE SET
          profile = excluded.profile,
          qualification_date = excluded.qualification_date,
          state = excluded.state,
          active_profile = excluded.active_profile,
          record_json = excluded.record_json,
          row_mac = excluded.row_mac`,
      )
      .run(
        row.session_id,
        row.profile,
        row.qualification_date,
        row.state,
        row.active_profile,
        row.record_json,
        rowMac,
      );
  }

  private appendAudit(
    action: AuditAction,
    input: unknown,
    fromState: SessionState | null,
    record: SessionRecordV1,
  ): void {
    const metadata = this.getMetadata();
    const row = {
      action,
      from_state: fromState,
      input_json: canonicalJson(input),
      occurred_at: record.updatedAt,
      previous_mac: metadata.audit_head_mac,
      record_json: canonicalJson(record),
      sequence: metadata.next_audit_sequence,
      session_id: record.sessionId,
      to_state: record.state,
    };
    const rowMac = this.auditRowMac(row);
    this.database
      .prepare(
        `INSERT INTO rsi_session_lifecycle_audit (
          sequence, session_id, action, occurred_at, from_state, to_state,
          input_json, record_json, previous_mac, row_mac
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        row.sequence,
        row.session_id,
        row.action,
        row.occurred_at,
        row.from_state,
        row.to_state,
        row.input_json,
        row.record_json,
        row.previous_mac,
        rowMac,
      );
    this.refreshMetadata();
  }

  private refreshMetadata(): void {
    const sessions = this.getAllSessionRows();
    const audit = this.getAllAuditRows();
    const activeCount = sessions.filter((row) => row.active_profile !== null).length;
    const auditHead = audit.at(-1)?.row_mac ?? GENESIS_MAC;
    const latestOccurredAt = audit.at(-1)?.occurred_at ?? null;
    const projection = this.schemaProjection();
    const metadata = {
      active_count: activeCount,
      audit_head_mac: auditHead,
      key_check_mac: this.keyCheckMac(),
      latest_occurred_at: latestOccurredAt,
      next_audit_sequence: audit.length + 1,
      profile: this.profile,
      rows_mac: this.rowsMac(sessions),
      schema_projection_mac: mac(this.macKey, "schema-projection", projection),
      schema_version: SCHEMA_VERSION,
      session_count: sessions.length,
      singleton: 1,
    };
    const metadataMac = this.metadataMac(metadata);
    const changed = this.database
      .prepare(
        `UPDATE rsi_session_lifecycle_metadata SET
          schema_version = ?, profile = ?, key_check_mac = ?, next_audit_sequence = ?,
          session_count = ?, active_count = ?, latest_occurred_at = ?, rows_mac = ?,
          audit_head_mac = ?, schema_projection_mac = ?, metadata_mac = ?
        WHERE singleton = 1`,
      )
      .run(
        metadata.schema_version,
        metadata.profile,
        metadata.key_check_mac,
        metadata.next_audit_sequence,
        metadata.session_count,
        metadata.active_count,
        metadata.latest_occurred_at,
        metadata.rows_mac,
        metadata.audit_head_mac,
        metadata.schema_projection_mac,
        metadataMac,
      );
    if (changed.changes !== 1) throw new SessionLifecycleIntegrityError();
  }

  private verifyIntegrityInternal(): void {
    try {
      const metadata = this.getMetadata();
      const projection = this.schemaProjection();
      if (
        metadata.singleton !== 1 ||
        metadata.schema_version !== SCHEMA_VERSION ||
        metadata.profile !== this.profile ||
        !Number.isSafeInteger(metadata.next_audit_sequence) ||
        metadata.next_audit_sequence < 1 ||
        !Number.isSafeInteger(metadata.session_count) ||
        metadata.session_count < 0 ||
        metadata.session_count > MAX_SESSION_RECORDS ||
        !Number.isSafeInteger(metadata.active_count) ||
        metadata.active_count < 0 ||
        metadata.active_count > 1 ||
        (metadata.latest_occurred_at !== null &&
          !CanonicalTimestampSchema.safeParse(metadata.latest_occurred_at).success) ||
        !secureEqual(metadata.key_check_mac, this.keyCheckMac()) ||
        !secureEqual(
          metadata.schema_projection_mac,
          mac(this.macKey, "schema-projection", projection),
        ) ||
        !secureEqual(metadata.metadata_mac, this.metadataMac(metadata))
      ) {
        throw new SessionLifecycleIntegrityError();
      }

      const sessions = this.getAllSessionRows();
      if (sessions.length !== metadata.session_count || sessions.length > MAX_SESSION_RECORDS) {
        throw new SessionLifecycleIntegrityError();
      }
      const acceptedDates = new Set<string>();
      let activeCount = 0;
      const finalRecords = new Map<string, string>();
      for (const row of sessions) {
        const unsigned = {
          active_profile: row.active_profile,
          profile: row.profile,
          qualification_date: row.qualification_date,
          record_json: row.record_json,
          session_id: row.session_id,
          state: row.state,
        };
        if (!secureEqual(row.row_mac, this.sessionRowMac(unsigned))) {
          throw new SessionLifecycleIntegrityError();
        }
        const record = parseRecordJson(row.record_json);
        if (
          record.sessionId !== row.session_id ||
          record.profile !== row.profile ||
          record.profile !== this.profile ||
          record.qualificationDate !== row.qualification_date ||
          record.state !== row.state ||
          row.active_profile !== activeProfile(record)
        ) {
          throw new SessionLifecycleIntegrityError();
        }
        if (row.active_profile !== null) activeCount += 1;
        if (row.state === "accepted") {
          const key = `${row.profile}\0${row.qualification_date}`;
          if (acceptedDates.has(key)) throw new SessionLifecycleIntegrityError();
          acceptedDates.add(key);
        }
        finalRecords.set(row.session_id, row.record_json);
      }
      if (
        activeCount !== metadata.active_count ||
        !secureEqual(metadata.rows_mac, this.rowsMac(sessions))
      ) {
        throw new SessionLifecycleIntegrityError();
      }

      const audit = this.getAllAuditRows();
      if (audit.length > MAX_AUDIT_RECORDS || metadata.next_audit_sequence !== audit.length + 1) {
        throw new SessionLifecycleIntegrityError();
      }
      let previousMac = GENESIS_MAC;
      let previousTime: string | null = null;
      const replayStates = new Map<string, SessionState>();
      const replayRecords = new Map<string, string>();
      for (const [index, row] of audit.entries()) {
        const unsigned = {
          action: row.action,
          from_state: row.from_state,
          input_json: row.input_json,
          occurred_at: row.occurred_at,
          previous_mac: row.previous_mac,
          record_json: row.record_json,
          sequence: row.sequence,
          session_id: row.session_id,
          to_state: row.to_state,
        };
        if (
          row.sequence !== index + 1 ||
          !AUDIT_ACTIONS.includes(row.action) ||
          !secureEqual(row.previous_mac, previousMac) ||
          !secureEqual(row.row_mac, this.auditRowMac(unsigned)) ||
          !CanonicalTimestampSchema.safeParse(row.occurred_at).success ||
          (previousTime !== null && milliseconds(row.occurred_at) < milliseconds(previousTime))
        ) {
          throw new SessionLifecycleIntegrityError();
        }
        parseAuditInput(row);
        const priorState = replayStates.get(row.session_id) ?? null;
        if (priorState !== row.from_state) throw new SessionLifecycleIntegrityError();
        assertTransition(row.action, row.from_state, row.to_state);
        const record = parseRecordJson(row.record_json);
        if (
          record.sessionId !== row.session_id ||
          record.state !== row.to_state ||
          record.updatedAt !== row.occurred_at
        ) {
          throw new SessionLifecycleIntegrityError();
        }
        replayStates.set(row.session_id, row.to_state);
        replayRecords.set(row.session_id, row.record_json);
        previousMac = row.row_mac;
        previousTime = row.occurred_at;
      }
      if (
        !secureEqual(metadata.audit_head_mac, previousMac) ||
        metadata.latest_occurred_at !== previousTime ||
        replayRecords.size !== finalRecords.size
      ) {
        throw new SessionLifecycleIntegrityError();
      }
      for (const [sessionId, recordJson] of finalRecords) {
        if (replayRecords.get(sessionId) !== recordJson) throw new SessionLifecycleIntegrityError();
      }
    } catch (error) {
      if (error instanceof SessionLifecycleClosedError) throw error;
      if (error instanceof SessionLifecycleIntegrityError) throw error;
      throw new SessionLifecycleIntegrityError();
    }
  }

  private readTransaction<T>(read: () => T): T {
    this.assertOpen();
    this.database.exec("BEGIN");
    try {
      this.verifyIntegrityInternal();
      const result = read();
      this.verifyIntegrityInternal();
      this.database.exec("COMMIT");
      return result;
    } catch (error) {
      if (this.database.isTransaction) this.database.exec("ROLLBACK");
      throw error;
    }
  }

  private writeTransaction<T>(write: () => T): T {
    this.assertOpen();
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.verifyIntegrityInternal();
      const result = write();
      this.verifyIntegrityInternal();
      this.database.exec("COMMIT");
      return result;
    } catch (error) {
      if (this.database.isTransaction) this.database.exec("ROLLBACK");
      throw error;
    }
  }

  private getMetadata(): MetadataRow {
    const row = this.database
      .prepare("SELECT * FROM rsi_session_lifecycle_metadata WHERE singleton = 1")
      .get() as unknown as MetadataRow | undefined;
    if (row === undefined) throw new SessionLifecycleIntegrityError();
    return row;
  }

  private getSessionRow(sessionId: string): SessionRow | undefined {
    return this.database
      .prepare("SELECT * FROM rsi_session_lifecycle_sessions WHERE session_id = ?")
      .get(sessionId) as unknown as SessionRow | undefined;
  }

  private getAuditByAction(sessionId: string, action: AuditAction): AuditRow | undefined {
    return this.database
      .prepare("SELECT * FROM rsi_session_lifecycle_audit WHERE session_id = ? AND action = ?")
      .get(sessionId, action) as unknown as AuditRow | undefined;
  }

  private getAllSessionRows(): SessionRow[] {
    return this.database
      .prepare("SELECT * FROM rsi_session_lifecycle_sessions ORDER BY session_id")
      .all() as unknown as SessionRow[];
  }

  private getAllAuditRows(): AuditRow[] {
    return this.database
      .prepare("SELECT * FROM rsi_session_lifecycle_audit ORDER BY sequence")
      .all() as unknown as AuditRow[];
  }

  private verifyTrustedHead(head: SessionLifecycleTrustedHeadV1): void {
    if (head.profile !== this.profile) throw new SessionLifecycleIntegrityError();
    if (head.auditSequence === 0) {
      if (!secureEqual(head.auditMac, GENESIS_MAC)) throw new SessionLifecycleIntegrityError();
      return;
    }
    const row = this.database
      .prepare("SELECT row_mac FROM rsi_session_lifecycle_audit WHERE sequence = ?")
      .get(head.auditSequence) as { row_mac: string } | undefined;
    if (row === undefined || !secureEqual(row.row_mac, head.auditMac)) {
      throw new SessionLifecycleIntegrityError();
    }
  }

  private keyCheckMac(): string {
    return mac(this.macKey, "key-check", { profile: this.profile, schemaVersion: SCHEMA_VERSION });
  }

  private sessionRowMac(row: Omit<SessionRow, "row_mac">): string {
    return mac(this.macKey, "session-row", row);
  }

  private auditRowMac(row: Omit<AuditRow, "row_mac">): string {
    return mac(this.macKey, "audit-row", row);
  }

  private rowsMac(rows: readonly SessionRow[]): string {
    return mac(
      this.macKey,
      "session-row-set",
      rows.map((row) => ({ rowMac: row.row_mac, sessionId: row.session_id })),
    );
  }

  private metadataMac(metadata: Omit<MetadataRow, "metadata_mac"> | MetadataRow): string {
    const { metadata_mac: _metadataMac, ...unsigned } = metadata as MetadataRow;
    return mac(this.macKey, "metadata-row", unsigned);
  }

  private schemaProjection(): readonly Readonly<{
    name: string;
    sql: string;
    table: string;
    type: string;
  }>[] {
    return (
      this.database
        .prepare(
          `SELECT type, name, tbl_name AS "table", sql
             FROM sqlite_schema
            WHERE name NOT LIKE 'sqlite_%'
            ORDER BY type, name`,
        )
        .all() as unknown as { name: string; sql: string | null; table: string; type: string }[]
    ).map((entry) => {
      if (entry.sql === null) throw new SessionLifecycleIntegrityError();
      return {
        name: entry.name,
        sql: entry.sql,
        table: entry.table,
        type: entry.type,
      };
    });
  }

  private assertOpen(): void {
    this.assertAuthentic();
    if (this.closed) throw new SessionLifecycleClosedError();
  }

  private assertAuthentic(): void {
    if (
      Object.getPrototypeOf(this) !== SqliteSessionCoordinator.prototype ||
      !authenticCoordinators.has(this)
    ) {
      throw new SessionLifecycleIntegrityError();
    }
  }

  private closeAfterFailedOpen(): void {
    if (!this.closed) {
      this.closed = true;
      try {
        this.database.close();
      } catch {
        // The original authentication/open failure remains primary.
      }
    }
    this.macKey.fill(0);
    authenticCoordinators.delete(this);
    OPEN_PATHS.delete(this.path);
  }
}

/** Returns true only after a concrete coordinator completes authenticated open and recovery. */
export function isSqliteSessionCoordinator(value: unknown): value is SqliteSessionCoordinator {
  return (
    typeof value === "object" &&
    value !== null &&
    authenticCoordinators.has(value) &&
    Object.getPrototypeOf(value) === SqliteSessionCoordinator.prototype
  );
}

/** Safely parses and freezes local evidence without mutating lifecycle state. */
export function parseSessionLocalVerificationEvidence(
  value: unknown,
): Readonly<SessionLocalVerificationEvidenceV1> {
  return parseSessionInput(SessionLocalVerificationEvidenceSchema, value);
}
