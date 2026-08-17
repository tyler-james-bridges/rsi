import { Buffer } from "node:buffer";
import { createHash, verify } from "node:crypto";
import { TextDecoder } from "node:util";

import {
  canonicalJson,
  decodeCanonicalBase64url,
  decodeSignature,
  exactArray,
  exactObject,
  importEd25519PublicKey,
  sha256,
  validateCommit,
  validateEnum,
  validateHash,
  validateIdentifier,
  validateSafeInteger,
  validateSemver,
  validateTimestamp,
  validateUuidV4,
} from "./canonical.js";
import { fail } from "./errors.js";
import type {
  BackupProfile,
  BackupPublicKeyV1,
  BackupRetention,
  BackupSessionState,
  CheckpointHeadExportV1,
  CheckpointPayloadV1,
  ConfigSchemaHashV1,
  ConfigSchemaName,
  EventStateEvidenceV1,
  RecoveryEvidenceV1,
  RecoveryRunbookId,
  ReleaseEvidenceV1,
  SanitizedStateEvidenceSnapshotV1,
  SignedCheckpointV1,
} from "./types.js";

export const MAX_JOURNAL_ENTRIES = 4_096;
export const MAX_JOURNAL_BYTES = 2 * 1024 * 1024;
export const MAX_JSON_ARTIFACT_BYTES = 64 * 1024;

const CHECKPOINT_SIGNATURE_DOMAIN = Buffer.from("rsi-store-checkpoint-signature-v1\0", "utf8");
const CHECKPOINT_HASH_DOMAIN = Buffer.from("rsi-store-checkpoint-entry-v1\0", "utf8");
const GENESIS_HASH = "0".repeat(64);
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

const PROFILES = ["canary", "production-observer"] as const;
const RETENTIONS = ["month-end-365d", "session-30d"] as const;
const SESSION_STATES = ["accepted", "acceptance-ready", "locally-verified"] as const;
const CONFIG_SCHEMA_NAMES = [
  "alert-outbox",
  "backup-manifest",
  "capture-registry",
  "checkpoint-journal",
  "event-state",
  "external-anchor-outbox",
  "observer-config",
  "operations-state",
  "preflight-report",
  "public-projection",
  "sanitized-event-archive",
  "sanitized-state-evidence",
  "session-controller",
  "session-lifecycle",
  "source-contracts",
  "vault",
] as const;
const RUNBOOK_IDS = Array.from(
  { length: 19 },
  (_, index) => `RB-${String(index + 1).padStart(2, "0")}`,
) as RecoveryRunbookId[];

interface PublicKeysArtifactV1 {
  readonly keys: readonly [
    Readonly<BackupPublicKeyV1 & { readonly role: "checkpoint" }>,
    Readonly<BackupPublicKeyV1 & { readonly role: "release" }>,
  ];
  readonly publicKeysType: "rsi.backup.public-keys";
  readonly version: 1;
}

interface ConfigSchemasArtifactV1 {
  readonly configSchemaHashesType: "rsi.backup.config-schema-hashes";
  readonly schemas: readonly ConfigSchemaHashV1[];
  readonly version: 1;
}

interface RecoveryEvidenceArtifactV1 {
  readonly records: readonly RecoveryEvidenceV1[];
  readonly recoveryEvidenceType: "rsi.backup.recovery-evidence";
  readonly version: 1;
}

export interface SanitizedArtifactSet {
  readonly checkpointHead: CheckpointHeadExportV1;
  readonly checkpointJournal: readonly SignedCheckpointV1[];
  readonly checkpointJournalBytes: Buffer;
  readonly checkpointPublicKey: BackupPublicKeyV1;
  readonly configSchemas: ConfigSchemasArtifactV1;
  readonly eventState: EventStateEvidenceV1;
  readonly profile: BackupProfile;
  readonly publicKeys: PublicKeysArtifactV1;
  readonly recoveryEvidence: RecoveryEvidenceArtifactV1;
  readonly release: ReleaseEvidenceV1;
  readonly releasePublicKey: BackupPublicKeyV1;
  readonly retention: BackupRetention;
  readonly sessionId: string;
  readonly sessionState: BackupSessionState;
  readonly sessionStateAt: string;
}

export interface ArtifactObjects {
  readonly checkpointHead: unknown;
  readonly checkpointJournal: readonly unknown[];
  readonly checkpointJournalBytes: Buffer;
  readonly configSchemas: unknown;
  readonly eventState: unknown;
  readonly publicKeys: unknown;
  readonly recoveryEvidence: unknown;
  readonly release: unknown;
}

export function sanitizeSnapshot(value: unknown): SanitizedArtifactSet {
  const record = exactObject(
    value,
    [
      "checkpointJournal",
      "checkpointPublicKey",
      "configSchemas",
      "eventState",
      "profile",
      "recoveryEvidence",
      "release",
      "releasePublicKey",
      "retention",
      "sessionId",
      "sessionState",
      "sessionStateAt",
      "trustedCheckpointHead",
    ],
    "Snapshot",
  );
  const profile = validateEnum(record.profile, PROFILES, "Backup profile");
  const retention = validateEnum(record.retention, RETENTIONS, "Backup retention");
  const sessionId = validateUuidV4(record.sessionId, "Session identifier");
  const sessionState = validateEnum(record.sessionState, SESSION_STATES, "Session state");
  const sessionStateAt = validateTimestamp(record.sessionStateAt, "Session state timestamp");
  const eventState = parseEventState(record.eventState);
  const checkpointPublicKey = parsePublicKey(record.checkpointPublicKey, "Checkpoint public key");
  const releasePublicKey = parsePublicKey(record.releasePublicKey, "Release public key");
  if (checkpointPublicKey.fingerprintSha256 === releasePublicKey.fingerprintSha256) {
    fail("INPUT_INVALID", "Checkpoint and release keys must be distinct");
  }
  const release = parseReleaseEvidence(record.release);
  if (
    release.keyId !== releasePublicKey.keyId ||
    release.publicKeyFingerprint !== releasePublicKey.fingerprintSha256
  ) {
    fail("INPUT_INVALID", "Release evidence does not bind the release public key");
  }
  const configSchemas = parseConfigSchemas(record.configSchemas);
  const configArtifact: ConfigSchemasArtifactV1 = Object.freeze({
    configSchemaHashesType: "rsi.backup.config-schema-hashes",
    schemas: configSchemas,
    version: 1,
  });
  if (sha256(canonicalJson(configArtifact)) !== release.configSetSha256) {
    fail("INPUT_INVALID", "Release evidence does not bind the config schema set");
  }
  const recoveryRecords = parseRecoveryEvidence(record.recoveryEvidence, release, sessionStateAt);
  const recoveryEvidence: RecoveryEvidenceArtifactV1 = Object.freeze({
    records: recoveryRecords,
    recoveryEvidenceType: "rsi.backup.recovery-evidence",
    version: 1,
  });
  const checkpointJournal = parseCheckpointJournal(record.checkpointJournal);
  const trustedHeadRecord = exactObject(
    record.trustedCheckpointHead,
    ["checkpointHash", "journalSequence"],
    "Trusted checkpoint head",
  );
  const trustedCheckpointHash = validateHash(
    trustedHeadRecord.checkpointHash,
    "Trusted checkpoint hash",
  );
  const trustedJournalSequence = validateSafeInteger(
    trustedHeadRecord.journalSequence,
    "Trusted checkpoint sequence",
    1,
  );
  validateCheckpointJournal(checkpointJournal, checkpointPublicKey, eventState, sessionStateAt);
  const tail = checkpointJournal.at(-1);
  if (
    tail === undefined ||
    tail.checkpointHash !== trustedCheckpointHash ||
    tail.payload.journalSequence !== trustedJournalSequence
  ) {
    fail("INPUT_INVALID", "Trusted checkpoint head must equal the journal tail");
  }
  const checkpointHead = checkpointHeadFrom(tail);
  const checkpointJournalBytes = Buffer.from(
    checkpointJournal.map((entry) => `${canonicalJson(entry)}\n`).join(""),
    "utf8",
  );
  if (checkpointJournalBytes.length > MAX_JOURNAL_BYTES) {
    fail("INPUT_INVALID", "Checkpoint journal exceeds its byte bound");
  }
  const keys: PublicKeysArtifactV1["keys"] = Object.freeze([
    Object.freeze({ role: "checkpoint" as const, ...checkpointPublicKey }),
    Object.freeze({ role: "release" as const, ...releasePublicKey }),
  ] as const);
  const publicKeys: PublicKeysArtifactV1 = Object.freeze({
    keys,
    publicKeysType: "rsi.backup.public-keys",
    version: 1,
  });
  return Object.freeze({
    checkpointHead,
    checkpointJournal,
    checkpointJournalBytes,
    checkpointPublicKey,
    configSchemas: configArtifact,
    eventState,
    profile,
    publicKeys,
    recoveryEvidence,
    release,
    releasePublicKey,
    retention,
    sessionId,
    sessionState,
    sessionStateAt,
  });
}

export function validateDecodedArtifacts(
  objects: ArtifactObjects,
  binding: {
    readonly profile: unknown;
    readonly retention: unknown;
    readonly sessionId: unknown;
    readonly sessionState: unknown;
    readonly sessionStateAt: unknown;
  },
): SanitizedArtifactSet {
  const publicKeys = parsePublicKeysArtifact(objects.publicKeys);
  const configArtifactRecord = exactObject(
    objects.configSchemas,
    ["configSchemaHashesType", "schemas", "version"],
    "Config schema artifact",
  );
  if (
    configArtifactRecord.configSchemaHashesType !== "rsi.backup.config-schema-hashes" ||
    configArtifactRecord.version !== 1
  ) {
    fail("ARCHIVE_FORMAT", "Config schema artifact version is unsupported");
  }
  const configSchemas: ConfigSchemasArtifactV1 = Object.freeze({
    configSchemaHashesType: "rsi.backup.config-schema-hashes",
    schemas: parseConfigSchemas(configArtifactRecord.schemas),
    version: 1,
  });
  const recoveryArtifactRecord = exactObject(
    objects.recoveryEvidence,
    ["records", "recoveryEvidenceType", "version"],
    "Recovery evidence artifact",
  );
  if (
    recoveryArtifactRecord.recoveryEvidenceType !== "rsi.backup.recovery-evidence" ||
    recoveryArtifactRecord.version !== 1
  ) {
    fail("ARCHIVE_FORMAT", "Recovery evidence artifact version is unsupported");
  }
  const release = parseReleaseEvidence(objects.release);
  const sessionStateAt = validateTimestamp(binding.sessionStateAt, "Session state timestamp");
  const recoveryEvidence: RecoveryEvidenceArtifactV1 = Object.freeze({
    records: parseRecoveryEvidence(recoveryArtifactRecord.records, release, sessionStateAt),
    recoveryEvidenceType: "rsi.backup.recovery-evidence",
    version: 1,
  });
  if (sha256(canonicalJson(configSchemas)) !== release.configSetSha256) {
    fail("INTEGRITY_MISMATCH", "Release/config binding is invalid");
  }
  if (
    release.keyId !== publicKeys.keys[1].keyId ||
    release.publicKeyFingerprint !== publicKeys.keys[1].fingerprintSha256
  ) {
    fail("INTEGRITY_MISMATCH", "Release/public-key binding is invalid");
  }
  const eventState = parseEventState(objects.eventState);
  const checkpointJournal = parseCheckpointJournal(objects.checkpointJournal);
  if (!objects.checkpointJournalBytes.equals(encodeJournal(checkpointJournal))) {
    fail("ARCHIVE_FORMAT", "Checkpoint journal is not canonical");
  }
  validateCheckpointJournal(checkpointJournal, publicKeys.keys[0], eventState, sessionStateAt);
  const tail = checkpointJournal.at(-1);
  if (tail === undefined) fail("ARCHIVE_FORMAT", "Checkpoint journal is empty");
  const checkpointHead = parseCheckpointHead(objects.checkpointHead);
  const derivedHead = checkpointHeadFrom(tail);
  if (canonicalJson(checkpointHead) !== canonicalJson(derivedHead)) {
    fail("INTEGRITY_MISMATCH", "Checkpoint head does not equal the journal tail");
  }
  const profile = validateEnum(binding.profile, PROFILES, "Backup profile");
  const retention = validateEnum(binding.retention, RETENTIONS, "Backup retention");
  const sessionId = validateUuidV4(binding.sessionId, "Session identifier");
  const sessionState = validateEnum(binding.sessionState, SESSION_STATES, "Session state");
  return Object.freeze({
    checkpointHead,
    checkpointJournal,
    checkpointJournalBytes: Buffer.from(objects.checkpointJournalBytes),
    checkpointPublicKey: publicKeys.keys[0],
    configSchemas,
    eventState,
    profile,
    publicKeys,
    recoveryEvidence,
    release,
    releasePublicKey: publicKeys.keys[1],
    retention,
    sessionId,
    sessionState,
    sessionStateAt,
  });
}

export function parseCanonicalJson(bytes: Uint8Array, safeName: string): unknown {
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_JSON_ARTIFACT_BYTES) {
    fail("ARCHIVE_BOUNDS", `${safeName} is outside its byte bound`);
  }
  let text: string;
  try {
    text = utf8Decoder.decode(bytes);
  } catch {
    fail("ARCHIVE_FORMAT", `${safeName} is not valid UTF-8`);
  }
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    fail("ARCHIVE_FORMAT", `${safeName} is not valid JSON`);
  }
  if (canonicalJson(value) !== text) {
    fail("ARCHIVE_FORMAT", `${safeName} is not canonical JSON`);
  }
  return value;
}

export function parseCanonicalJournal(bytes: Uint8Array): readonly unknown[] {
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_JOURNAL_BYTES) {
    fail("ARCHIVE_BOUNDS", "Checkpoint journal is outside its byte bound");
  }
  let text: string;
  try {
    text = utf8Decoder.decode(bytes);
  } catch {
    fail("ARCHIVE_FORMAT", "Checkpoint journal is not valid UTF-8");
  }
  if (!text.endsWith("\n")) fail("ARCHIVE_FORMAT", "Checkpoint journal is truncated");
  const lines = text.slice(0, -1).split("\n");
  if (lines.length === 0 || lines.length > MAX_JOURNAL_ENTRIES || lines.some((line) => !line)) {
    fail("ARCHIVE_BOUNDS", "Checkpoint journal entry count is invalid");
  }
  return Object.freeze(
    lines.map((line) => {
      let value: unknown;
      try {
        value = JSON.parse(line) as unknown;
      } catch {
        fail("ARCHIVE_FORMAT", "Checkpoint journal entry is invalid JSON");
      }
      if (canonicalJson(value) !== line) {
        fail("ARCHIVE_FORMAT", "Checkpoint journal entry is not canonical JSON");
      }
      return value;
    }),
  );
}

function parseEventState(value: unknown): EventStateEvidenceV1 {
  const record = exactObject(
    value,
    ["eventCount", "eventStateType", "headHash", "headSequence", "storeId", "version"],
    "Event-state export",
  );
  if (record.eventStateType !== "rsi.backup.event-state-evidence" || record.version !== 1) {
    fail("INPUT_INVALID", "Event-state export version is unsupported");
  }
  const eventCount = validateSafeInteger(record.eventCount, "Event count", 1);
  const headSequence = validateSafeInteger(record.headSequence, "Event head sequence", 1);
  if (eventCount !== headSequence) {
    fail("INPUT_INVALID", "Event count must equal the event head sequence");
  }
  return Object.freeze({
    eventCount,
    eventStateType: "rsi.backup.event-state-evidence",
    headHash: validateHash(record.headHash, "Event head hash"),
    headSequence,
    storeId: validateIdentifier(record.storeId, "Store identifier"),
    version: 1,
  });
}

function parsePublicKey(value: unknown, safeName: string): BackupPublicKeyV1 {
  const record = exactObject(value, ["fingerprintSha256", "keyId", "spkiDerBase64url"], safeName);
  const spkiDer = decodeCanonicalBase64url(record.spkiDerBase64url, safeName, 512);
  importEd25519PublicKey(spkiDer, safeName);
  const fingerprint = validateHash(record.fingerprintSha256, `${safeName} fingerprint`);
  if (sha256(spkiDer) !== fingerprint) {
    fail("INPUT_INVALID", `${safeName} fingerprint is invalid`);
  }
  return Object.freeze({
    fingerprintSha256: fingerprint,
    keyId: validateIdentifier(record.keyId, `${safeName} identifier`),
    spkiDerBase64url: spkiDer.toString("base64url"),
  });
}

function parsePublicKeysArtifact(value: unknown): PublicKeysArtifactV1 {
  const record = exactObject(value, ["keys", "publicKeysType", "version"], "Public-key artifact");
  if (record.publicKeysType !== "rsi.backup.public-keys" || record.version !== 1) {
    fail("ARCHIVE_FORMAT", "Public-key artifact version is unsupported");
  }
  const keys = exactArray(record.keys, "Public-key list");
  if (keys.length !== 2) fail("ARCHIVE_FORMAT", "Public-key list has an invalid count");
  const parseRole = <Role extends "checkpoint" | "release">(
    entry: unknown,
    expectedRole: Role,
  ): Readonly<BackupPublicKeyV1 & { readonly role: Role }> => {
    const keyRecord = exactObject(
      entry,
      ["fingerprintSha256", "keyId", "role", "spkiDerBase64url"],
      "Public-key record",
    );
    if (keyRecord.role !== expectedRole) fail("ARCHIVE_FORMAT", "Public-key role order is invalid");
    return Object.freeze({
      role: expectedRole,
      ...parsePublicKey(
        {
          fingerprintSha256: keyRecord.fingerprintSha256,
          keyId: keyRecord.keyId,
          spkiDerBase64url: keyRecord.spkiDerBase64url,
        },
        "Public key",
      ),
    });
  };
  const checkpoint = parseRole(keys[0], "checkpoint");
  const release = parseRole(keys[1], "release");
  if (checkpoint.fingerprintSha256 === release.fingerprintSha256) {
    fail("ARCHIVE_FORMAT", "Checkpoint and release keys must be distinct");
  }
  const parsedKeys: PublicKeysArtifactV1["keys"] = Object.freeze([checkpoint, release] as const);
  return Object.freeze({
    keys: parsedKeys,
    publicKeysType: "rsi.backup.public-keys",
    version: 1,
  });
}

function parseConfigSchemas(value: unknown): readonly ConfigSchemaHashV1[] {
  const entries = exactArray(value, "Config schema list");
  if (entries.length === 0 || entries.length > CONFIG_SCHEMA_NAMES.length) {
    fail("INPUT_INVALID", "Config schema list count is invalid");
  }
  const parsed = entries.map((entry) => {
    const record = exactObject(entry, ["name", "schemaSha256", "version"], "Config schema");
    return Object.freeze({
      name: validateEnum(record.name, CONFIG_SCHEMA_NAMES, "Config schema name"),
      schemaSha256: validateHash(record.schemaSha256, "Config schema hash"),
      version: validateSafeInteger(record.version, "Config schema version", 1),
    });
  });
  for (let index = 0; index < parsed.length; index += 1) {
    if (index > 0 && parsed[index - 1]!.name >= parsed[index]!.name) {
      fail("INPUT_INVALID", "Config schemas must be uniquely sorted by name");
    }
  }
  return Object.freeze(parsed);
}

function parseReleaseEvidence(value: unknown): ReleaseEvidenceV1 {
  const record = exactObject(
    value,
    [
      "commitSha",
      "configSetSha256",
      "keyId",
      "publicKeyFingerprint",
      "releaseEvidenceType",
      "releaseManifestSha256",
      "releaseVersion",
      "sbomSha256",
      "sourceTreeSha256",
      "status",
      "version",
    ],
    "Release evidence",
  );
  if (
    record.releaseEvidenceType !== "rsi.backup.release-evidence" ||
    record.status !== "verified" ||
    record.version !== 1
  ) {
    fail("INPUT_INVALID", "Release evidence status or version is unsupported");
  }
  return Object.freeze({
    commitSha: validateCommit(record.commitSha),
    configSetSha256: validateHash(record.configSetSha256, "Config-set hash"),
    keyId: validateIdentifier(record.keyId, "Release key identifier"),
    publicKeyFingerprint: validateHash(record.publicKeyFingerprint, "Release key fingerprint"),
    releaseEvidenceType: "rsi.backup.release-evidence",
    releaseManifestSha256: validateHash(record.releaseManifestSha256, "Release manifest hash"),
    releaseVersion: validateSemver(record.releaseVersion),
    sbomSha256: validateHash(record.sbomSha256, "SBOM hash"),
    sourceTreeSha256: validateHash(record.sourceTreeSha256, "Source-tree hash"),
    status: "verified",
    version: 1,
  });
}

function parseRecoveryEvidence(
  value: unknown,
  release: ReleaseEvidenceV1,
  sessionStateAt: string,
): readonly RecoveryEvidenceV1[] {
  const entries = exactArray(value, "Recovery evidence list");
  if (entries.length === 0 || entries.length > RUNBOOK_IDS.length) {
    fail("INPUT_INVALID", "Recovery evidence count is invalid");
  }
  const parsed = entries.map((entry) => {
    const record = exactObject(
      entry,
      ["completedAt", "evidenceSha256", "outcome", "releaseManifestSha256", "runbookId"],
      "Recovery evidence record",
    );
    const completedAt = validateTimestamp(record.completedAt, "Recovery completion timestamp");
    if (completedAt > sessionStateAt) {
      fail("INPUT_INVALID", "Recovery evidence may not postdate session state");
    }
    const releaseManifestSha256 = validateHash(
      record.releaseManifestSha256,
      "Recovery release hash",
    );
    if (releaseManifestSha256 !== release.releaseManifestSha256) {
      fail("INPUT_INVALID", "Recovery evidence does not bind the release manifest");
    }
    return Object.freeze({
      completedAt,
      evidenceSha256: validateHash(record.evidenceSha256, "Recovery evidence hash"),
      outcome: validateEnum(record.outcome, ["failed", "passed"] as const, "Recovery outcome"),
      releaseManifestSha256,
      runbookId: validateEnum(record.runbookId, RUNBOOK_IDS, "Recovery runbook"),
    });
  });
  for (let index = 0; index < parsed.length; index += 1) {
    if (index > 0 && parsed[index - 1]!.runbookId >= parsed[index]!.runbookId) {
      fail("INPUT_INVALID", "Recovery evidence must be uniquely sorted by runbook");
    }
  }
  return Object.freeze(parsed);
}

function parseCheckpointJournal(value: unknown): readonly SignedCheckpointV1[] {
  const entries = exactArray(value, "Checkpoint journal");
  if (entries.length === 0 || entries.length > MAX_JOURNAL_ENTRIES) {
    fail("INPUT_INVALID", "Checkpoint journal entry count is invalid");
  }
  return Object.freeze(entries.map((entry) => parseSignedCheckpoint(entry)));
}

function parseSignedCheckpoint(value: unknown): SignedCheckpointV1 {
  const record = exactObject(value, ["checkpointHash", "payload", "signature"], "Checkpoint entry");
  const payloadRecord = exactObject(
    record.payload,
    [
      "checkpointType",
      "createdAt",
      "journalSequence",
      "keyId",
      "previousCheckpointHash",
      "storeHeadHash",
      "storeHeadSequence",
      "storeId",
      "version",
    ],
    "Checkpoint payload",
  );
  if (payloadRecord.checkpointType !== "rsi.store.head" || payloadRecord.version !== 1) {
    fail("INPUT_INVALID", "Checkpoint payload version is unsupported");
  }
  const payload: CheckpointPayloadV1 = Object.freeze({
    checkpointType: "rsi.store.head",
    createdAt: validateTimestamp(payloadRecord.createdAt, "Checkpoint timestamp"),
    journalSequence: validateSafeInteger(
      payloadRecord.journalSequence,
      "Checkpoint journal sequence",
      1,
    ),
    keyId: validateIdentifier(payloadRecord.keyId, "Checkpoint key identifier"),
    previousCheckpointHash: validateHash(
      payloadRecord.previousCheckpointHash,
      "Previous checkpoint hash",
    ),
    storeHeadHash: validateHash(payloadRecord.storeHeadHash, "Checkpoint store-head hash"),
    storeHeadSequence: validateSafeInteger(
      payloadRecord.storeHeadSequence,
      "Checkpoint store-head sequence",
      1,
    ),
    storeId: validateIdentifier(payloadRecord.storeId, "Checkpoint store identifier"),
    version: 1,
  });
  const signature = decodeSignature(record.signature).toString("base64url");
  return Object.freeze({
    checkpointHash: validateHash(record.checkpointHash, "Checkpoint hash"),
    payload,
    signature,
  });
}

function parseCheckpointHead(value: unknown): CheckpointHeadExportV1 {
  const record = exactObject(
    value,
    [
      "checkpointHash",
      "checkpointHeadType",
      "journalSequence",
      "keyId",
      "storeHeadHash",
      "storeHeadSequence",
      "storeId",
      "version",
    ],
    "Checkpoint head",
  );
  if (record.checkpointHeadType !== "rsi.backup.checkpoint-head" || record.version !== 1) {
    fail("INPUT_INVALID", "Checkpoint head version is unsupported");
  }
  return Object.freeze({
    checkpointHash: validateHash(record.checkpointHash, "Checkpoint head hash"),
    checkpointHeadType: "rsi.backup.checkpoint-head",
    journalSequence: validateSafeInteger(record.journalSequence, "Checkpoint head sequence", 1),
    keyId: validateIdentifier(record.keyId, "Checkpoint head key identifier"),
    storeHeadHash: validateHash(record.storeHeadHash, "Checkpoint head store hash"),
    storeHeadSequence: validateSafeInteger(
      record.storeHeadSequence,
      "Checkpoint head store sequence",
      1,
    ),
    storeId: validateIdentifier(record.storeId, "Checkpoint head store identifier"),
    version: 1,
  });
}

function checkpointHeadFrom(tail: SignedCheckpointV1): CheckpointHeadExportV1 {
  return Object.freeze({
    checkpointHash: tail.checkpointHash,
    checkpointHeadType: "rsi.backup.checkpoint-head",
    journalSequence: tail.payload.journalSequence,
    keyId: tail.payload.keyId,
    storeHeadHash: tail.payload.storeHeadHash,
    storeHeadSequence: tail.payload.storeHeadSequence,
    storeId: tail.payload.storeId,
    version: 1,
  });
}

function encodeJournal(entries: readonly SignedCheckpointV1[]): Buffer {
  return Buffer.from(entries.map((entry) => `${canonicalJson(entry)}\n`).join(""), "utf8");
}

function validateCheckpointJournal(
  entries: readonly SignedCheckpointV1[],
  publicKey: BackupPublicKeyV1,
  eventState: EventStateEvidenceV1,
  sessionStateAt: string,
): void {
  const keyDer = decodeCanonicalBase64url(publicKey.spkiDerBase64url, "Checkpoint public key", 512);
  const key = importEd25519PublicKey(keyDer, "Checkpoint public key");
  let previousHash = GENESIS_HASH;
  let previousStoreSequence = 0;
  let previousTimestamp: string | undefined;
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index]!;
    const expectedSequence = index + 1;
    if (
      entry.payload.journalSequence !== expectedSequence ||
      entry.payload.previousCheckpointHash !== previousHash ||
      entry.payload.storeHeadSequence <= previousStoreSequence ||
      entry.payload.keyId !== publicKey.keyId ||
      entry.payload.storeId !== eventState.storeId ||
      (previousTimestamp !== undefined && entry.payload.createdAt < previousTimestamp) ||
      entry.payload.createdAt > sessionStateAt
    ) {
      fail("INPUT_INVALID", "Checkpoint journal linkage or binding is invalid");
    }
    const signedBytes = Buffer.concat([
      CHECKPOINT_SIGNATURE_DOMAIN,
      Buffer.from(canonicalJson(entry.payload), "utf8"),
    ]);
    if (!verify(null, signedBytes, key, decodeSignature(entry.signature))) {
      fail("SIGNATURE_INVALID", "Checkpoint signature is invalid");
    }
    const calculatedHash = createHash("sha256")
      .update(CHECKPOINT_HASH_DOMAIN)
      .update(canonicalJson({ payload: entry.payload, signature: entry.signature }), "utf8")
      .digest("hex");
    if (calculatedHash !== entry.checkpointHash) {
      fail("INTEGRITY_MISMATCH", "Checkpoint entry hash is invalid");
    }
    previousHash = entry.checkpointHash;
    previousStoreSequence = entry.payload.storeHeadSequence;
    previousTimestamp = entry.payload.createdAt;
  }
  const tail = entries.at(-1)!;
  if (
    tail.payload.storeHeadHash !== eventState.headHash ||
    tail.payload.storeHeadSequence !== eventState.headSequence
  ) {
    fail("INTEGRITY_MISMATCH", "Final checkpoint does not equal the event-state head");
  }
}
