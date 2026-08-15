import { Buffer } from "node:buffer";
import { randomUUID, verify } from "node:crypto";
import { types as utilTypes } from "node:util";

import {
  BACKUP_RECEIPT_TYPE,
  BACKUP_REPORT_TYPE,
  BACKUP_TYPE,
  BACKUP_VERSION,
  type StateEvidenceReceiptV1,
  type StateEvidenceTrustV1,
  type StateEvidenceVerificationReportV1,
} from "./types.js";
import {
  canonicalJson,
  copyBytes,
  decodeSignature,
  exactArray,
  exactObject,
  importEd25519PublicKey,
  sha256,
  validateEnum,
  validateHash,
  validateIdentifier,
  validateSafeInteger,
  validateSemver,
  validateTimestamp,
  validateUuidV4,
} from "./canonical.js";
import { fail } from "./errors.js";
import {
  MAX_JOURNAL_BYTES,
  MAX_JSON_ARTIFACT_BYTES,
  parseCanonicalJournal,
  parseCanonicalJson,
  type ArtifactObjects,
  type SanitizedArtifactSet,
  validateDecodedArtifacts,
} from "./schema.js";

export const ARCHIVE_MAGIC = Buffer.from("RSIBACKUP1", "ascii");
export const MAX_ARCHIVE_BYTES = 5 * 1024 * 1024;
export const MAX_TOTAL_ARTIFACT_BYTES = 4 * 1024 * 1024;
const MAX_ENVELOPE_BYTES = 128 * 1024;
const SIGNATURE_DOMAIN = Buffer.from("rsi-sanitized-state-evidence-manifest-v1\0", "utf8");

const ARTIFACT_DEFINITIONS = Object.freeze([
  Object.freeze({
    mediaType: "application/json",
    path: "event-state-evidence.v1.json",
    role: "event-state-evidence",
    maximumBytes: MAX_JSON_ARTIFACT_BYTES,
  }),
  Object.freeze({
    mediaType: "application/x-ndjson",
    path: "checkpoint-journal.v1.jsonl",
    role: "checkpoint-journal",
    maximumBytes: MAX_JOURNAL_BYTES,
  }),
  Object.freeze({
    mediaType: "application/json",
    path: "checkpoint-head.v1.json",
    role: "checkpoint-head",
    maximumBytes: MAX_JSON_ARTIFACT_BYTES,
  }),
  Object.freeze({
    mediaType: "application/json",
    path: "public-keys.v1.json",
    role: "public-keys",
    maximumBytes: MAX_JSON_ARTIFACT_BYTES,
  }),
  Object.freeze({
    mediaType: "application/json",
    path: "config-schema-hashes.v1.json",
    role: "config-schema-hashes",
    maximumBytes: MAX_JSON_ARTIFACT_BYTES,
  }),
  Object.freeze({
    mediaType: "application/json",
    path: "recovery-evidence.v1.json",
    role: "recovery-evidence",
    maximumBytes: MAX_JSON_ARTIFACT_BYTES,
  }),
  Object.freeze({
    mediaType: "application/json",
    path: "release-evidence.v1.json",
    role: "release-evidence",
    maximumBytes: MAX_JSON_ARTIFACT_BYTES,
  }),
] as const);

export type ArtifactRole = (typeof ARTIFACT_DEFINITIONS)[number]["role"];

export interface ArtifactDescriptorV1 {
  readonly mediaType: "application/json" | "application/x-ndjson";
  readonly path: string;
  readonly role: ArtifactRole;
  readonly sha256: string;
  readonly sizeBytes: number;
}

export interface BackupManifestV1 {
  readonly artifactCount: 7;
  readonly artifacts: readonly ArtifactDescriptorV1[];
  readonly backupId: string;
  readonly backupType: typeof BACKUP_TYPE;
  readonly checkpoint: {
    readonly checkpointHash: string;
    readonly journalSequence: number;
    readonly keyId: string;
    readonly publicKeyFingerprintSha256: string;
    readonly storeHeadHash: string;
    readonly storeHeadSequence: number;
    readonly storeId: string;
  };
  readonly componentScope: "observer-sanitized-state-evidence";
  readonly createdAt: string;
  readonly eventStateEvidence: {
    readonly eventCount: number;
    readonly headHash: string;
    readonly headSequence: number;
    readonly storeId: string;
  };
  readonly profile: "canary" | "production-observer";
  readonly recoveryCompleteness: "evidence-only";
  readonly release: {
    readonly commitSha: string;
    readonly configSetSha256: string;
    readonly keyId: string;
    readonly publicKeyFingerprintSha256: string;
    readonly releaseManifestSha256: string;
    readonly releaseVersion: string;
  };
  readonly requiredCompanionArtifacts: readonly [
    "sanitized-event-archive",
    "signed-release-bundle",
  ];
  readonly retention: "month-end-365d" | "session-30d";
  readonly session: {
    readonly id: string;
    readonly state: "accepted" | "acceptance-ready" | "locally-verified";
    readonly stateAt: string;
  };
  readonly signer: {
    readonly algorithm: "Ed25519";
    readonly keyId: string;
    readonly publicKeyFingerprintSha256: string;
  };
  readonly totalArtifactBytes: number;
  readonly version: typeof BACKUP_VERSION;
}

interface ManifestEnvelopeV1 {
  readonly manifest: BackupManifestV1;
  readonly signature: string;
}

export interface NormalizedSigner {
  readonly keyId: string;
  readonly publicKeySpkiDer: Buffer;
  readonly sign: (message: Uint8Array) => Promise<Uint8Array> | Uint8Array;
}

export interface EncodedArchive {
  readonly bytes: Buffer;
  readonly receipt: StateEvidenceReceiptV1;
}

export interface VerifiedArchive {
  readonly artifactBytes: ReadonlyMap<ArtifactRole, Buffer>;
  readonly envelope: ManifestEnvelopeV1;
  readonly report: StateEvidenceVerificationReportV1;
}

export async function encodeSignedArchive(
  data: SanitizedArtifactSet,
  signer: NormalizedSigner,
): Promise<EncodedArchive> {
  if (
    signer.keyId !== data.releasePublicKey.keyId ||
    !signer.publicKeySpkiDer.equals(
      Buffer.from(data.releasePublicKey.spkiDerBase64url, "base64url"),
    )
  ) {
    fail("INPUT_INVALID", "Manifest signer does not equal the release key");
  }
  const artifactBytes = encodeArtifactBytes(data);
  const descriptors = ARTIFACT_DEFINITIONS.map((definition) => {
    const bytes = artifactBytes.get(definition.role)!;
    if (bytes.length === 0 || bytes.length > definition.maximumBytes) {
      fail("ARCHIVE_BOUNDS", "Artifact exceeds its role-specific bound");
    }
    return Object.freeze({
      mediaType: definition.mediaType,
      path: definition.path,
      role: definition.role,
      sha256: sha256(bytes),
      sizeBytes: bytes.length,
    });
  });
  const totalArtifactBytes = descriptors.reduce((sum, descriptor) => sum + descriptor.sizeBytes, 0);
  if (totalArtifactBytes > MAX_TOTAL_ARTIFACT_BYTES) {
    fail("ARCHIVE_BOUNDS", "Backup artifact total exceeds its bound");
  }
  const backupId = randomUUID();
  const createdAt = new Date().toISOString();
  if (createdAt < data.sessionStateAt) {
    fail("INPUT_INVALID", "Backup creation time predates session state");
  }
  const manifest: BackupManifestV1 = Object.freeze({
    artifactCount: 7,
    artifacts: Object.freeze(descriptors),
    backupId,
    backupType: BACKUP_TYPE,
    checkpoint: Object.freeze({
      checkpointHash: data.checkpointHead.checkpointHash,
      journalSequence: data.checkpointHead.journalSequence,
      keyId: data.checkpointHead.keyId,
      publicKeyFingerprintSha256: data.checkpointPublicKey.fingerprintSha256,
      storeHeadHash: data.checkpointHead.storeHeadHash,
      storeHeadSequence: data.checkpointHead.storeHeadSequence,
      storeId: data.checkpointHead.storeId,
    }),
    componentScope: "observer-sanitized-state-evidence",
    createdAt,
    eventStateEvidence: Object.freeze({
      eventCount: data.eventState.eventCount,
      headHash: data.eventState.headHash,
      headSequence: data.eventState.headSequence,
      storeId: data.eventState.storeId,
    }),
    profile: data.profile,
    recoveryCompleteness: "evidence-only",
    release: Object.freeze({
      commitSha: data.release.commitSha,
      configSetSha256: data.release.configSetSha256,
      keyId: data.release.keyId,
      publicKeyFingerprintSha256: data.release.publicKeyFingerprint,
      releaseManifestSha256: data.release.releaseManifestSha256,
      releaseVersion: data.release.releaseVersion,
    }),
    requiredCompanionArtifacts: Object.freeze([
      "sanitized-event-archive",
      "signed-release-bundle",
    ] as const),
    retention: data.retention,
    session: Object.freeze({
      id: data.sessionId,
      state: data.sessionState,
      stateAt: data.sessionStateAt,
    }),
    signer: Object.freeze({
      algorithm: "Ed25519",
      keyId: signer.keyId,
      publicKeyFingerprintSha256: sha256(signer.publicKeySpkiDer),
    }),
    totalArtifactBytes,
    version: BACKUP_VERSION,
  });
  const signedMessage = manifestSignatureMessage(manifest);
  let signatureValue: Uint8Array;
  try {
    signatureValue = await signer.sign(Buffer.from(signedMessage));
  } catch {
    fail("SIGNER_FAILED", "Manifest signer failed");
  }
  const signatureBytes = copyBytes(signatureValue, "Manifest signature", 64);
  if (signatureBytes.length !== 64)
    fail("SIGNER_FAILED", "Manifest signer returned an invalid signature");
  const releaseKey = importEd25519PublicKey(signer.publicKeySpkiDer, "Manifest signer public key");
  if (!verify(null, signedMessage, releaseKey, signatureBytes)) {
    fail("SIGNATURE_INVALID", "Manifest signer returned an unverifiable signature");
  }
  const envelope: ManifestEnvelopeV1 = Object.freeze({
    manifest,
    signature: signatureBytes.toString("base64url"),
  });
  signatureBytes.fill(0);
  const envelopeBytes = Buffer.from(canonicalJson(envelope), "utf8");
  if (envelopeBytes.length > MAX_ENVELOPE_BYTES) {
    fail("ARCHIVE_BOUNDS", "Signed manifest envelope exceeds its bound");
  }
  const header = Buffer.allocUnsafe(ARCHIVE_MAGIC.length + 4);
  ARCHIVE_MAGIC.copy(header);
  header.writeUInt32BE(envelopeBytes.length, ARCHIVE_MAGIC.length);
  const bytes = Buffer.concat([
    header,
    envelopeBytes,
    ...ARTIFACT_DEFINITIONS.map(({ role }) => artifactBytes.get(role)!),
  ]);
  if (bytes.length > MAX_ARCHIVE_BYTES) fail("ARCHIVE_BOUNDS", "Backup archive exceeds its bound");
  const manifestSha256 = sha256(canonicalJson(manifest));
  const receipt = receiptFor(manifest, bytes, manifestSha256);
  return Object.freeze({ bytes, receipt });
}

export function verifyArchiveBytes(bytesValue: Uint8Array, trustValue: unknown): VerifiedArchive {
  const bytes = copyBytes(bytesValue, "Backup archive", MAX_ARCHIVE_BYTES);
  const trust = parseTrust(trustValue);
  if (
    bytes.length !== trust.receipt.archiveSizeBytes ||
    sha256(bytes) !== trust.receipt.archiveSha256
  ) {
    fail("TRUST_MISMATCH", "Archive does not match the retained receipt");
  }
  const { artifactBytes, envelope } = decodeArchive(bytes);
  const manifest = envelope.manifest;
  const manifestSha256 = sha256(canonicalJson(manifest));
  if (
    manifestSha256 !== trust.receipt.manifestSha256 ||
    manifest.backupId !== trust.receipt.backupId ||
    manifest.profile !== trust.receipt.profile ||
    manifest.session.id !== trust.receipt.sessionId ||
    manifest.release.releaseManifestSha256 !== trust.receipt.releaseManifestSha256 ||
    manifest.checkpoint.checkpointHash !== trust.receipt.checkpointHash ||
    manifest.checkpoint.journalSequence !== trust.receipt.checkpointJournalSequence ||
    manifest.signer.publicKeyFingerprintSha256 !== trust.receipt.signerFingerprintSha256
  ) {
    fail("TRUST_MISMATCH", "Manifest does not match the retained receipt");
  }
  const releaseKey = importEd25519PublicKey(trust.releasePublicKeySpkiDer, "Trusted release key");
  if (
    sha256(trust.releasePublicKeySpkiDer) !== manifest.signer.publicKeyFingerprintSha256 ||
    manifest.signer.keyId !== manifest.release.keyId ||
    manifest.signer.publicKeyFingerprintSha256 !== manifest.release.publicKeyFingerprintSha256 ||
    !verify(
      null,
      manifestSignatureMessage(manifest),
      releaseKey,
      decodeSignature(envelope.signature),
    )
  ) {
    fail("SIGNATURE_INVALID", "Manifest signature or release-key binding is invalid");
  }
  const decoded = decodeArtifactObjects(artifactBytes);
  const sanitized = validateDecodedArtifacts(decoded, {
    profile: manifest.profile,
    retention: manifest.retention,
    sessionId: manifest.session.id,
    sessionState: manifest.session.state,
    sessionStateAt: manifest.session.stateAt,
  });
  if (
    !Buffer.from(sanitized.releasePublicKey.spkiDerBase64url, "base64url").equals(
      trust.releasePublicKeySpkiDer,
    ) ||
    !Buffer.from(sanitized.checkpointPublicKey.spkiDerBase64url, "base64url").equals(
      trust.checkpointPublicKeySpkiDer,
    ) ||
    canonicalJson(manifest.eventStateEvidence) !==
      canonicalJson({
        eventCount: sanitized.eventState.eventCount,
        headHash: sanitized.eventState.headHash,
        headSequence: sanitized.eventState.headSequence,
        storeId: sanitized.eventState.storeId,
      }) ||
    canonicalJson(manifest.checkpoint) !==
      canonicalJson({
        checkpointHash: sanitized.checkpointHead.checkpointHash,
        journalSequence: sanitized.checkpointHead.journalSequence,
        keyId: sanitized.checkpointHead.keyId,
        publicKeyFingerprintSha256: sanitized.checkpointPublicKey.fingerprintSha256,
        storeHeadHash: sanitized.checkpointHead.storeHeadHash,
        storeHeadSequence: sanitized.checkpointHead.storeHeadSequence,
        storeId: sanitized.checkpointHead.storeId,
      }) ||
    canonicalJson(manifest.release) !==
      canonicalJson({
        commitSha: sanitized.release.commitSha,
        configSetSha256: sanitized.release.configSetSha256,
        keyId: sanitized.release.keyId,
        publicKeyFingerprintSha256: sanitized.release.publicKeyFingerprint,
        releaseManifestSha256: sanitized.release.releaseManifestSha256,
        releaseVersion: sanitized.release.releaseVersion,
      })
  ) {
    fail("INTEGRITY_MISMATCH", "Manifest/artifact bindings are invalid");
  }
  const report: StateEvidenceVerificationReportV1 = Object.freeze({
    archiveSha256: trust.receipt.archiveSha256,
    artifactCount: 7,
    backupId: manifest.backupId,
    checkpointHash: manifest.checkpoint.checkpointHash,
    componentScope: "observer-sanitized-state-evidence",
    manifestSha256,
    profile: manifest.profile,
    recoveryCompleteness: "evidence-only",
    releaseManifestSha256: manifest.release.releaseManifestSha256,
    reportType: BACKUP_REPORT_TYPE,
    requiredCompanionArtifacts: Object.freeze([
      "sanitized-event-archive",
      "signed-release-bundle",
    ] as const),
    sessionId: manifest.session.id,
    signerFingerprintSha256: trust.receipt.signerFingerprintSha256,
    status: "verified-evidence-component",
    totalArtifactBytes: manifest.totalArtifactBytes,
    version: BACKUP_VERSION,
  });
  return Object.freeze({ artifactBytes, envelope, report });
}

function encodeArtifactBytes(data: SanitizedArtifactSet): ReadonlyMap<ArtifactRole, Buffer> {
  return new Map<ArtifactRole, Buffer>([
    ["event-state-evidence", Buffer.from(canonicalJson(data.eventState), "utf8")],
    ["checkpoint-journal", Buffer.from(data.checkpointJournalBytes)],
    ["checkpoint-head", Buffer.from(canonicalJson(data.checkpointHead), "utf8")],
    ["public-keys", Buffer.from(canonicalJson(data.publicKeys), "utf8")],
    ["config-schema-hashes", Buffer.from(canonicalJson(data.configSchemas), "utf8")],
    ["recovery-evidence", Buffer.from(canonicalJson(data.recoveryEvidence), "utf8")],
    ["release-evidence", Buffer.from(canonicalJson(data.release), "utf8")],
  ]);
}

function decodeArchive(bytes: Buffer): {
  readonly artifactBytes: ReadonlyMap<ArtifactRole, Buffer>;
  readonly envelope: ManifestEnvelopeV1;
} {
  const minimum = ARCHIVE_MAGIC.length + 4;
  if (bytes.length < minimum || !bytes.subarray(0, ARCHIVE_MAGIC.length).equals(ARCHIVE_MAGIC)) {
    fail("ARCHIVE_FORMAT", "Backup archive magic is invalid");
  }
  const envelopeLength = bytes.readUInt32BE(ARCHIVE_MAGIC.length);
  if (
    envelopeLength === 0 ||
    envelopeLength > MAX_ENVELOPE_BYTES ||
    minimum + envelopeLength > bytes.length
  ) {
    fail("ARCHIVE_BOUNDS", "Signed manifest envelope is outside its bound");
  }
  const envelopeValue = parseCanonicalJson(
    bytes.subarray(minimum, minimum + envelopeLength),
    "Signed manifest envelope",
  );
  const envelopeRecord = exactObject(envelopeValue, ["manifest", "signature"], "Manifest envelope");
  const envelope: ManifestEnvelopeV1 = Object.freeze({
    manifest: parseManifest(envelopeRecord.manifest),
    signature: decodeSignature(envelopeRecord.signature).toString("base64url"),
  });
  let offset = minimum + envelopeLength;
  const artifactBytes = new Map<ArtifactRole, Buffer>();
  for (const descriptor of envelope.manifest.artifacts) {
    const end = offset + descriptor.sizeBytes;
    if (end > bytes.length) fail("ARCHIVE_FORMAT", "Backup archive is truncated");
    const artifact = Buffer.from(bytes.subarray(offset, end));
    if (sha256(artifact) !== descriptor.sha256) {
      fail("INTEGRITY_MISMATCH", "Artifact digest is invalid");
    }
    artifactBytes.set(descriptor.role, artifact);
    offset = end;
  }
  if (offset !== bytes.length) fail("ARCHIVE_FORMAT", "Backup archive has trailing bytes");
  return Object.freeze({ artifactBytes, envelope });
}

function parseManifest(value: unknown): BackupManifestV1 {
  const record = exactObject(
    value,
    [
      "artifactCount",
      "artifacts",
      "backupId",
      "backupType",
      "checkpoint",
      "componentScope",
      "createdAt",
      "eventStateEvidence",
      "profile",
      "recoveryCompleteness",
      "release",
      "requiredCompanionArtifacts",
      "retention",
      "session",
      "signer",
      "totalArtifactBytes",
      "version",
    ],
    "Backup manifest",
  );
  if (
    record.artifactCount !== 7 ||
    record.backupType !== BACKUP_TYPE ||
    record.componentScope !== "observer-sanitized-state-evidence" ||
    record.recoveryCompleteness !== "evidence-only" ||
    record.version !== BACKUP_VERSION
  ) {
    fail("ARCHIVE_FORMAT", "Backup manifest scope, count, or version is unsupported");
  }
  const artifactsValue = exactArray(record.artifacts, "Artifact descriptors");
  if (artifactsValue.length !== ARTIFACT_DEFINITIONS.length) {
    fail("ARCHIVE_FORMAT", "Artifact descriptor count is invalid");
  }
  let computedTotal = 0;
  const artifacts = artifactsValue.map((value, index) => {
    const definition = ARTIFACT_DEFINITIONS[index]!;
    const descriptor = exactObject(
      value,
      ["mediaType", "path", "role", "sha256", "sizeBytes"],
      "Artifact descriptor",
    );
    if (
      descriptor.mediaType !== definition.mediaType ||
      descriptor.path !== definition.path ||
      descriptor.role !== definition.role
    ) {
      fail("ARCHIVE_FORMAT", "Artifact role, path, media type, or order is invalid");
    }
    const sizeBytes = validateSafeInteger(descriptor.sizeBytes, "Artifact size", 1);
    if (sizeBytes > definition.maximumBytes) fail("ARCHIVE_BOUNDS", "Artifact exceeds its bound");
    computedTotal += sizeBytes;
    if (!Number.isSafeInteger(computedTotal) || computedTotal > MAX_TOTAL_ARTIFACT_BYTES) {
      fail("ARCHIVE_BOUNDS", "Artifact total exceeds its bound");
    }
    return Object.freeze({
      mediaType: definition.mediaType,
      path: definition.path,
      role: definition.role,
      sha256: validateHash(descriptor.sha256, "Artifact hash"),
      sizeBytes,
    });
  });
  const totalArtifactBytes = validateSafeInteger(
    record.totalArtifactBytes,
    "Total artifact bytes",
    1,
  );
  if (computedTotal !== totalArtifactBytes)
    fail("ARCHIVE_FORMAT", "Artifact byte total is invalid");
  const session = exactObject(record.session, ["id", "state", "stateAt"], "Manifest session");
  const companionArtifacts = exactArray(
    record.requiredCompanionArtifacts,
    "Required companion artifacts",
  );
  if (
    companionArtifacts.length !== 2 ||
    companionArtifacts[0] !== "sanitized-event-archive" ||
    companionArtifacts[1] !== "signed-release-bundle"
  ) {
    fail("ARCHIVE_FORMAT", "Required companion artifact set is invalid");
  }
  const eventState = exactObject(
    record.eventStateEvidence,
    ["eventCount", "headHash", "headSequence", "storeId"],
    "Manifest event state",
  );
  const checkpoint = exactObject(
    record.checkpoint,
    [
      "checkpointHash",
      "journalSequence",
      "keyId",
      "publicKeyFingerprintSha256",
      "storeHeadHash",
      "storeHeadSequence",
      "storeId",
    ],
    "Manifest checkpoint",
  );
  const release = exactObject(
    record.release,
    [
      "commitSha",
      "configSetSha256",
      "keyId",
      "publicKeyFingerprintSha256",
      "releaseManifestSha256",
      "releaseVersion",
    ],
    "Manifest release",
  );
  const signer = exactObject(
    record.signer,
    ["algorithm", "keyId", "publicKeyFingerprintSha256"],
    "Manifest signer",
  );
  if (signer.algorithm !== "Ed25519") fail("ARCHIVE_FORMAT", "Manifest algorithm is unsupported");
  const createdAt = validateTimestamp(record.createdAt, "Backup creation timestamp");
  const stateAt = validateTimestamp(session.stateAt, "Session state timestamp");
  if (createdAt < stateAt) fail("ARCHIVE_FORMAT", "Backup predates its session state");
  return Object.freeze({
    artifactCount: 7,
    artifacts: Object.freeze(artifacts),
    backupId: validateUuidV4(record.backupId, "Backup identifier"),
    backupType: BACKUP_TYPE,
    checkpoint: Object.freeze({
      checkpointHash: validateHash(checkpoint.checkpointHash, "Manifest checkpoint hash"),
      journalSequence: validateSafeInteger(
        checkpoint.journalSequence,
        "Manifest checkpoint sequence",
        1,
      ),
      keyId: validateIdentifier(checkpoint.keyId, "Manifest checkpoint key identifier"),
      publicKeyFingerprintSha256: validateHash(
        checkpoint.publicKeyFingerprintSha256,
        "Manifest checkpoint fingerprint",
      ),
      storeHeadHash: validateHash(checkpoint.storeHeadHash, "Manifest store-head hash"),
      storeHeadSequence: validateSafeInteger(
        checkpoint.storeHeadSequence,
        "Manifest store-head sequence",
        1,
      ),
      storeId: validateIdentifier(checkpoint.storeId, "Manifest store identifier"),
    }),
    componentScope: "observer-sanitized-state-evidence",
    createdAt,
    eventStateEvidence: Object.freeze({
      eventCount: validateSafeInteger(eventState.eventCount, "Manifest event count", 1),
      headHash: validateHash(eventState.headHash, "Manifest event head hash"),
      headSequence: validateSafeInteger(eventState.headSequence, "Manifest event sequence", 1),
      storeId: validateIdentifier(eventState.storeId, "Manifest event store identifier"),
    }),
    profile: validateEnum(record.profile, ["canary", "production-observer"] as const, "Profile"),
    recoveryCompleteness: "evidence-only",
    release: Object.freeze({
      commitSha:
        typeof release.commitSha === "string" && /^[0-9a-f]{40}$/.test(release.commitSha)
          ? release.commitSha
          : fail("INPUT_INVALID", "Manifest commit digest is invalid"),
      configSetSha256: validateHash(release.configSetSha256, "Manifest config-set hash"),
      keyId: validateIdentifier(release.keyId, "Manifest release key identifier"),
      publicKeyFingerprintSha256: validateHash(
        release.publicKeyFingerprintSha256,
        "Manifest release fingerprint",
      ),
      releaseManifestSha256: validateHash(release.releaseManifestSha256, "Manifest release hash"),
      releaseVersion: validateSemver(release.releaseVersion),
    }),
    requiredCompanionArtifacts: Object.freeze([
      "sanitized-event-archive",
      "signed-release-bundle",
    ] as const),
    retention: validateEnum(
      record.retention,
      ["month-end-365d", "session-30d"] as const,
      "Retention",
    ),
    session: Object.freeze({
      id: validateUuidV4(session.id, "Session identifier"),
      state: validateEnum(
        session.state,
        ["accepted", "acceptance-ready", "locally-verified"] as const,
        "Session state",
      ),
      stateAt,
    }),
    signer: Object.freeze({
      algorithm: "Ed25519",
      keyId: validateIdentifier(signer.keyId, "Manifest signer identifier"),
      publicKeyFingerprintSha256: validateHash(
        signer.publicKeyFingerprintSha256,
        "Manifest signer fingerprint",
      ),
    }),
    totalArtifactBytes,
    version: BACKUP_VERSION,
  });
}

function decodeArtifactObjects(artifactBytes: ReadonlyMap<ArtifactRole, Buffer>): ArtifactObjects {
  const get = (role: ArtifactRole): Buffer => {
    const bytes = artifactBytes.get(role);
    if (bytes === undefined) fail("ARCHIVE_FORMAT", "Required artifact is missing");
    return bytes;
  };
  const checkpointJournalBytes = get("checkpoint-journal");
  return Object.freeze({
    checkpointHead: parseCanonicalJson(get("checkpoint-head"), "Checkpoint-head artifact"),
    checkpointJournal: parseCanonicalJournal(checkpointJournalBytes),
    checkpointJournalBytes,
    configSchemas: parseCanonicalJson(get("config-schema-hashes"), "Config-schema artifact"),
    eventState: parseCanonicalJson(get("event-state-evidence"), "Event-state-evidence artifact"),
    publicKeys: parseCanonicalJson(get("public-keys"), "Public-key artifact"),
    recoveryEvidence: parseCanonicalJson(get("recovery-evidence"), "Recovery-evidence artifact"),
    release: parseCanonicalJson(get("release-evidence"), "Release-evidence artifact"),
  });
}

function manifestSignatureMessage(manifest: BackupManifestV1): Buffer {
  return Buffer.concat([SIGNATURE_DOMAIN, Buffer.from(canonicalJson(manifest), "utf8")]);
}

function receiptFor(
  manifest: BackupManifestV1,
  bytes: Buffer,
  manifestSha256: string,
): StateEvidenceReceiptV1 {
  return Object.freeze({
    archiveSha256: sha256(bytes),
    archiveSizeBytes: bytes.length,
    backupId: manifest.backupId,
    checkpointHash: manifest.checkpoint.checkpointHash,
    checkpointJournalSequence: manifest.checkpoint.journalSequence,
    componentScope: "observer-sanitized-state-evidence",
    manifestSha256,
    profile: manifest.profile,
    receiptType: BACKUP_RECEIPT_TYPE,
    recoveryCompleteness: "evidence-only",
    releaseManifestSha256: manifest.release.releaseManifestSha256,
    requiredCompanionArtifacts: Object.freeze([
      "sanitized-event-archive",
      "signed-release-bundle",
    ] as const),
    sessionId: manifest.session.id,
    signerFingerprintSha256: manifest.signer.publicKeyFingerprintSha256,
    version: BACKUP_VERSION,
  });
}

function parseTrust(value: unknown): {
  readonly checkpointPublicKeySpkiDer: Buffer;
  readonly receipt: StateEvidenceReceiptV1;
  readonly releasePublicKeySpkiDer: Buffer;
} {
  const record = exactObject(
    value,
    ["checkpointPublicKeySpkiDer", "receipt", "releasePublicKeySpkiDer"],
    "Backup trust",
  );
  const receiptRecord = exactObject(
    record.receipt,
    [
      "archiveSha256",
      "archiveSizeBytes",
      "backupId",
      "checkpointHash",
      "checkpointJournalSequence",
      "componentScope",
      "manifestSha256",
      "profile",
      "receiptType",
      "recoveryCompleteness",
      "releaseManifestSha256",
      "requiredCompanionArtifacts",
      "sessionId",
      "signerFingerprintSha256",
      "version",
    ],
    "Backup receipt",
  );
  if (
    receiptRecord.receiptType !== BACKUP_RECEIPT_TYPE ||
    receiptRecord.componentScope !== "observer-sanitized-state-evidence" ||
    receiptRecord.recoveryCompleteness !== "evidence-only" ||
    receiptRecord.version !== BACKUP_VERSION
  ) {
    fail("TRUST_MISMATCH", "Backup receipt scope or version is unsupported");
  }
  const receiptCompanions = exactArray(
    receiptRecord.requiredCompanionArtifacts,
    "Receipt companion artifacts",
  );
  if (
    receiptCompanions.length !== 2 ||
    receiptCompanions[0] !== "sanitized-event-archive" ||
    receiptCompanions[1] !== "signed-release-bundle"
  ) {
    fail("TRUST_MISMATCH", "Backup receipt companion set is invalid");
  }
  const checkpointPublicKeySpkiDer = copyBytes(
    record.checkpointPublicKeySpkiDer,
    "Trusted checkpoint key",
    512,
  );
  const releasePublicKeySpkiDer = copyBytes(
    record.releasePublicKeySpkiDer,
    "Trusted release key",
    512,
  );
  importEd25519PublicKey(checkpointPublicKeySpkiDer, "Trusted checkpoint key");
  importEd25519PublicKey(releasePublicKeySpkiDer, "Trusted release key");
  const receipt: StateEvidenceReceiptV1 = Object.freeze({
    archiveSha256: validateHash(receiptRecord.archiveSha256, "Receipt archive hash"),
    archiveSizeBytes: validateSafeInteger(
      receiptRecord.archiveSizeBytes,
      "Receipt archive size",
      1,
    ),
    backupId: validateUuidV4(receiptRecord.backupId, "Receipt backup identifier"),
    checkpointHash: validateHash(receiptRecord.checkpointHash, "Receipt checkpoint hash"),
    checkpointJournalSequence: validateSafeInteger(
      receiptRecord.checkpointJournalSequence,
      "Receipt checkpoint sequence",
      1,
    ),
    componentScope: "observer-sanitized-state-evidence",
    manifestSha256: validateHash(receiptRecord.manifestSha256, "Receipt manifest hash"),
    profile: validateEnum(
      receiptRecord.profile,
      ["canary", "production-observer"] as const,
      "Receipt profile",
    ),
    receiptType: BACKUP_RECEIPT_TYPE,
    recoveryCompleteness: "evidence-only",
    releaseManifestSha256: validateHash(
      receiptRecord.releaseManifestSha256,
      "Receipt release hash",
    ),
    requiredCompanionArtifacts: Object.freeze([
      "sanitized-event-archive",
      "signed-release-bundle",
    ] as const),
    sessionId: validateUuidV4(receiptRecord.sessionId, "Receipt session identifier"),
    signerFingerprintSha256: validateHash(
      receiptRecord.signerFingerprintSha256,
      "Receipt signer fingerprint",
    ),
    version: BACKUP_VERSION,
  });
  if (receipt.archiveSizeBytes > MAX_ARCHIVE_BYTES) {
    fail("ARCHIVE_BOUNDS", "Receipt archive size exceeds its bound");
  }
  return Object.freeze({ checkpointPublicKeySpkiDer, receipt, releasePublicKeySpkiDer });
}

export function normalizeSigner(value: unknown): NormalizedSigner {
  const record = exactObject(value, ["keyId", "publicKeySpkiDer", "sign"], "Manifest signer");
  if (typeof record.sign !== "function" || utilTypes.isProxy(record.sign)) {
    fail("INPUT_INVALID", "Manifest signer callback is invalid");
  }
  const publicKeySpkiDer = copyBytes(record.publicKeySpkiDer, "Manifest signer public key", 512);
  importEd25519PublicKey(publicKeySpkiDer, "Manifest signer public key");
  return Object.freeze({
    keyId: validateIdentifier(record.keyId, "Manifest signer identifier"),
    publicKeySpkiDer,
    sign: record.sign as NormalizedSigner["sign"],
  });
}

/** Internal format metadata for adversarial tests; not exported by the package entrypoint. */
export const internalArtifactDefinitions = ARTIFACT_DEFINITIONS;
