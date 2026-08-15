import { Buffer } from "node:buffer";
import { createHash, generateKeyPairSync, randomUUID, sign, type KeyObject } from "node:crypto";

import { ARCHIVE_MAGIC, type BackupManifestV1 } from "../src/archive.js";
import { canonicalJson, sha256 } from "../src/canonical.js";
import type {
  StateEvidenceReceiptV1,
  StateEvidenceSignerV1,
  StateEvidenceTrustV1,
  ConfigSchemaHashV1,
  SanitizedStateEvidenceSnapshotV1,
  SignedCheckpointV1,
} from "../src/types.js";

const CHECKPOINT_SIGNATURE_DOMAIN = Buffer.from("rsi-store-checkpoint-signature-v1\0", "utf8");
const CHECKPOINT_HASH_DOMAIN = Buffer.from("rsi-store-checkpoint-entry-v1\0", "utf8");
const MANIFEST_SIGNATURE_DOMAIN = Buffer.from("rsi-sanitized-state-evidence-manifest-v1\0", "utf8");

export interface Fixture {
  readonly checkpointPrivateKey: KeyObject;
  readonly checkpointPublicDer: Buffer;
  readonly releasePrivateKey: KeyObject;
  readonly releasePublicDer: Buffer;
  readonly signer: StateEvidenceSignerV1;
  readonly snapshot: SanitizedStateEvidenceSnapshotV1;
}

export function makeFixture(): Fixture {
  const checkpointKeys = generateKeyPairSync("ed25519");
  const releaseKeys = generateKeyPairSync("ed25519");
  const checkpointPublicDer = Buffer.from(
    checkpointKeys.publicKey.export({ format: "der", type: "spki" }),
  );
  const releasePublicDer = Buffer.from(
    releaseKeys.publicKey.export({ format: "der", type: "spki" }),
  );
  const eventHeadHash = digest("event-head");
  const checkpointJournal = makeCheckpointJournal(
    checkpointKeys.privateKey,
    "checkpoint-key-v1",
    "observer-store-v1",
    eventHeadHash,
  );
  const configSchemas: readonly ConfigSchemaHashV1[] = Object.freeze([
    Object.freeze({ name: "alert-outbox", schemaSha256: digest("schema-alerts"), version: 1 }),
    Object.freeze({ name: "backup-manifest", schemaSha256: digest("schema-backup"), version: 1 }),
    Object.freeze({ name: "capture-registry", schemaSha256: digest("schema-capture"), version: 1 }),
    Object.freeze({
      name: "checkpoint-journal",
      schemaSha256: digest("schema-checkpoint"),
      version: 1,
    }),
    Object.freeze({ name: "event-state", schemaSha256: digest("schema-event"), version: 1 }),
    Object.freeze({
      name: "external-anchor-outbox",
      schemaSha256: digest("schema-anchor"),
      version: 1,
    }),
    Object.freeze({ name: "observer-config", schemaSha256: digest("schema-config"), version: 1 }),
    Object.freeze({
      name: "operations-state",
      schemaSha256: digest("schema-operations"),
      version: 1,
    }),
    Object.freeze({
      name: "preflight-report",
      schemaSha256: digest("schema-preflight"),
      version: 1,
    }),
    Object.freeze({
      name: "public-projection",
      schemaSha256: digest("schema-public-projection"),
      version: 1,
    }),
    Object.freeze({
      name: "sanitized-event-archive",
      schemaSha256: digest("schema-event-archive"),
      version: 1,
    }),
    Object.freeze({
      name: "sanitized-state-evidence",
      schemaSha256: digest("schema-sanitized-backup"),
      version: 1,
    }),
    Object.freeze({
      name: "session-controller",
      schemaSha256: digest("schema-session-controller"),
      version: 1,
    }),
    Object.freeze({
      name: "session-lifecycle",
      schemaSha256: digest("schema-session"),
      version: 1,
    }),
    Object.freeze({
      name: "source-contracts",
      schemaSha256: digest("schema-source-contracts"),
      version: 1,
    }),
    Object.freeze({ name: "vault", schemaSha256: digest("schema-vault"), version: 1 }),
  ]);
  const configSetSha256 = sha256(
    canonicalJson({
      configSchemaHashesType: "rsi.backup.config-schema-hashes",
      schemas: configSchemas,
      version: 1,
    }),
  );
  const releaseManifestSha256 = digest("release-manifest");
  const snapshot: SanitizedStateEvidenceSnapshotV1 = Object.freeze({
    checkpointJournal,
    checkpointPublicKey: Object.freeze({
      fingerprintSha256: sha256(checkpointPublicDer),
      keyId: "checkpoint-key-v1",
      spkiDerBase64url: checkpointPublicDer.toString("base64url"),
    }),
    configSchemas,
    eventState: Object.freeze({
      eventCount: 2,
      eventStateType: "rsi.backup.event-state-evidence",
      headHash: eventHeadHash,
      headSequence: 2,
      storeId: "observer-store-v1",
      version: 1,
    }),
    profile: "production-observer",
    recoveryEvidence: Object.freeze([
      Object.freeze({
        completedAt: "2026-08-14T12:02:00.000Z",
        evidenceSha256: digest("rb-01-evidence"),
        outcome: "passed",
        releaseManifestSha256,
        runbookId: "RB-01",
      }),
      Object.freeze({
        completedAt: "2026-08-14T12:03:00.000Z",
        evidenceSha256: digest("rb-19-evidence"),
        outcome: "passed",
        releaseManifestSha256,
        runbookId: "RB-19",
      }),
    ]),
    release: Object.freeze({
      commitSha: "a".repeat(40),
      configSetSha256,
      keyId: "release-key-v1",
      publicKeyFingerprint: sha256(releasePublicDer),
      releaseEvidenceType: "rsi.backup.release-evidence",
      releaseManifestSha256,
      releaseVersion: "1.2.3",
      sbomSha256: digest("sbom"),
      sourceTreeSha256: digest("source-tree"),
      status: "verified",
      version: 1,
    }),
    releasePublicKey: Object.freeze({
      fingerprintSha256: sha256(releasePublicDer),
      keyId: "release-key-v1",
      spkiDerBase64url: releasePublicDer.toString("base64url"),
    }),
    retention: "session-30d",
    sessionId: randomUUID(),
    sessionState: "acceptance-ready",
    sessionStateAt: "2026-08-14T12:05:00.000Z",
    trustedCheckpointHead: Object.freeze({
      checkpointHash: checkpointJournal[1]!.checkpointHash,
      journalSequence: 2,
    }),
  });
  const signer: StateEvidenceSignerV1 = Object.freeze({
    keyId: "release-key-v1",
    publicKeySpkiDer: releasePublicDer,
    sign: (message: Uint8Array) => sign(null, message, releaseKeys.privateKey),
  });
  return Object.freeze({
    checkpointPrivateKey: checkpointKeys.privateKey,
    checkpointPublicDer,
    releasePrivateKey: releaseKeys.privateKey,
    releasePublicDer,
    signer,
    snapshot,
  });
}

function makeCheckpointJournal(
  privateKey: KeyObject,
  keyId: string,
  storeId: string,
  finalHeadHash: string,
): readonly SignedCheckpointV1[] {
  const first = signCheckpoint(
    {
      checkpointType: "rsi.store.head",
      createdAt: "2026-08-14T12:00:00.000Z",
      journalSequence: 1,
      keyId,
      previousCheckpointHash: "0".repeat(64),
      storeHeadHash: digest("event-one"),
      storeHeadSequence: 1,
      storeId,
      version: 1,
    },
    privateKey,
  );
  const second = signCheckpoint(
    {
      checkpointType: "rsi.store.head",
      createdAt: "2026-08-14T12:01:00.000Z",
      journalSequence: 2,
      keyId,
      previousCheckpointHash: first.checkpointHash,
      storeHeadHash: finalHeadHash,
      storeHeadSequence: 2,
      storeId,
      version: 1,
    },
    privateKey,
  );
  return Object.freeze([first, second]);
}

function signCheckpoint(
  payload: SignedCheckpointV1["payload"],
  privateKey: KeyObject,
): SignedCheckpointV1 {
  const signature = sign(
    null,
    Buffer.concat([CHECKPOINT_SIGNATURE_DOMAIN, Buffer.from(canonicalJson(payload), "utf8")]),
    privateKey,
  ).toString("base64url");
  const checkpointHash = createHash("sha256")
    .update(CHECKPOINT_HASH_DOMAIN)
    .update(canonicalJson({ payload, signature }), "utf8")
    .digest("hex");
  return Object.freeze({ checkpointHash, payload: Object.freeze(payload), signature });
}

export function trustFor(fixture: Fixture, receipt: StateEvidenceReceiptV1): StateEvidenceTrustV1 {
  return Object.freeze({
    checkpointPublicKeySpkiDer: fixture.checkpointPublicDer,
    receipt,
    releasePublicKeySpkiDer: fixture.releasePublicDer,
  });
}

export interface RawArchive {
  readonly artifacts: Buffer[];
  readonly manifest: BackupManifestV1 & Record<string, unknown>;
  signature: string;
}

export function unpackArchive(bytes: Buffer): RawArchive {
  const envelopeLength = bytes.readUInt32BE(ARCHIVE_MAGIC.length);
  const envelopeStart = ARCHIVE_MAGIC.length + 4;
  const envelope = JSON.parse(
    bytes.subarray(envelopeStart, envelopeStart + envelopeLength).toString("utf8"),
  ) as { manifest: BackupManifestV1 & Record<string, unknown>; signature: string };
  let offset = envelopeStart + envelopeLength;
  const artifacts = envelope.manifest.artifacts.map((descriptor) => {
    const artifact = Buffer.from(bytes.subarray(offset, offset + descriptor.sizeBytes));
    offset += descriptor.sizeBytes;
    return artifact;
  });
  return { artifacts, manifest: envelope.manifest, signature: envelope.signature };
}

export function replaceArtifact(raw: RawArchive, role: string, bytes: Buffer): void {
  const index = raw.manifest.artifacts.findIndex((descriptor) => descriptor.role === role);
  if (index < 0) throw new Error("fixture role not found");
  raw.artifacts[index] = bytes;
  const descriptor = raw.manifest.artifacts[index]! as unknown as Record<string, unknown>;
  descriptor.sha256 = sha256(bytes);
  descriptor.sizeBytes = bytes.length;
  (raw.manifest as unknown as Record<string, unknown>).totalArtifactBytes =
    raw.manifest.artifacts.reduce((sum, entry) => sum + entry.sizeBytes, 0);
}

export function repackArchive(
  raw: RawArchive,
  privateKey: KeyObject,
  priorReceipt: StateEvidenceReceiptV1,
  signManifest = true,
): { readonly bytes: Buffer; readonly receipt: StateEvidenceReceiptV1 } {
  const signature = signManifest
    ? sign(
        null,
        Buffer.concat([
          MANIFEST_SIGNATURE_DOMAIN,
          Buffer.from(canonicalJson(raw.manifest), "utf8"),
        ]),
        privateKey,
      ).toString("base64url")
    : raw.signature;
  const envelopeBytes = Buffer.from(canonicalJson({ manifest: raw.manifest, signature }), "utf8");
  const header = Buffer.alloc(ARCHIVE_MAGIC.length + 4);
  ARCHIVE_MAGIC.copy(header);
  header.writeUInt32BE(envelopeBytes.length, ARCHIVE_MAGIC.length);
  const bytes = Buffer.concat([header, envelopeBytes, ...raw.artifacts]);
  const receipt = Object.freeze({
    ...priorReceipt,
    archiveSha256: sha256(bytes),
    archiveSizeBytes: bytes.length,
    backupId: raw.manifest.backupId,
    checkpointHash: raw.manifest.checkpoint.checkpointHash,
    checkpointJournalSequence: raw.manifest.checkpoint.journalSequence,
    manifestSha256: sha256(canonicalJson(raw.manifest)),
    profile: raw.manifest.profile,
    releaseManifestSha256: raw.manifest.release.releaseManifestSha256,
    sessionId: raw.manifest.session.id,
    signerFingerprintSha256: raw.manifest.signer.publicKeyFingerprintSha256,
  });
  return { bytes, receipt };
}

export function digest(label: string): string {
  return createHash("sha256").update(label, "utf8").digest("hex");
}
