import { Buffer } from "node:buffer";
import { randomUUID, verify } from "node:crypto";
import { types as utilTypes } from "node:util";

import {
  MAX_ARTIFACT_COUNT,
  MAX_TOTAL_ARTIFACT_BYTES,
  normalizeReleaseArtifacts,
  parseArtifactDescriptors,
  validateDecodedArtifactSet,
  validateReleaseArtifactSemantics,
  type NormalizedArtifactSet,
  type NormalizedReleaseArtifact,
} from "./artifacts.js";
import {
  canonicalJson,
  copyInputBytes,
  decodeSignature,
  exactArray,
  exactObject,
  importEd25519PublicKey,
  parseCanonicalJson,
  sha256,
  validateGitHash,
  validateHash,
  validateIdentifier,
  validateSafeInteger,
  validateSemver,
  validateTimestamp,
  validateUuidV4,
} from "./canonical.js";
import { fail } from "./errors.js";
import {
  RELEASE_BUNDLE_RECEIPT_TYPE,
  RELEASE_BUNDLE_REPORT_TYPE,
  RELEASE_BUNDLE_TYPE,
  RELEASE_BUNDLE_VERSION,
  type ReleaseArtifactBindingsV1,
  type ReleaseArtifactDescriptorV1,
  type ReleaseBundleReceiptV1,
  type ReleaseBundleVerificationReportV1,
  type ReleaseIdentityV1,
} from "./types.js";

export const ARCHIVE_MAGIC = Buffer.from("RSIRELEASE1", "ascii");
export const MAX_ENVELOPE_BYTES = 512 * 1024;
export const MAX_ARCHIVE_BYTES = 34 * 1024 * 1024;
const SIGNATURE_DOMAIN = Buffer.from("rsi-signed-release-bundle-manifest-v1\0", "utf8");

export interface ReleaseBundleManifestV1 {
  readonly artifactCount: number;
  readonly artifacts: readonly ReleaseArtifactDescriptorV1[];
  readonly bundleId: string;
  readonly bundleType: typeof RELEASE_BUNDLE_TYPE;
  readonly companionType: "signed-release-bundle";
  readonly componentScope: "observer-sanitized-release";
  readonly createdAt: string;
  readonly recoveryCompleteness: "release-component";
  readonly release: Omit<ReleaseIdentityV1, "createdAt">;
  readonly requiredCompanionArtifacts: readonly [
    "sanitized-state-evidence",
    "sanitized-event-archive",
  ];
  readonly restorability: "closed-source-config-docs";
  readonly signer: {
    readonly algorithm: "Ed25519";
    readonly keyId: string;
    readonly publicKeyFingerprintSha256: string;
  };
  readonly totalArtifactBytes: number;
  readonly version: typeof RELEASE_BUNDLE_VERSION;
}

export interface ManifestEnvelopeV1 {
  readonly manifest: ReleaseBundleManifestV1;
  readonly signature: string;
}

export interface NormalizedSigner {
  readonly keyId: string;
  readonly publicKeySpkiDer: Buffer;
  readonly sign: (message: Uint8Array) => Promise<Uint8Array> | Uint8Array;
}

export interface EncodedReleaseArchive {
  readonly bytes: Buffer;
  readonly receipt: ReleaseBundleReceiptV1;
}

export interface VerifiedReleaseArchive {
  readonly artifactBytes: ReadonlyMap<string, Buffer>;
  readonly envelope: ManifestEnvelopeV1;
  readonly report: ReleaseBundleVerificationReportV1;
}

export function normalizeReleaseIdentity(
  value: unknown,
  artifactSet: NormalizedArtifactSet,
): ReleaseIdentityV1 {
  const record = exactObject(
    value,
    [
      "artifactSetSha256",
      "commitSha",
      "configSetSha256",
      "createdAt",
      "gitTreeSha",
      "lockfileSha256",
      "nodeVersion",
      "pnpmVersion",
      "predecessorManifestSha256",
      "recoverySetSha256",
      "releaseVersion",
      "runbookSetSha256",
      "sbomSha256",
      "sourceTreeSha256",
      "testSummarySha256",
    ],
    "Release identity",
  );
  const nodeVersion = validateSemver(record.nodeVersion, "Node version");
  const pnpmVersion = validateSemver(record.pnpmVersion, "pnpm version");
  if (!nodeVersion.startsWith("24.") || !pnpmVersion.startsWith("11.")) {
    fail("POLICY_VIOLATION", "Release runtime must pin Node 24 and pnpm 11");
  }
  const predecessorManifestSha256 =
    record.predecessorManifestSha256 === null
      ? null
      : validateHash(record.predecessorManifestSha256, "Predecessor manifest hash");
  const release: ReleaseIdentityV1 = Object.freeze({
    artifactSetSha256: validateHash(record.artifactSetSha256, "Artifact-set hash"),
    commitSha: validateGitHash(record.commitSha, "Release commit"),
    configSetSha256: validateHash(record.configSetSha256, "Configuration-set hash"),
    createdAt: validateTimestamp(record.createdAt, "Release creation time"),
    gitTreeSha: validateGitHash(record.gitTreeSha, "Release Git tree"),
    lockfileSha256: validateHash(record.lockfileSha256, "Lockfile hash"),
    nodeVersion,
    pnpmVersion,
    predecessorManifestSha256,
    recoverySetSha256: validateHash(record.recoverySetSha256, "Recovery-set hash"),
    releaseVersion: validateSemver(record.releaseVersion, "Release version"),
    runbookSetSha256: validateHash(record.runbookSetSha256, "Runbook-set hash"),
    sbomSha256: validateHash(record.sbomSha256, "SBOM hash"),
    sourceTreeSha256: validateHash(record.sourceTreeSha256, "Source-tree hash"),
    testSummarySha256: validateHash(record.testSummarySha256, "Test-summary hash"),
  });
  if (canonicalJson(bindingsFromRelease(release)) !== canonicalJson(artifactSet.bindings)) {
    fail("INTEGRITY_MISMATCH", "Release identity does not match the supplied artifact set");
  }
  validateReleaseArtifactSemantics(artifactSet.artifacts, release);
  return release;
}

export function normalizeSigner(value: unknown): NormalizedSigner {
  const record = exactObject(value, ["keyId", "publicKeySpkiDer", "sign"], "Release signer");
  if (typeof record.sign !== "function" || utilTypes.isProxy(record.sign)) {
    fail("INPUT_INVALID", "Release signer callback is invalid");
  }
  const publicKeySpkiDer = copyInputBytes(record.publicKeySpkiDer, "Release public key", 512);
  importEd25519PublicKey(publicKeySpkiDer, "Release public key");
  return Object.freeze({
    keyId: validateIdentifier(record.keyId, "Release signer identifier"),
    publicKeySpkiDer,
    sign: record.sign as NormalizedSigner["sign"],
  });
}

export async function encodeSignedReleaseArchive(
  artifactSet: NormalizedArtifactSet,
  release: ReleaseIdentityV1,
  signer: NormalizedSigner,
): Promise<EncodedReleaseArchive> {
  const manifest: ReleaseBundleManifestV1 = Object.freeze({
    artifactCount: artifactSet.artifacts.length,
    artifacts: Object.freeze(artifactSet.artifacts.map(({ descriptor }) => descriptor)),
    bundleId: randomUUID(),
    bundleType: RELEASE_BUNDLE_TYPE,
    companionType: "signed-release-bundle",
    componentScope: "observer-sanitized-release",
    createdAt: release.createdAt,
    recoveryCompleteness: "release-component",
    release: Object.freeze({
      ...bindingsFromRelease(release),
      commitSha: release.commitSha,
      gitTreeSha: release.gitTreeSha,
      nodeVersion: release.nodeVersion,
      pnpmVersion: release.pnpmVersion,
      predecessorManifestSha256: release.predecessorManifestSha256,
      releaseVersion: release.releaseVersion,
    }),
    requiredCompanionArtifacts: Object.freeze([
      "sanitized-state-evidence",
      "sanitized-event-archive",
    ] as const),
    restorability: "closed-source-config-docs",
    signer: Object.freeze({
      algorithm: "Ed25519",
      keyId: signer.keyId,
      publicKeyFingerprintSha256: sha256(signer.publicKeySpkiDer),
    }),
    totalArtifactBytes: artifactSet.totalArtifactBytes,
    version: RELEASE_BUNDLE_VERSION,
  });
  const signedMessage = manifestSignatureMessage(manifest);
  let returned: Uint8Array;
  try {
    returned = await signer.sign(new Uint8Array(signedMessage));
  } catch {
    fail("SIGNER_FAILED", "Release signer failed");
  }
  const signature = copyInputBytes(returned, "Release signature", 64);
  if (signature.length !== 64)
    fail("SIGNER_FAILED", "Release signer returned an invalid signature");
  const releaseKey = importEd25519PublicKey(signer.publicKeySpkiDer, "Release public key");
  if (!verify(null, manifestSignatureMessage(manifest), releaseKey, signature)) {
    fail("SIGNATURE_INVALID", "Release signer returned an unverifiable signature");
  }
  const envelope: ManifestEnvelopeV1 = Object.freeze({
    manifest,
    signature: signature.toString("base64url"),
  });
  signature.fill(0);
  const envelopeBytes = Buffer.from(canonicalJson(envelope), "utf8");
  if (envelopeBytes.length > MAX_ENVELOPE_BYTES) {
    fail("ARCHIVE_BOUNDS", "Signed release manifest exceeds its bound");
  }
  const header = Buffer.alloc(ARCHIVE_MAGIC.length + 4);
  ARCHIVE_MAGIC.copy(header);
  header.writeUInt32BE(envelopeBytes.length, ARCHIVE_MAGIC.length);
  const bytes = Buffer.concat([
    header,
    envelopeBytes,
    ...artifactSet.artifacts.map((artifact) => artifact.bytes),
  ]);
  if (bytes.length > MAX_ARCHIVE_BYTES) fail("ARCHIVE_BOUNDS", "Release archive exceeds its bound");
  const manifestSha256 = sha256(canonicalJson(manifest));
  return Object.freeze({
    bytes,
    receipt: receiptFor(manifest, bytes, manifestSha256),
  });
}

export function verifyReleaseArchiveBytes(
  bytesValue: Uint8Array,
  trustValue: unknown,
): VerifiedReleaseArchive {
  const bytes = copyInternalArchiveBytes(bytesValue);
  const trust = parseTrust(trustValue);
  if (
    bytes.length !== trust.receipt.archiveSizeBytes ||
    sha256(bytes) !== trust.receipt.archiveSha256
  ) {
    fail("TRUST_MISMATCH", "Release archive does not match the retained receipt");
  }
  const { artifactBytes, envelope } = decodeArchive(bytes);
  const manifest = envelope.manifest;
  const manifestSha256 = sha256(canonicalJson(manifest));
  assertReceiptMatchesManifest(trust.receipt, manifest, manifestSha256);
  const releaseKey = importEd25519PublicKey(trust.releasePublicKeySpkiDer, "Trusted release key");
  if (
    sha256(trust.releasePublicKeySpkiDer) !== manifest.signer.publicKeyFingerprintSha256 ||
    trust.receipt.signerKeyId !== manifest.signer.keyId ||
    !verify(
      null,
      manifestSignatureMessage(manifest),
      releaseKey,
      decodeSignature(envelope.signature),
    )
  ) {
    fail("SIGNATURE_INVALID", "Release signature or trusted-key binding is invalid");
  }
  const normalized = validateDecodedArtifactSet(manifest.artifacts, artifactBytes);
  const releaseIdentity: ReleaseIdentityV1 = Object.freeze({
    ...manifest.release,
    createdAt: manifest.createdAt,
  });
  if (
    canonicalJson(normalized.bindings) !== canonicalJson(bindingsFromRelease(releaseIdentity)) ||
    normalized.totalArtifactBytes !== manifest.totalArtifactBytes
  ) {
    fail("INTEGRITY_MISMATCH", "Release manifest artifact bindings are invalid");
  }
  validateReleaseArtifactSemantics(normalized.artifacts, releaseIdentity);
  const report: ReleaseBundleVerificationReportV1 = Object.freeze({
    ...normalized.bindings,
    archiveSha256: trust.receipt.archiveSha256,
    artifactCount: manifest.artifactCount,
    bundleId: manifest.bundleId,
    commitSha: manifest.release.commitSha,
    companionType: "signed-release-bundle",
    gitTreeSha: manifest.release.gitTreeSha,
    manifestSha256,
    recoveryCompleteness: "release-component",
    releaseVersion: manifest.release.releaseVersion,
    reportType: RELEASE_BUNDLE_REPORT_TYPE,
    requiredCompanionArtifacts: Object.freeze([
      "sanitized-state-evidence",
      "sanitized-event-archive",
    ] as const),
    signerFingerprintSha256: trust.receipt.signerFingerprintSha256,
    status: "verified-restorable-release-component",
    totalArtifactBytes: manifest.totalArtifactBytes,
    version: RELEASE_BUNDLE_VERSION,
  });
  return Object.freeze({ artifactBytes, envelope, report });
}

function copyInternalArchiveBytes(value: Uint8Array): Buffer {
  if (
    !(value instanceof Uint8Array) ||
    value.byteLength === 0 ||
    value.byteLength > MAX_ARCHIVE_BYTES
  ) {
    fail("ARCHIVE_BOUNDS", "Release archive bytes are outside their bound");
  }
  return Buffer.from(value);
}

function decodeArchive(bytes: Buffer): {
  readonly artifactBytes: ReadonlyMap<string, Buffer>;
  readonly envelope: ManifestEnvelopeV1;
} {
  const minimum = ARCHIVE_MAGIC.length + 4;
  if (bytes.length < minimum || !bytes.subarray(0, ARCHIVE_MAGIC.length).equals(ARCHIVE_MAGIC)) {
    fail("ARCHIVE_FORMAT", "Release archive magic is invalid");
  }
  const envelopeLength = bytes.readUInt32BE(ARCHIVE_MAGIC.length);
  if (
    envelopeLength === 0 ||
    envelopeLength > MAX_ENVELOPE_BYTES ||
    minimum + envelopeLength > bytes.length
  ) {
    fail("ARCHIVE_BOUNDS", "Signed release manifest is outside its bound");
  }
  const envelopeValue = parseCanonicalJson(
    bytes.subarray(minimum, minimum + envelopeLength),
    "Signed release manifest",
  );
  const envelopeRecord = exactObject(envelopeValue, ["manifest", "signature"], "Release envelope");
  const envelope: ManifestEnvelopeV1 = Object.freeze({
    manifest: parseManifest(envelopeRecord.manifest),
    signature: decodeSignature(envelopeRecord.signature).toString("base64url"),
  });
  let offset = minimum + envelopeLength;
  const artifactBytes = new Map<string, Buffer>();
  for (const descriptor of envelope.manifest.artifacts) {
    const end = offset + descriptor.sizeBytes;
    if (end > bytes.length) fail("ARCHIVE_FORMAT", "Release archive is truncated");
    const artifact = Buffer.from(bytes.subarray(offset, end));
    if (sha256(artifact) !== descriptor.sha256) {
      fail("INTEGRITY_MISMATCH", "Release artifact digest is invalid");
    }
    artifactBytes.set(descriptor.path, artifact);
    offset = end;
  }
  if (offset !== bytes.length) fail("ARCHIVE_FORMAT", "Release archive has trailing bytes");
  return Object.freeze({ artifactBytes, envelope });
}

function parseManifest(value: unknown): ReleaseBundleManifestV1 {
  const record = exactObject(
    value,
    [
      "artifactCount",
      "artifacts",
      "bundleId",
      "bundleType",
      "companionType",
      "componentScope",
      "createdAt",
      "recoveryCompleteness",
      "release",
      "requiredCompanionArtifacts",
      "restorability",
      "signer",
      "totalArtifactBytes",
      "version",
    ],
    "Release manifest",
  );
  if (
    record.bundleType !== RELEASE_BUNDLE_TYPE ||
    record.companionType !== "signed-release-bundle" ||
    record.componentScope !== "observer-sanitized-release" ||
    record.recoveryCompleteness !== "release-component" ||
    record.restorability !== "closed-source-config-docs" ||
    record.version !== RELEASE_BUNDLE_VERSION
  ) {
    fail("ARCHIVE_FORMAT", "Release manifest scope or semantics are unsupported");
  }
  const artifacts = parseArtifactDescriptors(record.artifacts);
  const artifactCount = validateSafeInteger(
    record.artifactCount,
    "Release artifact count",
    1,
    MAX_ARTIFACT_COUNT,
  );
  if (artifactCount !== artifacts.length)
    fail("ARCHIVE_FORMAT", "Release artifact count is invalid");
  const totalArtifactBytes = validateSafeInteger(
    record.totalArtifactBytes,
    "Release artifact byte total",
    1,
    MAX_TOTAL_ARTIFACT_BYTES,
  );
  if (artifacts.reduce((sum, descriptor) => sum + descriptor.sizeBytes, 0) !== totalArtifactBytes) {
    fail("ARCHIVE_FORMAT", "Release artifact byte total is invalid");
  }
  const release = parseManifestRelease(record.release);
  const signer = exactObject(
    record.signer,
    ["algorithm", "keyId", "publicKeyFingerprintSha256"],
    "Release manifest signer",
  );
  if (signer.algorithm !== "Ed25519")
    fail("ARCHIVE_FORMAT", "Release signature algorithm is unsupported");
  assertCompanions(record.requiredCompanionArtifacts);
  return Object.freeze({
    artifactCount,
    artifacts,
    bundleId: validateUuidV4(record.bundleId, "Release bundle identifier"),
    bundleType: RELEASE_BUNDLE_TYPE,
    companionType: "signed-release-bundle",
    componentScope: "observer-sanitized-release",
    createdAt: validateTimestamp(record.createdAt, "Release creation time"),
    recoveryCompleteness: "release-component",
    release,
    requiredCompanionArtifacts: Object.freeze([
      "sanitized-state-evidence",
      "sanitized-event-archive",
    ] as const),
    restorability: "closed-source-config-docs",
    signer: Object.freeze({
      algorithm: "Ed25519",
      keyId: validateIdentifier(signer.keyId, "Release signer identifier"),
      publicKeyFingerprintSha256: validateHash(
        signer.publicKeyFingerprintSha256,
        "Release signer fingerprint",
      ),
    }),
    totalArtifactBytes,
    version: RELEASE_BUNDLE_VERSION,
  });
}

function parseManifestRelease(value: unknown): Omit<ReleaseIdentityV1, "createdAt"> {
  const record = exactObject(
    value,
    [
      "artifactSetSha256",
      "commitSha",
      "configSetSha256",
      "gitTreeSha",
      "lockfileSha256",
      "nodeVersion",
      "pnpmVersion",
      "predecessorManifestSha256",
      "recoverySetSha256",
      "releaseVersion",
      "runbookSetSha256",
      "sbomSha256",
      "sourceTreeSha256",
      "testSummarySha256",
    ],
    "Manifest release identity",
  );
  const nodeVersion = validateSemver(record.nodeVersion, "Manifest Node version");
  const pnpmVersion = validateSemver(record.pnpmVersion, "Manifest pnpm version");
  if (!nodeVersion.startsWith("24.") || !pnpmVersion.startsWith("11.")) {
    fail("ARCHIVE_FORMAT", "Manifest runtime policy is unsupported");
  }
  return Object.freeze({
    artifactSetSha256: validateHash(record.artifactSetSha256, "Manifest artifact-set hash"),
    commitSha: validateGitHash(record.commitSha, "Manifest release commit"),
    configSetSha256: validateHash(record.configSetSha256, "Manifest configuration-set hash"),
    gitTreeSha: validateGitHash(record.gitTreeSha, "Manifest Git tree"),
    lockfileSha256: validateHash(record.lockfileSha256, "Manifest lockfile hash"),
    nodeVersion,
    pnpmVersion,
    predecessorManifestSha256:
      record.predecessorManifestSha256 === null
        ? null
        : validateHash(record.predecessorManifestSha256, "Manifest predecessor hash"),
    recoverySetSha256: validateHash(record.recoverySetSha256, "Manifest recovery-set hash"),
    releaseVersion: validateSemver(record.releaseVersion, "Manifest release version"),
    runbookSetSha256: validateHash(record.runbookSetSha256, "Manifest runbook-set hash"),
    sbomSha256: validateHash(record.sbomSha256, "Manifest SBOM hash"),
    sourceTreeSha256: validateHash(record.sourceTreeSha256, "Manifest source-tree hash"),
    testSummarySha256: validateHash(record.testSummarySha256, "Manifest test-summary hash"),
  });
}

function parseTrust(value: unknown): {
  readonly receipt: ReleaseBundleReceiptV1;
  readonly releasePublicKeySpkiDer: Buffer;
} {
  const record = exactObject(value, ["receipt", "releasePublicKeySpkiDer"], "Release trust");
  const releasePublicKeySpkiDer = copyInputBytes(
    record.releasePublicKeySpkiDer,
    "Trusted release public key",
    512,
  );
  importEd25519PublicKey(releasePublicKeySpkiDer, "Trusted release public key");
  return Object.freeze({ receipt: parseReceipt(record.receipt), releasePublicKeySpkiDer });
}

function parseReceipt(value: unknown): ReleaseBundleReceiptV1 {
  const record = exactObject(
    value,
    [
      "archiveSha256",
      "archiveSizeBytes",
      "artifactSetSha256",
      "bundleId",
      "commitSha",
      "companionType",
      "configSetSha256",
      "gitTreeSha",
      "lockfileSha256",
      "manifestSha256",
      "predecessorManifestSha256",
      "receiptType",
      "recoveryCompleteness",
      "recoverySetSha256",
      "releaseVersion",
      "requiredCompanionArtifacts",
      "runbookSetSha256",
      "sbomSha256",
      "signerFingerprintSha256",
      "signerKeyId",
      "sourceTreeSha256",
      "testSummarySha256",
      "version",
    ],
    "Retained release receipt",
  );
  if (
    record.receiptType !== RELEASE_BUNDLE_RECEIPT_TYPE ||
    record.companionType !== "signed-release-bundle" ||
    record.recoveryCompleteness !== "release-component" ||
    record.version !== RELEASE_BUNDLE_VERSION
  ) {
    fail("TRUST_MISMATCH", "Retained release receipt scope is unsupported");
  }
  assertCompanions(record.requiredCompanionArtifacts);
  const archiveSizeBytes = validateSafeInteger(
    record.archiveSizeBytes,
    "Receipt archive size",
    1,
    MAX_ARCHIVE_BYTES,
  );
  return Object.freeze({
    archiveSha256: validateHash(record.archiveSha256, "Receipt archive hash"),
    archiveSizeBytes,
    artifactSetSha256: validateHash(record.artifactSetSha256, "Receipt artifact-set hash"),
    bundleId: validateUuidV4(record.bundleId, "Receipt bundle identifier"),
    commitSha: validateGitHash(record.commitSha, "Receipt release commit"),
    companionType: "signed-release-bundle",
    configSetSha256: validateHash(record.configSetSha256, "Receipt configuration-set hash"),
    gitTreeSha: validateGitHash(record.gitTreeSha, "Receipt Git tree"),
    lockfileSha256: validateHash(record.lockfileSha256, "Receipt lockfile hash"),
    manifestSha256: validateHash(record.manifestSha256, "Receipt manifest hash"),
    predecessorManifestSha256:
      record.predecessorManifestSha256 === null
        ? null
        : validateHash(record.predecessorManifestSha256, "Receipt predecessor hash"),
    receiptType: RELEASE_BUNDLE_RECEIPT_TYPE,
    recoveryCompleteness: "release-component",
    recoverySetSha256: validateHash(record.recoverySetSha256, "Receipt recovery-set hash"),
    releaseVersion: validateSemver(record.releaseVersion, "Receipt release version"),
    requiredCompanionArtifacts: Object.freeze([
      "sanitized-state-evidence",
      "sanitized-event-archive",
    ] as const),
    runbookSetSha256: validateHash(record.runbookSetSha256, "Receipt runbook-set hash"),
    sbomSha256: validateHash(record.sbomSha256, "Receipt SBOM hash"),
    signerFingerprintSha256: validateHash(
      record.signerFingerprintSha256,
      "Receipt signer fingerprint",
    ),
    signerKeyId: validateIdentifier(record.signerKeyId, "Receipt signer identifier"),
    sourceTreeSha256: validateHash(record.sourceTreeSha256, "Receipt source-tree hash"),
    testSummarySha256: validateHash(record.testSummarySha256, "Receipt test-summary hash"),
    version: RELEASE_BUNDLE_VERSION,
  });
}

function receiptFor(
  manifest: ReleaseBundleManifestV1,
  bytes: Buffer,
  manifestSha256: string,
): ReleaseBundleReceiptV1 {
  return Object.freeze({
    ...bindingsFromRelease(manifest.release),
    archiveSha256: sha256(bytes),
    archiveSizeBytes: bytes.length,
    bundleId: manifest.bundleId,
    commitSha: manifest.release.commitSha,
    companionType: "signed-release-bundle",
    gitTreeSha: manifest.release.gitTreeSha,
    manifestSha256,
    predecessorManifestSha256: manifest.release.predecessorManifestSha256,
    receiptType: RELEASE_BUNDLE_RECEIPT_TYPE,
    recoveryCompleteness: "release-component",
    releaseVersion: manifest.release.releaseVersion,
    requiredCompanionArtifacts: Object.freeze([
      "sanitized-state-evidence",
      "sanitized-event-archive",
    ] as const),
    signerFingerprintSha256: manifest.signer.publicKeyFingerprintSha256,
    signerKeyId: manifest.signer.keyId,
    version: RELEASE_BUNDLE_VERSION,
  });
}

function assertReceiptMatchesManifest(
  receipt: ReleaseBundleReceiptV1,
  manifest: ReleaseBundleManifestV1,
  manifestSha256: string,
): void {
  const expected = receiptFor(manifest, Buffer.alloc(0), manifestSha256);
  const comparableExpected = {
    ...expected,
    archiveSha256: receipt.archiveSha256,
    archiveSizeBytes: receipt.archiveSizeBytes,
  };
  if (canonicalJson(comparableExpected) !== canonicalJson(receipt)) {
    fail("TRUST_MISMATCH", "Release manifest does not match the retained receipt");
  }
}

function assertCompanions(value: unknown): void {
  const companions = exactArray(value, "Required release companions");
  if (
    companions.length !== 2 ||
    companions[0] !== "sanitized-state-evidence" ||
    companions[1] !== "sanitized-event-archive"
  ) {
    fail("ARCHIVE_FORMAT", "Required release companion set is invalid");
  }
}

function bindingsFromRelease(value: ReleaseArtifactBindingsV1): ReleaseArtifactBindingsV1 {
  return Object.freeze({
    artifactSetSha256: value.artifactSetSha256,
    configSetSha256: value.configSetSha256,
    lockfileSha256: value.lockfileSha256,
    recoverySetSha256: value.recoverySetSha256,
    runbookSetSha256: value.runbookSetSha256,
    sbomSha256: value.sbomSha256,
    sourceTreeSha256: value.sourceTreeSha256,
    testSummarySha256: value.testSummarySha256,
  });
}

export function manifestSignatureMessage(manifest: ReleaseBundleManifestV1): Buffer {
  return Buffer.concat([SIGNATURE_DOMAIN, Buffer.from(canonicalJson(manifest), "utf8")]);
}

/** Test-only decoder metadata; deliberately not exported by the package entrypoint. */
export function decodeEnvelopeForTest(bytes: Buffer): ManifestEnvelopeV1 {
  const minimum = ARCHIVE_MAGIC.length + 4;
  const length = bytes.readUInt32BE(ARCHIVE_MAGIC.length);
  return parseCanonicalJson(
    bytes.subarray(minimum, minimum + length),
    "Signed release manifest",
  ) as ManifestEnvelopeV1;
}
