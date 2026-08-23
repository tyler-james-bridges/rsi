import { createPublicKey, timingSafeEqual } from "node:crypto";
import { types as utilTypes } from "node:util";

import {
  decodeReleaseKeyHelperCompatibilityEvidence,
  releaseKeyHelperCompatibilityEvidenceSha256,
  type ReleaseKeyHelperCompatibilityEvidenceV1,
} from "@rsi/release-key-provisioning";

import {
  canonicalJson,
  exactArray,
  exactObject,
  sha256,
  validateCanonicalTimestamp,
  validateGitHash,
  validateHash,
  validateIdentifier,
} from "./canonical.js";
import { fail } from "./errors.js";

export const FOUNDATION_RELEASE_IDENTITY_PATH =
  "config/foundation-release-identity.v1.json" as const;
export const FOUNDATION_RELEASE_PROVISIONING_RECEIPT_PATH =
  "config/foundation-release-key-provisioning-receipt.v1.json" as const;

const SERVICE = "dev.rsi.macbook.release-signing" as const;
const ACCOUNT = "release-ed25519-v1" as const;
const PROTECTION = "data-protection-when-unlocked-this-device-only-user-presence" as const;
const IDENTITY_TYPE = "rsi.release-public-identity-candidate" as const;
const RECEIPT_TYPE = "rsi.release-key-provisioning-receipt" as const;
const MAX_PIN_BYTES = 64 * 1024;

export interface FoundationPinnedReleaseIdentityV1 {
  readonly account: typeof ACCOUNT;
  readonly createdAt: string;
  readonly helperBinarySha256: string;
  readonly helperCompatibilityEvidence: ReleaseKeyHelperCompatibilityEvidenceV1;
  readonly helperCompatibilityEvidenceSha256: string;
  readonly helperCompatibilityTestedCommitSha: string;
  readonly helperCompilerIdentitySha256: string;
  readonly helperSourceSha256: string;
  readonly identitySha256: string;
  readonly keyId: string;
  readonly platformIdentitySha256: string;
  readonly provisioningIntentSha256: string;
  readonly provisioningReceiptSha256: string;
  readonly provisioningRepositoryCommitSha: string;
  readonly publicKeySpkiDer: Uint8Array;
  readonly pinningRepositoryCommitSha: string;
  readonly service: typeof SERVICE;
  readonly signerFingerprintSha256: string;
}

export function parseFoundationPinnedReleaseIdentity(
  identityBytesValue: Uint8Array,
  receiptBytesValue: Uint8Array,
  compatibilityBytesValue: Uint8Array,
  expectedCommitValue: string,
): FoundationPinnedReleaseIdentityV1 {
  const expectedCommit = validateGitHash(expectedCommitValue, "Pinned identity repository commit");
  const identityBytes = copyBoundedBytes(identityBytesValue, "Pinned release identity");
  const receiptBytes = copyBoundedBytes(receiptBytesValue, "Pinned provisioning receipt");
  const compatibilityBytes = copyBoundedBytes(
    compatibilityBytesValue,
    "Pinned helper compatibility evidence",
  );
  let publicKeySpkiDer: Buffer | undefined;
  try {
    const identity = parseCanonicalRecord(identityBytes, "Pinned release identity");
    const receipt = parseCanonicalRecord(receiptBytes, "Pinned provisioning receipt");
    const helperCompatibilityEvidence =
      decodeReleaseKeyHelperCompatibilityEvidence(compatibilityBytes);
    const identityRecord = exactObject(
      identity,
      [
        "account",
        "algorithm",
        "candidateType",
        "createdAt",
        "helperBinarySha256",
        "helperCompatibilityEvidenceSha256",
        "helperCompatibilityTestedCommitSha",
        "helperCompilerIdentitySha256",
        "helperSourceSha256",
        "keyId",
        "keychainProtection",
        "platformIdentitySha256",
        "publicKeySpkiDerBase64url",
        "service",
        "signerFingerprintSha256",
        "version",
      ],
      "Pinned release identity",
    );
    if (
      identityRecord.account !== ACCOUNT ||
      identityRecord.algorithm !== "Ed25519" ||
      identityRecord.candidateType !== IDENTITY_TYPE ||
      identityRecord.keychainProtection !== PROTECTION ||
      identityRecord.service !== SERVICE ||
      identityRecord.version !== 1
    ) {
      fail("CUSTODY_FAILED", "Pinned release identity policy is invalid");
    }
    publicKeySpkiDer = decodeCanonicalBase64url(
      identityRecord.publicKeySpkiDerBase64url,
      44,
      "Pinned Ed25519 public key",
    );
    assertCanonicalEd25519Spki(publicKeySpkiDer);
    const signerFingerprintSha256 = validateHash(
      identityRecord.signerFingerprintSha256,
      "Pinned signer fingerprint",
    );
    const keyId = validateIdentifier(identityRecord.keyId, "Pinned signer key ID");
    if (
      sha256(publicKeySpkiDer) !== signerFingerprintSha256 ||
      keyId !== `rsi-release-${signerFingerprintSha256.slice(0, 16)}`
    ) {
      publicKeySpkiDer.fill(0);
      fail("CUSTODY_FAILED", "Pinned release identity cryptographic binding is invalid");
    }
    const createdAt = validateCanonicalTimestamp(
      identityRecord.createdAt,
      "Pinned identity creation time",
    );
    const helperBinarySha256 = validateHash(
      identityRecord.helperBinarySha256,
      "Pinned helper binary hash",
    );
    const helperCompatibilityEvidenceSha256 = validateHash(
      identityRecord.helperCompatibilityEvidenceSha256,
      "Pinned helper compatibility evidence hash",
    );
    const helperCompatibilityTestedCommitSha = validateGitHash(
      identityRecord.helperCompatibilityTestedCommitSha,
      "Pinned helper compatibility tested commit",
    );
    const helperCompilerIdentitySha256 = validateHash(
      identityRecord.helperCompilerIdentitySha256,
      "Pinned helper compiler identity hash",
    );
    const helperSourceSha256 = validateHash(
      identityRecord.helperSourceSha256,
      "Pinned helper source hash",
    );
    const platformIdentitySha256 = validateHash(
      identityRecord.platformIdentitySha256,
      "Pinned platform identity hash",
    );
    const identitySha256 = sha256(identityBytes);
    if (
      helperCompatibilityEvidenceSha256 !==
        releaseKeyHelperCompatibilityEvidenceSha256(helperCompatibilityEvidence) ||
      helperCompatibilityTestedCommitSha !== helperCompatibilityEvidence.testedCommitSha ||
      helperBinarySha256 !== helperCompatibilityEvidence.helper.binarySha256 ||
      helperCompilerIdentitySha256 !== helperCompatibilityEvidence.helper.compilerIdentitySha256 ||
      helperSourceSha256 !== helperCompatibilityEvidence.helper.sourceSha256
    ) {
      fail("CUSTODY_FAILED", "Pinned helper compatibility evidence does not bind the helper");
    }
    const receiptRecord = parseReceipt(receipt, {
      createdAt,
      helperBinarySha256,
      helperCompatibilityEvidenceSha256,
      helperCompatibilityTestedCommitSha,
      helperCompilerIdentitySha256,
      helperSourceSha256,
      identitySha256,
      keyId,
      platformIdentitySha256,
      signerFingerprintSha256,
    });
    return Object.freeze({
      account: ACCOUNT,
      createdAt,
      helperBinarySha256,
      helperCompatibilityEvidence,
      helperCompatibilityEvidenceSha256,
      helperCompatibilityTestedCommitSha,
      helperCompilerIdentitySha256,
      helperSourceSha256,
      identitySha256,
      keyId,
      platformIdentitySha256,
      provisioningIntentSha256: receiptRecord.provisioningIntentSha256,
      provisioningReceiptSha256: sha256(receiptBytes),
      provisioningRepositoryCommitSha: receiptRecord.provisioningRepositoryCommitSha,
      publicKeySpkiDer: Uint8Array.from(publicKeySpkiDer),
      pinningRepositoryCommitSha: expectedCommit,
      service: SERVICE,
      signerFingerprintSha256,
    });
  } finally {
    identityBytes.fill(0);
    receiptBytes.fill(0);
    compatibilityBytes.fill(0);
    publicKeySpkiDer?.fill(0);
  }
}

function parseReceipt(
  value: unknown,
  expected: {
    readonly createdAt: string;
    readonly helperBinarySha256: string;
    readonly helperCompatibilityEvidenceSha256: string;
    readonly helperCompatibilityTestedCommitSha: string;
    readonly helperCompilerIdentitySha256: string;
    readonly helperSourceSha256: string;
    readonly identitySha256: string;
    readonly keyId: string;
    readonly platformIdentitySha256: string;
    readonly signerFingerprintSha256: string;
  },
): {
  readonly provisioningIntentSha256: string;
  readonly provisioningRepositoryCommitSha: string;
} {
  const record = exactObject(
    value,
    [
      "account",
      "copyCount",
      "createdAt",
      "helperBinarySha256",
      "helperCompatibilityEvidenceSha256",
      "helperCompatibilityTestedCommitSha",
      "helperCompilerIdentitySha256",
      "helperSourceSha256",
      "keyId",
      "keychainProtection",
      "keychainStatus",
      "platformIdentitySha256",
      "provisioningIntentSha256",
      "publicIdentitySha256",
      "recoveryCopies",
      "receiptType",
      "repositoryCommitSha",
      "service",
      "signerFingerprintSha256",
      "status",
      "version",
    ],
    "Pinned provisioning receipt",
  );
  if (
    record.account !== ACCOUNT ||
    record.copyCount !== 2 ||
    record.createdAt !== expected.createdAt ||
    record.helperBinarySha256 !== expected.helperBinarySha256 ||
    record.helperCompatibilityEvidenceSha256 !== expected.helperCompatibilityEvidenceSha256 ||
    record.helperCompatibilityTestedCommitSha !== expected.helperCompatibilityTestedCommitSha ||
    record.helperCompilerIdentitySha256 !== expected.helperCompilerIdentitySha256 ||
    record.helperSourceSha256 !== expected.helperSourceSha256 ||
    record.keyId !== expected.keyId ||
    record.keychainProtection !== PROTECTION ||
    record.keychainStatus !== "identity-verified" ||
    record.platformIdentitySha256 !== expected.platformIdentitySha256 ||
    record.publicIdentitySha256 !== expected.identitySha256 ||
    record.receiptType !== RECEIPT_TYPE ||
    record.service !== SERVICE ||
    record.signerFingerprintSha256 !== expected.signerFingerprintSha256 ||
    record.status !== "verified-keychain-and-two-recovery-copies" ||
    record.version !== 1
  ) {
    fail("CUSTODY_FAILED", "Pinned provisioning receipt does not bind the release identity");
  }
  parseRecoveryCopies(record.recoveryCopies);
  return Object.freeze({
    provisioningIntentSha256: validateHash(
      record.provisioningIntentSha256,
      "Pinned provisioning intent hash",
    ),
    provisioningRepositoryCommitSha: validateGitHash(
      record.repositoryCommitSha,
      "Pinned provisioning repository commit",
    ),
  });
}

function parseRecoveryCopies(value: unknown): void {
  const values = exactArray(value, "Pinned recovery-copy evidence", 2);
  if (values.length !== 2) fail("CUSTODY_FAILED", "Pinned recovery-copy evidence is incomplete");
  const hashes: Array<{ envelope: string; physical: string; volume: string }> = [];
  for (const [index, entry] of values.entries()) {
    const record = exactObject(
      entry,
      [
        "copyIndex",
        "envelopeSha256",
        "physicalStoreIdentitySha256",
        "restoredAt",
        "restoreStatus",
        "volumeIdentitySha256",
      ],
      "Pinned recovery-copy evidence",
    );
    if (record.copyIndex !== index + 1 || record.restoreStatus !== "restore-verified") {
      fail("CUSTODY_FAILED", "Pinned recovery-copy evidence order or status is invalid");
    }
    validateCanonicalTimestamp(record.restoredAt, "Pinned recovery restore time");
    hashes.push({
      envelope: validateHash(record.envelopeSha256, "Pinned recovery envelope hash"),
      physical: validateHash(
        record.physicalStoreIdentitySha256,
        "Pinned recovery physical-store hash",
      ),
      volume: validateHash(record.volumeIdentitySha256, "Pinned recovery volume hash"),
    });
  }
  if (
    hashes[0]!.envelope === hashes[1]!.envelope ||
    hashes[0]!.physical === hashes[1]!.physical ||
    hashes[0]!.volume === hashes[1]!.volume
  ) {
    fail("CUSTODY_FAILED", "Pinned recovery copies are not independently bound");
  }
}

function parseCanonicalRecord(bytes: Buffer, label: string): unknown {
  let text: string;
  let value: unknown;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    value = JSON.parse(text) as unknown;
  } catch {
    fail("CUSTODY_FAILED", `${label} is not valid canonical JSON`);
  }
  if (canonicalJson(value) !== text) fail("CUSTODY_FAILED", `${label} is not canonical JSON`);
  return value;
}

function decodeCanonicalBase64url(value: unknown, size: number, label: string): Buffer {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/u.test(value)) {
    fail("CUSTODY_FAILED", `${label} encoding is invalid`);
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== size || bytes.toString("base64url") !== value) {
    bytes.fill(0);
    fail("CUSTODY_FAILED", `${label} encoding is invalid`);
  }
  return bytes;
}

function assertCanonicalEd25519Spki(bytes: Buffer): void {
  let key;
  try {
    key = createPublicKey({ format: "der", key: bytes, type: "spki" });
  } catch {
    fail("CUSTODY_FAILED", "Pinned public key is invalid");
  }
  const canonical = key.export({ format: "der", type: "spki" });
  try {
    if (
      key.asymmetricKeyType !== "ed25519" ||
      canonical.length !== bytes.length ||
      !timingSafeEqual(canonical, bytes)
    ) {
      fail("CUSTODY_FAILED", "Pinned public key is not canonical Ed25519 SPKI");
    }
  } finally {
    canonical.fill(0);
  }
}

function copyBoundedBytes(value: unknown, label: string): Buffer {
  if (
    !(value instanceof Uint8Array) ||
    utilTypes.isProxy(value) ||
    value.byteLength === 0 ||
    value.byteLength > MAX_PIN_BYTES
  ) {
    fail("CUSTODY_FAILED", `${label} bytes are invalid`);
  }
  return Buffer.from(value);
}
