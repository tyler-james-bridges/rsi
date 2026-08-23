import { createPublicKey, timingSafeEqual } from "node:crypto";
import { types as utilTypes } from "node:util";

import {
  canonicalJson,
  exactObject,
  sha256,
  validateHash,
  validateIdentifier,
} from "./canonical.js";
import { fail } from "./errors.js";

export const FOUNDATION_INDEPENDENT_REVIEWER_IDENTITY_PATH =
  "config/foundation-independent-reviewer-identity.v1.json" as const;
export const FOUNDATION_INDEPENDENT_REVIEWER_IDENTITY_TYPE =
  "rsi.foundation-independent-reviewer-identity" as const;
export const FOUNDATION_INDEPENDENT_REVIEWER_IDENTITY_VERSION = 1 as const;

const MAX_IDENTITY_BYTES = 64 * 1024;
const ED25519_SPKI_BYTES = 44;

export interface FoundationIndependentReviewerIdentityV1 {
  readonly algorithm: "Ed25519";
  readonly identityType: typeof FOUNDATION_INDEPENDENT_REVIEWER_IDENTITY_TYPE;
  readonly keyId: string;
  readonly publicKeySpkiDerBase64url: string;
  readonly reviewerFingerprintSha256: string;
  readonly reviewerId: string;
  readonly reviewerRole: "independent-non-authoring-agent";
  readonly version: typeof FOUNDATION_INDEPENDENT_REVIEWER_IDENTITY_VERSION;
}

export interface FoundationReviewerSeparationConstraintsV1 {
  readonly operatorIds: readonly string[];
  readonly releaseSignerFingerprintsSha256: readonly string[];
  readonly releaseSignerKeyIds: readonly string[];
  readonly releaseSignerPublicKeysSpkiDerBase64url: readonly string[];
}

export function parseFoundationIndependentReviewerIdentity(
  value: unknown,
): FoundationIndependentReviewerIdentityV1 {
  const record = exactObject(
    value,
    [
      "algorithm",
      "identityType",
      "keyId",
      "publicKeySpkiDerBase64url",
      "reviewerFingerprintSha256",
      "reviewerId",
      "reviewerRole",
      "version",
    ],
    "Foundation independent-reviewer identity",
  );
  if (
    record.algorithm !== "Ed25519" ||
    record.identityType !== FOUNDATION_INDEPENDENT_REVIEWER_IDENTITY_TYPE ||
    record.reviewerRole !== "independent-non-authoring-agent" ||
    record.version !== FOUNDATION_INDEPENDENT_REVIEWER_IDENTITY_VERSION
  ) {
    fail("VERIFICATION_FAILED", "Foundation independent-reviewer identity policy is invalid");
  }
  const publicKeySpkiDer = decodeCanonicalBase64url(
    record.publicKeySpkiDerBase64url,
    ED25519_SPKI_BYTES,
    "Foundation independent-reviewer public key",
  );
  try {
    assertCanonicalEd25519Spki(publicKeySpkiDer);
    const reviewerFingerprintSha256 = validateHash(
      record.reviewerFingerprintSha256,
      "Foundation independent-reviewer fingerprint",
    );
    const keyId = validateIdentifier(record.keyId, "Foundation independent-reviewer key ID");
    if (
      sha256(publicKeySpkiDer) !== reviewerFingerprintSha256 ||
      keyId !== `rsi-reviewer-${reviewerFingerprintSha256.slice(0, 16)}`
    ) {
      fail(
        "VERIFICATION_FAILED",
        "Foundation independent-reviewer identity cryptographic binding is invalid",
      );
    }
    return Object.freeze({
      algorithm: "Ed25519",
      identityType: FOUNDATION_INDEPENDENT_REVIEWER_IDENTITY_TYPE,
      keyId,
      publicKeySpkiDerBase64url: publicKeySpkiDer.toString("base64url"),
      reviewerFingerprintSha256,
      reviewerId: validateIdentifier(record.reviewerId, "Foundation independent-reviewer ID"),
      reviewerRole: "independent-non-authoring-agent",
      version: FOUNDATION_INDEPENDENT_REVIEWER_IDENTITY_VERSION,
    });
  } finally {
    publicKeySpkiDer.fill(0);
  }
}

export function decodeFoundationIndependentReviewerIdentity(
  value: Uint8Array,
): FoundationIndependentReviewerIdentityV1 {
  if (
    !(value instanceof Uint8Array) ||
    utilTypes.isProxy(value) ||
    value.byteLength === 0 ||
    value.byteLength > MAX_IDENTITY_BYTES
  ) {
    fail("INPUT_INVALID", "Foundation independent-reviewer identity bytes are invalid");
  }
  let text: string;
  let parsed: unknown;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(value);
    parsed = JSON.parse(text) as unknown;
  } catch {
    fail("INPUT_INVALID", "Foundation independent-reviewer identity is not valid JSON");
  }
  const identity = parseFoundationIndependentReviewerIdentity(parsed);
  if (canonicalJson(identity) !== text) {
    fail("INPUT_INVALID", "Foundation independent-reviewer identity is not canonical JSON");
  }
  return identity;
}

export function foundationIndependentReviewerIdentitySha256(
  value: FoundationIndependentReviewerIdentityV1,
): string {
  return sha256(canonicalJson(parseFoundationIndependentReviewerIdentity(value)));
}

export function foundationIndependentReviewerPublicKeySpkiDer(
  value: FoundationIndependentReviewerIdentityV1,
): Uint8Array {
  const identity = parseFoundationIndependentReviewerIdentity(value);
  return Uint8Array.from(Buffer.from(identity.publicKeySpkiDerBase64url, "base64url"));
}

export function assertFoundationIndependentReviewerSeparation(
  identityValue: FoundationIndependentReviewerIdentityV1,
  constraints: FoundationReviewerSeparationConstraintsV1,
): void {
  const identity = parseFoundationIndependentReviewerIdentity(identityValue);
  if (
    constraints.operatorIds.includes(identity.reviewerId) ||
    constraints.releaseSignerFingerprintsSha256.includes(identity.reviewerFingerprintSha256) ||
    constraints.releaseSignerKeyIds.includes(identity.keyId) ||
    constraints.releaseSignerPublicKeysSpkiDerBase64url.includes(identity.publicKeySpkiDerBase64url)
  ) {
    fail(
      "VERIFICATION_FAILED",
      "Foundation reviewer identity is not independent of the release signer or operator",
    );
  }
}

function decodeCanonicalBase64url(value: unknown, size: number, label: string): Buffer {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/u.test(value)) {
    fail("INPUT_INVALID", `${label} encoding is invalid`);
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== size || bytes.toString("base64url") !== value) {
    bytes.fill(0);
    fail("INPUT_INVALID", `${label} encoding is invalid`);
  }
  return bytes;
}

function assertCanonicalEd25519Spki(bytes: Buffer): void {
  let key;
  try {
    key = createPublicKey({ format: "der", key: bytes, type: "spki" });
  } catch {
    fail("INPUT_INVALID", "Foundation independent-reviewer public key is invalid");
  }
  const canonical = key.export({ format: "der", type: "spki" });
  try {
    if (
      key.type !== "public" ||
      key.asymmetricKeyType !== "ed25519" ||
      canonical.length !== bytes.length ||
      !timingSafeEqual(canonical, bytes)
    ) {
      fail("INPUT_INVALID", "Foundation independent-reviewer public key is not canonical Ed25519");
    }
  } finally {
    canonical.fill(0);
  }
}
