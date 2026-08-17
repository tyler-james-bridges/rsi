import { canonicalBytes, hex } from "./portable.js";
import { artifactSigningMessage, publicArtifactHashPreimage } from "./protocol.js";
import { PublicArtifactHeadSchema, SignedPublicArtifactSchema, parseSchema } from "./schemas.js";
import type {
  PublicArtifactHeadV1,
  PublicArtifactVerificationReportV1,
  PublicReceiptPayloadV1,
  PublicVerificationCrypto,
  SignedPublicArtifactV1,
} from "./types.js";

const MAX_PUBLIC_ARTIFACTS = 10_000;
const MAX_PUBLIC_ARTIFACT_BYTES = 32 * 1_024;
const MAX_PUBLIC_CHAIN_BYTES = 16 * 1_024 * 1_024;
const MINIMUM_PUBLICATION_DELAY_MS = 24 * 60 * 60 * 1_000;

export async function verifyPublicArtifactChain(
  optionsValue: Readonly<{
    artifacts: readonly unknown[];
    crypto: PublicVerificationCrypto;
    expectedHead?: PublicArtifactHeadV1;
    expectedKeyId: string;
    publicKeySpkiDer: Uint8Array;
  }>,
): Promise<Readonly<PublicArtifactVerificationReportV1>> {
  try {
    const options = parseOptions(optionsValue);
    const keyBytes = copyBrowserBytes(options.publicKeySpkiDer);
    let fingerprint: string;
    let key: unknown;
    try {
      fingerprint = hex(new Uint8Array(await options.crypto.digest("SHA-256", keyBytes)));
      key = await options.crypto.importEd25519PublicKey(keyBytes);
    } finally {
      keyBytes.fill(0);
    }
    const artifacts: SignedPublicArtifactV1[] = [];
    let predecessor: string | null = null;
    let profile: SignedPublicArtifactV1["payload"]["profile"] | null = null;
    let lastEffectiveTime = Number.NEGATIVE_INFINITY;
    let totalBytes = 0;
    const known = new Map<string, SignedPublicArtifactV1>();
    const inactive = new Set<string>();
    for (let index = 0; index < options.artifacts.length; index += 1) {
      const artifact = parseSchema(SignedPublicArtifactSchema, options.artifacts[index]);
      const artifactBytes = canonicalBytes(artifact);
      totalBytes += artifactBytes.byteLength;
      if (
        artifactBytes.byteLength > MAX_PUBLIC_ARTIFACT_BYTES ||
        totalBytes > MAX_PUBLIC_CHAIN_BYTES ||
        artifact.signerKeyId !== options.expectedKeyId ||
        artifact.signerFingerprintSha256 !== fingerprint ||
        artifact.payload.sequence !== index + 1 ||
        artifact.payload.predecessorSha256 !== predecessor ||
        (profile !== null && artifact.payload.profile !== profile)
      ) {
        return unverified();
      }
      profile ??= artifact.payload.profile;
      const { artifactSha256: _ignored, ...unsigned } = artifact;
      const artifactHash = hex(
        new Uint8Array(
          await options.crypto.digest("SHA-256", publicArtifactHashPreimage(unsigned)),
        ),
      );
      if (artifactHash !== artifact.artifactSha256) return unverified();
      const signature = decodeBase64url(artifact.signature);
      const message = artifactSigningMessage(
        artifact.payload,
        artifact.signerKeyId,
        artifact.signerFingerprintSha256,
      );
      if (!(await options.crypto.verifyEd25519(key, signature, message))) {
        return unverified();
      }
      const effectiveTime = validateArtifactSemantics(artifact, known, inactive, lastEffectiveTime);
      if (effectiveTime === null) return unverified();
      lastEffectiveTime = effectiveTime;
      if (artifact.payload.artifactType !== "rsi.public-receipt") {
        inactive.add(artifact.payload.targetArtifactSha256);
      }
      known.set(artifact.artifactSha256, artifact);
      artifacts.push(artifact);
      predecessor = artifact.artifactSha256;
    }
    if (options.expectedHead !== undefined) {
      const expectedHead = parseSchema(PublicArtifactHeadSchema, options.expectedHead);
      const pinned = artifacts[expectedHead.sequence - 1];
      if (pinned === undefined || pinned.artifactSha256 !== expectedHead.artifactSha256) {
        return unverified();
      }
    }
    const latestReceiptArtifact = artifacts
      .filter(
        (artifact): artifact is SignedPublicArtifactV1 & { payload: PublicReceiptPayloadV1 } =>
          artifact.payload.artifactType === "rsi.public-receipt" &&
          !inactive.has(artifact.artifactSha256),
      )
      .at(-1);
    const headArtifact = artifacts.at(-1)!;
    return Object.freeze({
      artifactCount: artifacts.length,
      head: Object.freeze({
        artifactSha256: headArtifact.artifactSha256,
        sequence: headArtifact.payload.sequence,
      }),
      latestReceipt: latestReceiptArtifact?.payload ?? null,
      schemaVersion: 1 as const,
      status: "VERIFIED" as const,
    });
  } catch {
    return unverified();
  }
}

function validateArtifactSemantics(
  artifact: SignedPublicArtifactV1,
  known: ReadonlyMap<string, SignedPublicArtifactV1>,
  inactive: ReadonlySet<string>,
  lastEffectiveTime: number,
): number | null {
  const payload = artifact.payload;
  if (payload.artifactType === "rsi.public-receipt") {
    const acceptedAt = Date.parse(payload.acceptedAt);
    const createdAt = Date.parse(payload.createdAt);
    const eligibleAt = Date.parse(payload.eligibleAt);
    const reviewedAt = Date.parse(payload.reviewedAt);
    const publishedAt = Date.parse(payload.publishedAt);
    if (
      createdAt < acceptedAt ||
      eligibleAt < createdAt ||
      eligibleAt - acceptedAt < MINIMUM_PUBLICATION_DELAY_MS ||
      reviewedAt < eligibleAt ||
      publishedAt < reviewedAt ||
      publishedAt < lastEffectiveTime ||
      BigInt(payload.costs.reconciledAtomic) > BigInt(payload.costs.reservedAtomic)
    ) {
      return null;
    }
    return publishedAt;
  }

  const target = known.get(payload.targetArtifactSha256);
  if (
    target?.payload.artifactType !== "rsi.public-receipt" ||
    target.payload.profile !== payload.profile ||
    inactive.has(payload.targetArtifactSha256)
  ) {
    return null;
  }
  const effectiveAt = Date.parse(
    payload.artifactType === "rsi.public-correction" ? payload.effectiveAt : payload.removedAt,
  );
  if (effectiveAt < Date.parse(target.payload.publishedAt) || effectiveAt < lastEffectiveTime) {
    return null;
  }
  if (payload.artifactType === "rsi.public-correction") {
    if (payload.replacementArtifactSha256 === payload.targetArtifactSha256) return null;
    if (payload.replacementArtifactSha256 !== null) {
      const replacement = known.get(payload.replacementArtifactSha256);
      if (
        replacement?.payload.artifactType !== "rsi.public-receipt" ||
        replacement.payload.profile !== payload.profile ||
        inactive.has(payload.replacementArtifactSha256)
      ) {
        return null;
      }
    }
  }
  return effectiveAt;
}

export function webCryptoAdapter(
  subtle: Readonly<{
    digest(algorithm: string, data: Uint8Array): Promise<ArrayBuffer>;
    importKey(
      format: "spki",
      keyData: Uint8Array,
      algorithm: Readonly<{ name: "Ed25519" }>,
      extractable: false,
      usages: readonly ["verify"],
    ): Promise<unknown>;
    verify(
      algorithm: Readonly<{ name: "Ed25519" }>,
      key: unknown,
      signature: Uint8Array,
      data: Uint8Array,
    ): Promise<boolean>;
  }>,
): PublicVerificationCrypto {
  return Object.freeze({
    digest: (algorithm: "SHA-256", data: Uint8Array) => subtle.digest(algorithm, data),
    importEd25519PublicKey: (spkiDer: Uint8Array) =>
      subtle.importKey("spki", spkiDer, { name: "Ed25519" }, false, ["verify"]),
    verifyEd25519: (key: unknown, signature: Uint8Array, message: Uint8Array) =>
      subtle.verify({ name: "Ed25519" }, key, signature, message),
  });
}

function unverified(): Readonly<PublicArtifactVerificationReportV1> {
  return Object.freeze({
    artifactCount: 0,
    head: null,
    latestReceipt: null,
    schemaVersion: 1 as const,
    status: "UNVERIFIED" as const,
  });
}

function decodeBase64url(value: string): Uint8Array {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/") + "==";
  const binary = atob(normalized);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  const canonical = btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
  if (bytes.byteLength !== 64 || canonical !== value) throw new Error();
  return bytes;
}

function parseOptions(optionsValue: unknown): Readonly<{
  artifacts: readonly unknown[];
  crypto: PublicVerificationCrypto;
  expectedHead?: PublicArtifactHeadV1;
  expectedKeyId: string;
  publicKeySpkiDer: Uint8Array;
}> {
  if (typeof optionsValue !== "object" || optionsValue === null) throw new Error();
  if (Object.getPrototypeOf(optionsValue) !== Object.prototype) throw new Error();
  const allowed = new Set([
    "artifacts",
    "crypto",
    "expectedHead",
    "expectedKeyId",
    "publicKeySpkiDer",
  ]);
  const keys = Reflect.ownKeys(optionsValue);
  if (
    keys.length < 4 ||
    keys.length > 5 ||
    keys.some((key) => typeof key !== "string" || !allowed.has(key))
  ) {
    throw new Error();
  }
  const required = ["artifacts", "crypto", "expectedKeyId", "publicKeySpkiDer"];
  const values: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of required) {
    const descriptor = Object.getOwnPropertyDescriptor(optionsValue, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw new Error();
    }
    values[key] = descriptor.value;
  }
  if (
    !Array.isArray(values.artifacts) ||
    Object.getPrototypeOf(values.artifacts) !== Array.prototype ||
    values.artifacts.length === 0 ||
    values.artifacts.length > MAX_PUBLIC_ARTIFACTS ||
    typeof values.expectedKeyId !== "string" ||
    !/^[a-z0-9][a-z0-9._:-]{0,127}$/.test(values.expectedKeyId) ||
    typeof values.crypto !== "object" ||
    values.crypto === null
  ) {
    throw new Error();
  }
  const crypto = values.crypto as Partial<PublicVerificationCrypto>;
  if (
    typeof crypto.digest !== "function" ||
    typeof crypto.importEd25519PublicKey !== "function" ||
    typeof crypto.verifyEd25519 !== "function"
  ) {
    throw new Error();
  }
  const expectedHeadDescriptor = Object.getOwnPropertyDescriptor(optionsValue, "expectedHead");
  if (
    expectedHeadDescriptor !== undefined &&
    (!("value" in expectedHeadDescriptor) || !expectedHeadDescriptor.enumerable)
  ) {
    throw new Error();
  }
  const parsed: {
    artifacts: readonly unknown[];
    crypto: PublicVerificationCrypto;
    expectedHead?: PublicArtifactHeadV1;
    expectedKeyId: string;
    publicKeySpkiDer: Uint8Array;
  } = {
    artifacts: values.artifacts,
    crypto: crypto as PublicVerificationCrypto,
    expectedKeyId: values.expectedKeyId,
    publicKeySpkiDer: values.publicKeySpkiDer as Uint8Array,
  };
  if (expectedHeadDescriptor !== undefined) {
    parsed.expectedHead = expectedHeadDescriptor.value as PublicArtifactHeadV1;
  }
  return parsed;
}

function copyBrowserBytes(value: unknown): Uint8Array {
  if (
    typeof value !== "object" ||
    value === null ||
    Object.getPrototypeOf(value) !== Uint8Array.prototype
  ) {
    throw new Error();
  }
  const bytes = value as Uint8Array;
  if (
    !(bytes.buffer instanceof ArrayBuffer) ||
    Object.getPrototypeOf(bytes.buffer) !== ArrayBuffer.prototype ||
    bytes.byteOffset !== 0 ||
    bytes.byteLength !== bytes.buffer.byteLength
  ) {
    throw new Error();
  }
  try {
    structuredClone(bytes);
    return Uint8Array.prototype.slice.call(bytes) as Uint8Array;
  } catch {
    throw new Error();
  }
}
