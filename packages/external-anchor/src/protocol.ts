import {
  createHash,
  createPrivateKey,
  createPublicKey,
  KeyObject,
  sign,
  verify,
  type PrivateKeyInput,
  type PublicKeyInput,
} from "node:crypto";

import {
  CHECKPOINT_JOURNAL_GENESIS_HASH,
  CHECKPOINT_PAYLOAD_VERSION,
  CHECKPOINT_TYPE,
  computeCheckpointHash,
  encodeCheckpointPayload,
  type CheckpointPayload,
  type SignedCheckpoint,
} from "@rsi/checkpoints";

import {
  assertNotProxy,
  canonicalJson,
  strictRecord,
  validateHash,
  validateIdentifier,
  validateSafeInteger,
  validateTimestamp,
} from "./canonical.js";
import { ExternalAnchorIntegrityError, ExternalAnchorValidationError } from "./errors.js";
import {
  EXTERNAL_ANCHOR_MAX_BYTES,
  EXTERNAL_ANCHOR_AUTHORIZATION_TYPE,
  EXTERNAL_ANCHOR_AUTHORIZATION_VERSION,
  EXTERNAL_ANCHOR_TYPE,
  EXTERNAL_ANCHOR_VERSION,
  type AnchorProfile,
  type AnchorRetentionMode,
  type AnchorRetentionPolicy,
  type ExternalAnchorAuthorizationPayload,
  type ExternalAnchorEnvelope,
  type ExternalAnchorProtocolOptions,
  type PrepareExternalAnchorInput,
  type PreparedExternalAnchorObject,
  type SignExternalAnchorAuthorizationInput,
  type SignedExternalAnchorAuthorization,
} from "./types.js";

const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/;
const AUTHORIZATION_SIGNATURE_DOMAIN = Buffer.from(
  "rsi-external-anchor-authorization-signature-v1\0",
  "utf8",
);
const OBJECT_KEY_PATTERN =
  /^anchors\/v1\/(canary|production-observer)\/([0-9]{16})\/([0-9a-f]{64})\.json$/;

export class ExternalAnchorProtocol {
  readonly expectedKeyId: string;
  readonly expectedStoreId: string;
  readonly publicKeyFingerprint: string;

  readonly #publicKey: KeyObject;

  constructor(options: ExternalAnchorProtocolOptions) {
    const record = strictRecord(
      options,
      ["expectedKeyId", "expectedPublicKey", "expectedStoreId"],
      "external anchor protocol options",
    );
    this.expectedKeyId = validateIdentifier(record.expectedKeyId, "expectedKeyId");
    this.expectedStoreId = validateIdentifier(record.expectedStoreId, "expectedStoreId");
    if (
      record.expectedPublicKey !== null &&
      (typeof record.expectedPublicKey === "object" ||
        typeof record.expectedPublicKey === "function")
    ) {
      assertNotProxy(record.expectedPublicKey, "expectedPublicKey");
    }
    try {
      this.#publicKey =
        record.expectedPublicKey instanceof KeyObject
          ? record.expectedPublicKey
          : createPublicKey(record.expectedPublicKey as PublicKeyInput);
    } catch {
      throw new ExternalAnchorValidationError("expectedPublicKey must be an Ed25519 public key");
    }
    if (this.#publicKey.type !== "public" || this.#publicKey.asymmetricKeyType !== "ed25519") {
      throw new ExternalAnchorValidationError("expectedPublicKey must be an Ed25519 public key");
    }
    this.publicKeyFingerprint = createHash("sha256")
      .update(this.#publicKey.export({ format: "der", type: "spki" }))
      .digest("hex");
  }

  prepare(input: PrepareExternalAnchorInput): PreparedExternalAnchorObject {
    const record = strictRecord(
      input,
      ["authorization", "checkpoint"],
      "external anchor preparation",
    );
    const checkpoint = this.verifySignedCheckpoint(record.checkpoint);
    const authorization = this.verifySignedAuthorization(record.authorization);
    assertAuthorizationMatchesCheckpoint(authorization, checkpoint);
    if (checkpoint.payload.storeHeadSequence < 1) {
      throw new ExternalAnchorValidationError("external anchors may not contain an empty head");
    }
    const envelope: ExternalAnchorEnvelope = deepFreezeEnvelope({
      anchorType: EXTERNAL_ANCHOR_TYPE,
      authorization,
      checkpoint,
      version: EXTERNAL_ANCHOR_VERSION,
    });
    const body = canonicalJson(envelope);
    const sizeBytes = Buffer.byteLength(body, "utf8");
    if (sizeBytes > EXTERNAL_ANCHOR_MAX_BYTES) {
      throw new ExternalAnchorValidationError("external anchor exceeds the 4 KiB contract");
    }
    const { profile, retention } = authorization.payload;
    const objectKey = objectKeyFor(
      profile,
      checkpoint.payload.journalSequence,
      checkpoint.checkpointHash,
    );
    return Object.freeze({
      body,
      checkpointHash: checkpoint.checkpointHash,
      contentSha256: sha256(body),
      journalSequence: checkpoint.payload.journalSequence,
      objectKey,
      profile,
      retention,
      sizeBytes,
      storeHeadSequence: checkpoint.payload.storeHeadSequence,
    });
  }

  parseAndVerifyBody(bodyInput: unknown): ExternalAnchorEnvelope {
    if (typeof bodyInput !== "string") {
      throw new ExternalAnchorValidationError("external anchor body must be a string");
    }
    const size = Buffer.byteLength(bodyInput, "utf8");
    if (size === 0 || size > EXTERNAL_ANCHOR_MAX_BYTES) {
      throw new ExternalAnchorValidationError("external anchor body violates the 4 KiB contract");
    }
    let decoded: unknown;
    try {
      decoded = JSON.parse(bodyInput) as unknown;
    } catch {
      throw new ExternalAnchorValidationError("external anchor body is not valid JSON");
    }
    const envelope = this.parseEnvelope(decoded);
    if (canonicalJson(envelope) !== bodyInput) {
      throw new ExternalAnchorValidationError("external anchor body is not canonical JSON");
    }
    return envelope;
  }

  parseEnvelope(value: unknown): ExternalAnchorEnvelope {
    const record = strictRecord(
      value,
      ["anchorType", "authorization", "checkpoint", "version"],
      "external anchor envelope",
    );
    if (record.anchorType !== EXTERNAL_ANCHOR_TYPE || record.version !== EXTERNAL_ANCHOR_VERSION) {
      throw new ExternalAnchorValidationError("unsupported external anchor envelope");
    }
    const checkpoint = this.verifySignedCheckpoint(record.checkpoint);
    const authorization = this.verifySignedAuthorization(record.authorization);
    assertAuthorizationMatchesCheckpoint(authorization, checkpoint);
    return deepFreezeEnvelope({
      anchorType: EXTERNAL_ANCHOR_TYPE,
      authorization,
      checkpoint,
      version: EXTERNAL_ANCHOR_VERSION,
    });
  }

  verifySignedAuthorization(value: unknown): SignedExternalAnchorAuthorization {
    const record = strictRecord(
      value,
      ["payload", "signature"],
      "signed external anchor authorization",
    );
    const payload = parseAuthorizationPayload(record.payload);
    const signature = parseSignature(record.signature);
    if (payload.keyId !== this.expectedKeyId) {
      throw new ExternalAnchorIntegrityError("anchor authorization has the wrong key ID");
    }
    if (payload.storeId !== this.expectedStoreId) {
      throw new ExternalAnchorIntegrityError("anchor authorization has the wrong store ID");
    }
    if (
      !verify(
        null,
        encodeExternalAnchorAuthorizationPayload(payload),
        this.#publicKey,
        Buffer.from(signature, "base64url"),
      )
    ) {
      throw new ExternalAnchorIntegrityError("anchor authorization signature is invalid");
    }
    return Object.freeze({ payload, signature });
  }

  verifySignedCheckpoint(value: unknown): SignedCheckpoint {
    const record = strictRecord(
      value,
      ["checkpointHash", "payload", "signature"],
      "signed checkpoint",
    );
    const checkpointHash = validateHash(record.checkpointHash, "checkpointHash");
    const signature = parseSignature(record.signature);
    const payload = parseCheckpointPayload(record.payload);
    if (payload.keyId !== this.expectedKeyId) {
      throw new ExternalAnchorIntegrityError("signed checkpoint has the wrong key ID");
    }
    if (payload.storeId !== this.expectedStoreId) {
      throw new ExternalAnchorIntegrityError("signed checkpoint has the wrong store ID");
    }
    if (computeCheckpointHash(payload, signature) !== checkpointHash) {
      throw new ExternalAnchorIntegrityError("signed checkpoint hash is invalid");
    }
    if (
      !verify(
        null,
        encodeCheckpointPayload(payload),
        this.#publicKey,
        Buffer.from(signature, "base64url"),
      )
    ) {
      throw new ExternalAnchorIntegrityError("signed checkpoint signature is invalid");
    }
    return Object.freeze({ checkpointHash, payload, signature });
  }
}

/** Signs only a checkpoint already authenticated by the same Ed25519 key. */
export function signExternalAnchorAuthorization(
  input: SignExternalAnchorAuthorizationInput,
): SignedExternalAnchorAuthorization {
  const record = strictRecord(
    input,
    ["checkpoint", "privateKey", "profile", "retentionMode"],
    "external anchor authorization signing input",
  );
  const checkpointRecord = strictRecord(
    record.checkpoint,
    ["checkpointHash", "payload", "signature"],
    "signed checkpoint",
  );
  const checkpointSignature = parseSignature(checkpointRecord.signature);
  const checkpointPayload = parseCheckpointPayload(checkpointRecord.payload);
  const checkpointHash = validateHash(checkpointRecord.checkpointHash, "checkpointHash");
  if (computeCheckpointHash(checkpointPayload, checkpointSignature) !== checkpointHash) {
    throw new ExternalAnchorIntegrityError("signed checkpoint hash is invalid");
  }
  if (
    record.privateKey !== null &&
    (typeof record.privateKey === "object" || typeof record.privateKey === "function")
  ) {
    assertNotProxy(record.privateKey, "privateKey");
  }
  let privateKey: KeyObject;
  try {
    privateKey =
      record.privateKey instanceof KeyObject
        ? record.privateKey
        : createPrivateKey(record.privateKey as PrivateKeyInput);
  } catch {
    throw new ExternalAnchorValidationError("privateKey must be an Ed25519 private key");
  }
  if (privateKey.type !== "private" || privateKey.asymmetricKeyType !== "ed25519") {
    throw new ExternalAnchorValidationError("privateKey must be an Ed25519 private key");
  }
  const publicKey = createPublicKey(privateKey);
  if (
    !verify(
      null,
      encodeCheckpointPayload(checkpointPayload),
      publicKey,
      Buffer.from(checkpointSignature, "base64url"),
    )
  ) {
    throw new ExternalAnchorIntegrityError(
      "checkpoint was not signed by the anchor authorization key",
    );
  }
  const payload: ExternalAnchorAuthorizationPayload = Object.freeze({
    authorizationType: EXTERNAL_ANCHOR_AUTHORIZATION_TYPE,
    checkpointHash,
    keyId: checkpointPayload.keyId,
    profile: parseProfile(record.profile),
    retention: retentionPolicy(record.retentionMode),
    storeId: checkpointPayload.storeId,
    version: EXTERNAL_ANCHOR_AUTHORIZATION_VERSION,
  });
  const signature = sign(
    null,
    encodeExternalAnchorAuthorizationPayload(payload),
    privateKey,
  ).toString("base64url");
  return Object.freeze({ payload, signature });
}

/** Returns the exact domain-separated bytes covered by the authorization signature. */
export function encodeExternalAnchorAuthorizationPayload(
  value: ExternalAnchorAuthorizationPayload,
): Buffer {
  const payload = parseAuthorizationPayload(value);
  return Buffer.concat([
    AUTHORIZATION_SIGNATURE_DOMAIN,
    Buffer.from(canonicalJson(payload), "utf8"),
  ]);
}

function parseAuthorizationPayload(value: unknown): ExternalAnchorAuthorizationPayload {
  const record = strictRecord(
    value,
    ["authorizationType", "checkpointHash", "keyId", "profile", "retention", "storeId", "version"],
    "external anchor authorization payload",
  );
  if (
    record.authorizationType !== EXTERNAL_ANCHOR_AUTHORIZATION_TYPE ||
    record.version !== EXTERNAL_ANCHOR_AUTHORIZATION_VERSION
  ) {
    throw new ExternalAnchorValidationError("unsupported external anchor authorization");
  }
  return Object.freeze({
    authorizationType: EXTERNAL_ANCHOR_AUTHORIZATION_TYPE,
    checkpointHash: validateHash(record.checkpointHash, "authorization checkpointHash"),
    keyId: validateIdentifier(record.keyId, "authorization keyId"),
    profile: parseProfile(record.profile),
    retention: parseRetentionEnvelope(record.retention),
    storeId: validateIdentifier(record.storeId, "authorization storeId"),
    version: EXTERNAL_ANCHOR_AUTHORIZATION_VERSION,
  });
}

function assertAuthorizationMatchesCheckpoint(
  authorization: SignedExternalAnchorAuthorization,
  checkpoint: SignedCheckpoint,
): void {
  if (
    authorization.payload.checkpointHash !== checkpoint.checkpointHash ||
    authorization.payload.keyId !== checkpoint.payload.keyId ||
    authorization.payload.storeId !== checkpoint.payload.storeId
  ) {
    throw new ExternalAnchorIntegrityError(
      "anchor authorization does not match the signed checkpoint",
    );
  }
}

function parseCheckpointPayload(value: unknown): CheckpointPayload {
  const record = strictRecord(
    value,
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
    "checkpoint payload",
  );
  if (record.checkpointType !== CHECKPOINT_TYPE || record.version !== CHECKPOINT_PAYLOAD_VERSION) {
    throw new ExternalAnchorValidationError("unsupported checkpoint payload");
  }
  const journalSequence = validateSafeInteger(record.journalSequence, "journalSequence", 1);
  const previousCheckpointHash = validateHash(
    record.previousCheckpointHash,
    "previousCheckpointHash",
  );
  if (journalSequence === 1 && previousCheckpointHash !== CHECKPOINT_JOURNAL_GENESIS_HASH) {
    throw new ExternalAnchorValidationError("first checkpoint must descend from genesis");
  }
  return Object.freeze({
    checkpointType: CHECKPOINT_TYPE,
    createdAt: validateTimestamp(record.createdAt, "createdAt"),
    journalSequence,
    keyId: validateIdentifier(record.keyId, "keyId"),
    previousCheckpointHash,
    storeHeadHash: validateHash(record.storeHeadHash, "storeHeadHash"),
    storeHeadSequence: validateSafeInteger(record.storeHeadSequence, "storeHeadSequence", 0),
    storeId: validateIdentifier(record.storeId, "storeId"),
    version: CHECKPOINT_PAYLOAD_VERSION,
  });
}

export function parseProfile(value: unknown): AnchorProfile {
  if (value !== "canary" && value !== "production-observer") {
    throw new ExternalAnchorValidationError("profile must be canary or production-observer");
  }
  return value;
}

export function retentionPolicy(value: unknown): AnchorRetentionPolicy {
  if (value === "governance") return Object.freeze({ days: 30 as const, mode: value });
  if (value === "compliance") return Object.freeze({ days: 365 as const, mode: value });
  throw new ExternalAnchorValidationError("retention mode must be governance or compliance");
}

function parseRetentionEnvelope(value: unknown): AnchorRetentionPolicy {
  const record = strictRecord(value, ["days", "mode"], "external anchor retention");
  const policy = retentionPolicy(record.mode);
  if (record.days !== policy.days) {
    throw new ExternalAnchorValidationError("external anchor retention days do not match mode");
  }
  return policy;
}

export function objectKeyFor(
  profile: AnchorProfile,
  journalSequence: number,
  checkpointHash: string,
): string {
  parseProfile(profile);
  validateSafeInteger(journalSequence, "journalSequence", 1);
  validateHash(checkpointHash, "checkpointHash");
  return `anchors/v1/${profile}/${String(journalSequence).padStart(16, "0")}/${checkpointHash}.json`;
}

export function parseObjectKey(value: unknown): Readonly<{
  checkpointHash: string;
  journalSequence: number;
  profile: AnchorProfile;
}> {
  if (typeof value !== "string") {
    throw new ExternalAnchorValidationError("objectKey must be a string");
  }
  const match = OBJECT_KEY_PATTERN.exec(value);
  if (match === null)
    throw new ExternalAnchorValidationError("objectKey violates the closed schema");
  const profile = parseProfile(match[1]);
  const journalSequence = Number(match[2]);
  validateSafeInteger(journalSequence, "objectKey journalSequence", 1);
  const checkpointHash = validateHash(match[3], "objectKey checkpointHash");
  if (objectKeyFor(profile, journalSequence, checkpointHash) !== value) {
    throw new ExternalAnchorValidationError("objectKey is not canonical");
  }
  return Object.freeze({ checkpointHash, journalSequence, profile });
}

export function anchorPrefix(profile: AnchorProfile): string {
  return `anchors/v1/${parseProfile(profile)}/`;
}

export function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function parseSignature(value: unknown): string {
  if (typeof value !== "string" || !SIGNATURE_PATTERN.test(value)) {
    throw new ExternalAnchorValidationError("signature must be canonical Ed25519 base64url");
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.byteLength !== 64 || decoded.toString("base64url") !== value) {
    throw new ExternalAnchorValidationError("signature must be canonical Ed25519 base64url");
  }
  return value;
}

function deepFreezeEnvelope(envelope: ExternalAnchorEnvelope): ExternalAnchorEnvelope {
  Object.freeze(envelope.checkpoint.payload);
  Object.freeze(envelope.checkpoint);
  Object.freeze(envelope.authorization.payload.retention);
  Object.freeze(envelope.authorization.payload);
  Object.freeze(envelope.authorization);
  return Object.freeze(envelope);
}
