import {
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from "node:crypto";

import {
  canonicalJson,
  exactObject,
  sha256,
  validateHash,
  validateIdentifier,
} from "./canonical.js";
import { fail } from "./errors.js";
import {
  RECOVERY_ENVELOPE_TYPE,
  RECOVERY_ENVELOPE_VERSION,
  RELEASE_KEYCHAIN_ACCOUNT,
  RELEASE_KEYCHAIN_SERVICE,
  RELEASE_KEY_ALGORITHM,
  type RecoveryCopyIndex,
  type RecoveryEnvelopeAadV1,
  type RecoveryEnvelopeV1,
  type ReleaseKeyMaterial,
} from "./types.js";

const INNER_MAGIC = Buffer.from("RSIRKEY1", "ascii");
const PRIVATE_KEY_BYTES = 48;
const PUBLIC_KEY_BYTES = 44;
const INNER_BYTES = INNER_MAGIC.length + 1 + PRIVATE_KEY_BYTES + 32;
const SALT_BYTES = 32;
const NONCE_BYTES = 12;
const AUTHENTICATION_TAG_BYTES = 16;
const SCRYPT_N = 131_072 as const;
const SCRYPT_R = 8 as const;
const SCRYPT_P = 1 as const;
const SCRYPT_MAX_MEMORY = 192 * 1024 * 1024;
const MAX_ENVELOPE_BYTES = 16 * 1024;

export function generateReleaseKeyMaterial(): ReleaseKeyMaterial {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privateKeyPkcs8Der = Buffer.from(privateKey.export({ format: "der", type: "pkcs8" }));
  const publicKeySpkiDer = Buffer.from(publicKey.export({ format: "der", type: "spki" }));
  if (
    privateKeyPkcs8Der.length !== PRIVATE_KEY_BYTES ||
    publicKeySpkiDer.length !== PUBLIC_KEY_BYTES
  ) {
    privateKeyPkcs8Der.fill(0);
    publicKeySpkiDer.fill(0);
    fail("VERIFICATION_FAILED", "Generated release identity has an unsupported encoding");
  }
  const signerFingerprintSha256 = sha256(publicKeySpkiDer);
  return Object.freeze({
    keyId: `rsi-release-${signerFingerprintSha256.slice(0, 16)}`,
    privateKeyPkcs8Der,
    publicKeySpkiDer,
    signerFingerprintSha256,
  });
}

export function encryptRecoveryEnvelope(
  material: ReleaseKeyMaterial,
  passphrase: Buffer,
  copyIndex: RecoveryCopyIndex,
): Buffer {
  validateMaterial(material);
  validatePassphrase(passphrase);
  validateCopyIndex(copyIndex);
  const salt = randomBytes(SALT_BYTES);
  const nonce = randomBytes(NONCE_BYTES);
  const key = deriveKey(passphrase, salt);
  const inner = encodeInner(material, copyIndex);
  const aad: RecoveryEnvelopeAadV1 = Object.freeze({
    account: RELEASE_KEYCHAIN_ACCOUNT,
    algorithm: RELEASE_KEY_ALGORITHM,
    cipher: Object.freeze({
      name: "AES-256-GCM",
      nonceBase64url: nonce.toString("base64url"),
      tagBytes: AUTHENTICATION_TAG_BYTES,
    }),
    copyIndex,
    envelopeType: RECOVERY_ENVELOPE_TYPE,
    keyId: material.keyId,
    kdf: Object.freeze({
      name: "scrypt",
      n: SCRYPT_N,
      p: SCRYPT_P,
      r: SCRYPT_R,
      saltBase64url: salt.toString("base64url"),
    }),
    publicKeySpkiDerBase64url: material.publicKeySpkiDer.toString("base64url"),
    service: RELEASE_KEYCHAIN_SERVICE,
    signerFingerprintSha256: material.signerFingerprintSha256,
    version: RECOVERY_ENVELOPE_VERSION,
  });
  const aadBytes = Buffer.from(canonicalJson(aad), "utf8");
  let ciphertext = Buffer.alloc(0);
  let authenticationTag = Buffer.alloc(0);
  try {
    const cipher = createCipheriv("aes-256-gcm", key, nonce, {
      authTagLength: AUTHENTICATION_TAG_BYTES,
    });
    cipher.setAAD(aadBytes);
    ciphertext = Buffer.concat([cipher.update(inner), cipher.final()]);
    authenticationTag = cipher.getAuthTag();
    const envelope: RecoveryEnvelopeV1 = Object.freeze({
      aad,
      authenticationTagBase64url: authenticationTag.toString("base64url"),
      ciphertextBase64url: ciphertext.toString("base64url"),
    });
    const bytes = Buffer.from(canonicalJson(envelope), "utf8");
    if (bytes.length <= 0 || bytes.length > MAX_ENVELOPE_BYTES) {
      bytes.fill(0);
      fail("ENVELOPE_INVALID", "Recovery envelope exceeds its size bound");
    }
    return bytes;
  } finally {
    salt.fill(0);
    nonce.fill(0);
    key.fill(0);
    inner.fill(0);
    aadBytes.fill(0);
    ciphertext.fill(0);
    authenticationTag.fill(0);
  }
}

export function decryptRecoveryEnvelope(
  bytes: Buffer,
  passphrase: Buffer,
  expectedCopyIndex: RecoveryCopyIndex,
): ReleaseKeyMaterial {
  validatePassphrase(passphrase);
  validateCopyIndex(expectedCopyIndex);
  const envelope = parseRecoveryEnvelope(bytes);
  if (envelope.aad.copyIndex !== expectedCopyIndex) {
    fail("ENVELOPE_INVALID", "Recovery envelope copy index is invalid");
  }
  const salt = decodeBase64url(envelope.aad.kdf.saltBase64url, SALT_BYTES, "Recovery salt");
  const nonce = decodeBase64url(envelope.aad.cipher.nonceBase64url, NONCE_BYTES, "Recovery nonce");
  const tag = decodeBase64url(
    envelope.authenticationTagBase64url,
    AUTHENTICATION_TAG_BYTES,
    "Recovery authentication tag",
  );
  const ciphertext = decodeBase64url(
    envelope.ciphertextBase64url,
    INNER_BYTES,
    "Recovery ciphertext",
  );
  const key = deriveKey(passphrase, salt);
  const aadBytes = Buffer.from(canonicalJson(envelope.aad), "utf8");
  let inner = Buffer.alloc(0);
  let decrypted = Buffer.alloc(0);
  let finalized = Buffer.alloc(0);
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, nonce, {
      authTagLength: AUTHENTICATION_TAG_BYTES,
    });
    decipher.setAAD(aadBytes);
    decipher.setAuthTag(tag);
    try {
      decrypted = decipher.update(ciphertext);
      finalized = decipher.final();
      inner = Buffer.concat([decrypted, finalized]);
    } catch {
      fail("ENVELOPE_INVALID", "Recovery envelope authentication failed");
    }
    return decodeInner(inner, envelope.aad);
  } finally {
    salt.fill(0);
    nonce.fill(0);
    tag.fill(0);
    ciphertext.fill(0);
    key.fill(0);
    aadBytes.fill(0);
    inner.fill(0);
    decrypted.fill(0);
    finalized.fill(0);
  }
}

export function parseRecoveryEnvelope(bytes: Buffer): RecoveryEnvelopeV1 {
  if (!Buffer.isBuffer(bytes) || bytes.length <= 0 || bytes.length > MAX_ENVELOPE_BYTES) {
    fail("ENVELOPE_INVALID", "Recovery envelope bytes are outside their bound");
  }
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
  } catch {
    fail("ENVELOPE_INVALID", "Recovery envelope JSON is invalid");
  }
  const record = exactObject(
    value,
    ["aad", "authenticationTagBase64url", "ciphertextBase64url"],
    "Recovery envelope",
  );
  const aadRecord = exactObject(
    record.aad,
    [
      "account",
      "algorithm",
      "cipher",
      "copyIndex",
      "envelopeType",
      "keyId",
      "kdf",
      "publicKeySpkiDerBase64url",
      "service",
      "signerFingerprintSha256",
      "version",
    ],
    "Recovery envelope AAD",
  );
  const cipherRecord = exactObject(
    aadRecord.cipher,
    ["name", "nonceBase64url", "tagBytes"],
    "Recovery cipher",
  );
  const kdfRecord = exactObject(
    aadRecord.kdf,
    ["name", "n", "p", "r", "saltBase64url"],
    "Recovery KDF",
  );
  if (
    aadRecord.account !== RELEASE_KEYCHAIN_ACCOUNT ||
    aadRecord.algorithm !== RELEASE_KEY_ALGORITHM ||
    aadRecord.envelopeType !== RECOVERY_ENVELOPE_TYPE ||
    aadRecord.service !== RELEASE_KEYCHAIN_SERVICE ||
    aadRecord.version !== RECOVERY_ENVELOPE_VERSION ||
    cipherRecord.name !== "AES-256-GCM" ||
    cipherRecord.tagBytes !== AUTHENTICATION_TAG_BYTES ||
    kdfRecord.name !== "scrypt" ||
    kdfRecord.n !== SCRYPT_N ||
    kdfRecord.r !== SCRYPT_R ||
    kdfRecord.p !== SCRYPT_P
  ) {
    fail("ENVELOPE_INVALID", "Recovery envelope policy is invalid");
  }
  const copyIndex = validateCopyIndex(aadRecord.copyIndex);
  const publicKeySpkiDer = decodeBase64url(
    aadRecord.publicKeySpkiDerBase64url,
    PUBLIC_KEY_BYTES,
    "Recovery public key",
  );
  const signerFingerprintSha256 = validateHash(
    aadRecord.signerFingerprintSha256,
    "Recovery signer fingerprint",
  );
  if (sha256(publicKeySpkiDer) !== signerFingerprintSha256) {
    publicKeySpkiDer.fill(0);
    fail("ENVELOPE_INVALID", "Recovery public identity binding is invalid");
  }
  const keyId = validateIdentifier(aadRecord.keyId, "Recovery key identifier");
  if (keyId !== `rsi-release-${signerFingerprintSha256.slice(0, 16)}`) {
    publicKeySpkiDer.fill(0);
    fail("ENVELOPE_INVALID", "Recovery key identifier does not match its fingerprint");
  }
  publicKeySpkiDer.fill(0);
  const aad: RecoveryEnvelopeAadV1 = Object.freeze({
    account: RELEASE_KEYCHAIN_ACCOUNT,
    algorithm: RELEASE_KEY_ALGORITHM,
    cipher: Object.freeze({
      name: "AES-256-GCM",
      nonceBase64url: validateBase64urlString(
        cipherRecord.nonceBase64url,
        NONCE_BYTES,
        "Recovery nonce",
      ),
      tagBytes: AUTHENTICATION_TAG_BYTES,
    }),
    copyIndex,
    envelopeType: RECOVERY_ENVELOPE_TYPE,
    keyId,
    kdf: Object.freeze({
      name: "scrypt",
      n: SCRYPT_N,
      p: SCRYPT_P,
      r: SCRYPT_R,
      saltBase64url: validateBase64urlString(kdfRecord.saltBase64url, SALT_BYTES, "Recovery salt"),
    }),
    publicKeySpkiDerBase64url: validateBase64urlString(
      aadRecord.publicKeySpkiDerBase64url,
      PUBLIC_KEY_BYTES,
      "Recovery public key",
    ),
    service: RELEASE_KEYCHAIN_SERVICE,
    signerFingerprintSha256,
    version: RECOVERY_ENVELOPE_VERSION,
  });
  const envelope: RecoveryEnvelopeV1 = Object.freeze({
    aad,
    authenticationTagBase64url: validateBase64urlString(
      record.authenticationTagBase64url,
      AUTHENTICATION_TAG_BYTES,
      "Recovery authentication tag",
    ),
    ciphertextBase64url: validateBase64urlString(
      record.ciphertextBase64url,
      INNER_BYTES,
      "Recovery ciphertext",
    ),
  });
  if (new TextDecoder().decode(bytes) !== canonicalJson(envelope)) {
    fail("ENVELOPE_INVALID", "Recovery envelope is not canonical");
  }
  return envelope;
}

export function encodeKeychainValue(privateKeyPkcs8Der: Buffer): Buffer {
  if (!Buffer.isBuffer(privateKeyPkcs8Der) || privateKeyPkcs8Der.length !== PRIVATE_KEY_BYTES) {
    fail("VERIFICATION_FAILED", "Release private-key encoding is invalid");
  }
  return encodeBase64urlWithoutString(privateKeyPkcs8Der);
}

function encodeInner(material: ReleaseKeyMaterial, copyIndex: RecoveryCopyIndex): Buffer {
  const inner = Buffer.alloc(INNER_BYTES);
  let offset = 0;
  INNER_MAGIC.copy(inner, offset);
  offset += INNER_MAGIC.length;
  inner[offset] = copyIndex;
  offset += 1;
  material.privateKeyPkcs8Der.copy(inner, offset);
  offset += PRIVATE_KEY_BYTES;
  Buffer.from(material.signerFingerprintSha256, "hex").copy(inner, offset);
  return inner;
}

function decodeInner(inner: Buffer, aad: RecoveryEnvelopeAadV1): ReleaseKeyMaterial {
  if (
    inner.length !== INNER_BYTES ||
    !timingSafeEqual(inner.subarray(0, INNER_MAGIC.length), INNER_MAGIC) ||
    inner[INNER_MAGIC.length] !== aad.copyIndex
  ) {
    fail("ENVELOPE_INVALID", "Recovery plaintext framing is invalid");
  }
  const privateKeyPkcs8Der = Buffer.from(
    inner.subarray(INNER_MAGIC.length + 1, INNER_MAGIC.length + 1 + PRIVATE_KEY_BYTES),
  );
  const embeddedFingerprint = inner.subarray(INNER_MAGIC.length + 1 + PRIVATE_KEY_BYTES);
  const expectedFingerprint = Buffer.from(aad.signerFingerprintSha256, "hex");
  if (!timingSafeEqual(embeddedFingerprint, expectedFingerprint)) {
    privateKeyPkcs8Der.fill(0);
    expectedFingerprint.fill(0);
    fail("ENVELOPE_INVALID", "Recovery plaintext identity binding is invalid");
  }
  expectedFingerprint.fill(0);
  let publicKeySpkiDer: Buffer;
  try {
    const privateKey = createPrivateKey({ format: "der", key: privateKeyPkcs8Der, type: "pkcs8" });
    if (privateKey.asymmetricKeyType !== "ed25519") throw new TypeError("wrong key type");
    publicKeySpkiDer = Buffer.from(
      createPublicKey(privateKey).export({ format: "der", type: "spki" }),
    );
  } catch {
    privateKeyPkcs8Der.fill(0);
    fail("ENVELOPE_INVALID", "Recovered release key is invalid");
  }
  const expectedPublic = decodeBase64url(
    aad.publicKeySpkiDerBase64url,
    PUBLIC_KEY_BYTES,
    "Recovery public key",
  );
  if (
    !timingSafeEqual(publicKeySpkiDer, expectedPublic) ||
    sha256(publicKeySpkiDer) !== aad.signerFingerprintSha256
  ) {
    privateKeyPkcs8Der.fill(0);
    publicKeySpkiDer.fill(0);
    expectedPublic.fill(0);
    fail("ENVELOPE_INVALID", "Recovered release identity does not match its envelope");
  }
  expectedPublic.fill(0);
  return Object.freeze({
    keyId: aad.keyId,
    privateKeyPkcs8Der,
    publicKeySpkiDer,
    signerFingerprintSha256: aad.signerFingerprintSha256,
  });
}

function validateMaterial(material: ReleaseKeyMaterial): void {
  if (
    material.privateKeyPkcs8Der.length !== PRIVATE_KEY_BYTES ||
    material.publicKeySpkiDer.length !== PUBLIC_KEY_BYTES ||
    validateHash(material.signerFingerprintSha256, "Release signer fingerprint") !==
      sha256(material.publicKeySpkiDer) ||
    validateIdentifier(material.keyId, "Release key identifier") !==
      `rsi-release-${material.signerFingerprintSha256.slice(0, 16)}`
  ) {
    fail("VERIFICATION_FAILED", "Release key material is invalid");
  }
}

export function validatePassphrase(value: Buffer): void {
  if (
    !Buffer.isBuffer(value) ||
    value.buffer instanceof SharedArrayBuffer ||
    value.length < 24 ||
    value.length > 256 ||
    new Set(value).size < 8
  ) {
    fail("PASSPHRASE_REFUSED", "Recovery passphrase does not satisfy the fixed policy");
  }
}

function deriveKey(passphrase: Buffer, salt: Buffer): Buffer {
  try {
    return scryptSync(passphrase, salt, 32, {
      N: SCRYPT_N,
      maxmem: SCRYPT_MAX_MEMORY,
      p: SCRYPT_P,
      r: SCRYPT_R,
    });
  } catch {
    fail("ENVELOPE_INVALID", "Recovery key derivation failed");
  }
}

function validateCopyIndex(value: unknown): RecoveryCopyIndex {
  if (value !== 1 && value !== 2) fail("ENVELOPE_INVALID", "Recovery copy index is invalid");
  return value;
}

function validateBase64urlString(value: unknown, length: number, label: string): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/u.test(value)) {
    fail("ENVELOPE_INVALID", `${label} encoding is invalid`);
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length !== length || decoded.toString("base64url") !== value) {
    decoded.fill(0);
    fail("ENVELOPE_INVALID", `${label} encoding is invalid`);
  }
  decoded.fill(0);
  return value;
}

function decodeBase64url(value: unknown, length: number, label: string): Buffer {
  const validated = validateBase64urlString(value, length, label);
  return Buffer.from(validated, "base64url");
}

function encodeBase64urlWithoutString(value: Buffer): Buffer {
  const alphabet = Buffer.from(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    "ascii",
  );
  const output = Buffer.alloc(Math.ceil((value.length * 4) / 3));
  let inputOffset = 0;
  let outputOffset = 0;
  while (inputOffset + 2 < value.length) {
    const word =
      (value[inputOffset]! << 16) | (value[inputOffset + 1]! << 8) | value[inputOffset + 2]!;
    output[outputOffset++] = alphabet[(word >>> 18) & 63]!;
    output[outputOffset++] = alphabet[(word >>> 12) & 63]!;
    output[outputOffset++] = alphabet[(word >>> 6) & 63]!;
    output[outputOffset++] = alphabet[word & 63]!;
    inputOffset += 3;
  }
  if (inputOffset < value.length) {
    const first = value[inputOffset]!;
    const second = inputOffset + 1 < value.length ? value[inputOffset + 1]! : 0;
    const word = (first << 16) | (second << 8);
    output[outputOffset++] = alphabet[(word >>> 18) & 63]!;
    output[outputOffset++] = alphabet[(word >>> 12) & 63]!;
    if (inputOffset + 1 < value.length) output[outputOffset++] = alphabet[(word >>> 6) & 63]!;
  }
  alphabet.fill(0);
  if (outputOffset !== output.length) {
    output.fill(0);
    fail("VERIFICATION_FAILED", "Release key encoding failed");
  }
  return output;
}
