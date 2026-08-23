import {
  createHash,
  createPublicKey,
  timingSafeEqual,
  verify as verifyEd25519,
  type KeyObject,
} from "node:crypto";
import { types as utilTypes } from "node:util";

import {
  exactObject,
  sha256,
  validateGitHash,
  validateHash,
  validateIdentifier,
} from "./canonical.js";
import { fail } from "./errors.js";
import { FOUNDATION_RELEASE_VERSION, FOUNDATION_TAG } from "./types.js";

export const FOUNDATION_OBJECTIVE_EVIDENCE_STATE = "FOUNDATION_BUILT" as const;
export const FOUNDATION_TAG_SIGNATURE_NAMESPACE = "git" as const;
export const FOUNDATION_TAG_SIGNATURE_HASH = "sha512" as const;

const TAGGER = "RSI Foundation Release <release@rsi.local> 0 +0000";
const MESSAGE_TITLE = "RSI foundation release evidence v1";
const SSH_ED25519 = "ssh-ed25519";
const SSHSIG_MAGIC = Buffer.from("SSHSIG", "ascii");
const SSHSIG_VERSION = 1;
const ARMOR_BEGIN = "-----BEGIN SSH SIGNATURE-----";
const ARMOR_END = "-----END SSH SIGNATURE-----";
const ARMOR_LINE_LENGTH = 70;
const MAX_TAG_OBJECT_BYTES = 64 * 1024;

export interface FoundationTagSignerV1 {
  readonly keyId: string;
  /** Canonical DER-encoded Ed25519 SubjectPublicKeyInfo. */
  readonly publicKeySpkiDer: Uint8Array;
  /** A one-shot callback. It receives the complete OpenSSH SSHSIG signed-data structure. */
  readonly sign: (message: Uint8Array) => Uint8Array | Promise<Uint8Array>;
}

export interface CreateFoundationSignedTagOptionsV1 {
  readonly archiveSha256: string;
  readonly ciEvidenceSha256: string;
  readonly manifestSha256: string;
  readonly readinessConclusionSha256: string;
  readonly signer: FoundationTagSignerV1;
  readonly targetCommit: string;
}

export interface VerifyFoundationSignedTagOptionsV1 {
  readonly archiveSha256: string;
  readonly ciEvidenceSha256: string;
  readonly manifestSha256: string;
  readonly readinessConclusionSha256: string;
  readonly publicKeySpkiDer: Uint8Array;
  readonly signerFingerprintSha256: string;
  readonly signerKeyId: string;
  readonly targetCommit: string;
}

export interface FoundationTagVerificationReportV1 {
  readonly archiveSha256: string;
  readonly ciEvidenceSha256: string;
  /** Git object ID: hash over `tag <length>\0` followed by the complete tag bytes. */
  readonly gitObjectSha1: string;
  /** Git object ID for a SHA-256-format Git repository. */
  readonly gitObjectSha256: string;
  readonly manifestSha256: string;
  readonly readinessConclusionSha256: string;
  readonly objectiveEvidenceState: typeof FOUNDATION_OBJECTIVE_EVIDENCE_STATE;
  readonly releaseVersion: typeof FOUNDATION_RELEASE_VERSION;
  readonly signatureAlgorithm: typeof SSH_ED25519;
  readonly signatureHash: typeof FOUNDATION_TAG_SIGNATURE_HASH;
  readonly signatureNamespace: typeof FOUNDATION_TAG_SIGNATURE_NAMESPACE;
  readonly signerFingerprintSha256: string;
  readonly signerKeyId: string;
  readonly tagName: typeof FOUNDATION_TAG;
  readonly tagObjectSizeBytes: number;
  readonly tagObjectSha256: string;
  readonly targetCommit: string;
  readonly unsignedPayloadSha256: string;
}

export interface FoundationSignedTagArtifactV1 {
  /** Complete annotated-tag content, suitable for `git hash-object -t tag --stdin`. */
  readonly tagObjectBytes: Uint8Array;
  readonly verification: FoundationTagVerificationReportV1;
}

interface ParsedSshSignature {
  readonly publicKeyBlob: Buffer;
  readonly signature: Buffer;
}

interface ImportedPublicKey {
  readonly key: KeyObject;
  readonly openSshBlob: Buffer;
  readonly spkiDer: Buffer;
}

/**
 * Creates, but never installs or publishes, the native Git-verifiable `foundation-v1` tag object.
 * The signer callback is invoked exactly once and the returned signature is verified before return.
 */
export async function createFoundationSignedTagArtifact(
  optionsValue: CreateFoundationSignedTagOptionsV1,
): Promise<FoundationSignedTagArtifactV1> {
  const options = exactObject(
    optionsValue,
    [
      "archiveSha256",
      "ciEvidenceSha256",
      "manifestSha256",
      "readinessConclusionSha256",
      "signer",
      "targetCommit",
    ],
    "Foundation signed-tag options",
  );
  const archiveSha256 = validateHash(options.archiveSha256, "Foundation archive SHA-256");
  const ciEvidenceSha256 = validateHash(options.ciEvidenceSha256, "Foundation CI evidence SHA-256");
  const manifestSha256 = validateHash(options.manifestSha256, "Foundation manifest SHA-256");
  const readinessConclusionSha256 = validateHash(
    options.readinessConclusionSha256,
    "Foundation readiness conclusion SHA-256",
  );
  const targetCommit = validateGitHash(options.targetCommit, "Foundation target commit");
  const signerRecord = exactObject(
    options.signer,
    ["keyId", "publicKeySpkiDer", "sign"],
    "Foundation tag signer",
  );
  const signerKeyId = validateIdentifier(signerRecord.keyId, "Foundation signer key ID");
  const signerCallback = signerRecord.sign;
  if (typeof signerCallback !== "function") {
    fail("INPUT_INVALID", "Foundation tag signer callback is invalid");
  }

  const publicKey = importEd25519PublicKey(
    signerRecord.publicKeySpkiDer,
    "Foundation signer public key",
  );
  const signerFingerprintSha256 = sha256(publicKey.spkiDer);
  assertKeyIdMatchesFingerprint(signerKeyId, signerFingerprintSha256);

  const unsignedPayload = Buffer.from(
    encodeUnsignedTagPayload({
      archiveSha256,
      ciEvidenceSha256,
      manifestSha256,
      readinessConclusionSha256,
      signerFingerprintSha256,
      signerKeyId,
      targetCommit,
    }),
    "utf8",
  );
  const signedData = encodeSshSigSignedData(unsignedPayload);
  let signature: Buffer | undefined;
  try {
    let returnedSignature: Uint8Array;
    try {
      // Deliberately no retry or fallback: this is the sole signature capability invocation.
      returnedSignature = await (
        signerCallback as (message: Uint8Array) => Uint8Array | Promise<Uint8Array>
      )(Uint8Array.from(signedData));
    } catch {
      fail("CUSTODY_FAILED", "Foundation tag signer failed");
    }
    signature = copySignature(returnedSignature, "CUSTODY_FAILED");
    if (!verifyEd25519(null, signedData, publicKey.key, signature)) {
      fail("CUSTODY_FAILED", "Foundation tag signer returned an invalid signature");
    }
    const envelope = encodeSshSigEnvelope(publicKey.openSshBlob, signature);
    const tagObjectBytes = Buffer.concat([
      unsignedPayload,
      Buffer.from(armorSshSig(envelope), "ascii"),
    ]);
    if (tagObjectBytes.length > MAX_TAG_OBJECT_BYTES) {
      fail("INPUT_INVALID", "Foundation tag object is too large");
    }
    const verification = verifyFoundationSignedTagArtifact(tagObjectBytes, {
      archiveSha256,
      ciEvidenceSha256,
      manifestSha256,
      readinessConclusionSha256,
      publicKeySpkiDer: publicKey.spkiDer,
      signerFingerprintSha256,
      signerKeyId,
      targetCommit,
    });
    return Object.freeze({
      tagObjectBytes: Uint8Array.from(tagObjectBytes),
      verification,
    });
  } finally {
    signature?.fill(0);
    signedData.fill(0);
    unsignedPayload.fill(0);
    publicKey.openSshBlob.fill(0);
    publicKey.spkiDer.fill(0);
  }
}

/** Strictly parses and cryptographically verifies a complete `foundation-v1` tag object. */
export function verifyFoundationSignedTagArtifact(
  tagObjectBytesValue: Uint8Array,
  optionsValue: VerifyFoundationSignedTagOptionsV1,
): FoundationTagVerificationReportV1 {
  const options = exactObject(
    optionsValue,
    [
      "archiveSha256",
      "ciEvidenceSha256",
      "manifestSha256",
      "readinessConclusionSha256",
      "publicKeySpkiDer",
      "signerFingerprintSha256",
      "signerKeyId",
      "targetCommit",
    ],
    "Foundation tag verification options",
  );
  const expectedArchiveSha256 = validateHash(options.archiveSha256, "Expected archive SHA-256");
  const expectedCiEvidenceSha256 = validateHash(
    options.ciEvidenceSha256,
    "Expected CI evidence SHA-256",
  );
  const expectedManifestSha256 = validateHash(options.manifestSha256, "Expected manifest SHA-256");
  const expectedReadinessConclusionSha256 = validateHash(
    options.readinessConclusionSha256,
    "Expected readiness conclusion SHA-256",
  );
  const expectedSignerFingerprint = validateHash(
    options.signerFingerprintSha256,
    "Expected signer fingerprint",
  );
  const expectedSignerKeyId = validateIdentifier(options.signerKeyId, "Expected signer key ID");
  const expectedTargetCommit = validateGitHash(options.targetCommit, "Expected target commit");
  assertKeyIdMatchesFingerprint(expectedSignerKeyId, expectedSignerFingerprint);
  const publicKey = importEd25519PublicKey(
    options.publicKeySpkiDer,
    "Expected Foundation signer public key",
  );
  const actualPublicKeyFingerprint = sha256(publicKey.spkiDer);
  if (actualPublicKeyFingerprint !== expectedSignerFingerprint) {
    fail("VERIFICATION_FAILED", "Foundation tag signer fingerprint does not match the trusted key");
  }

  const tagObjectBytes = copyTagObjectBytes(tagObjectBytesValue);
  try {
    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(tagObjectBytes);
    } catch {
      fail("VERIFICATION_FAILED", "Foundation tag object is not valid UTF-8");
    }
    const signatureOffset = text.indexOf(ARMOR_BEGIN);
    if (
      signatureOffset <= 0 ||
      text.lastIndexOf(ARMOR_BEGIN) !== signatureOffset ||
      !text.slice(0, signatureOffset).endsWith("\n")
    ) {
      fail("VERIFICATION_FAILED", "Foundation tag signature boundary is invalid");
    }
    const unsignedText = text.slice(0, signatureOffset);
    const armor = text.slice(signatureOffset);
    const parsed = parseUnsignedTagPayload(unsignedText);
    assertBinding(parsed.targetCommit, expectedTargetCommit, "target commit");
    assertBinding(parsed.archiveSha256, expectedArchiveSha256, "archive SHA-256");
    assertBinding(parsed.ciEvidenceSha256, expectedCiEvidenceSha256, "CI evidence SHA-256");
    assertBinding(parsed.manifestSha256, expectedManifestSha256, "manifest SHA-256");
    assertBinding(
      parsed.readinessConclusionSha256,
      expectedReadinessConclusionSha256,
      "readiness conclusion SHA-256",
    );
    assertBinding(parsed.signerFingerprintSha256, expectedSignerFingerprint, "signer fingerprint");
    assertBinding(parsed.signerKeyId, expectedSignerKeyId, "signer key ID");

    const canonicalUnsigned = encodeUnsignedTagPayload(parsed);
    if (canonicalUnsigned !== unsignedText) {
      fail("VERIFICATION_FAILED", "Foundation tag payload is not canonical");
    }
    const envelope = decodeCanonicalArmor(armor);
    const parsedSignature = parseSshSigEnvelope(envelope);
    if (!equalBytes(parsedSignature.publicKeyBlob, publicKey.openSshBlob)) {
      fail("VERIFICATION_FAILED", "Foundation tag signature embeds an unexpected public key");
    }
    const unsignedPayload = Buffer.from(unsignedText, "utf8");
    const signedData = encodeSshSigSignedData(unsignedPayload);
    try {
      if (!verifyEd25519(null, signedData, publicKey.key, parsedSignature.signature)) {
        fail("VERIFICATION_FAILED", "Foundation tag SSH signature is invalid");
      }
    } finally {
      signedData.fill(0);
      unsignedPayload.fill(0);
      parsedSignature.signature.fill(0);
      parsedSignature.publicKeyBlob.fill(0);
      envelope.fill(0);
    }

    const report: FoundationTagVerificationReportV1 = {
      archiveSha256: parsed.archiveSha256,
      ciEvidenceSha256: parsed.ciEvidenceSha256,
      gitObjectSha1: gitObjectHash("sha1", tagObjectBytes),
      gitObjectSha256: gitObjectHash("sha256", tagObjectBytes),
      manifestSha256: parsed.manifestSha256,
      readinessConclusionSha256: parsed.readinessConclusionSha256,
      objectiveEvidenceState: FOUNDATION_OBJECTIVE_EVIDENCE_STATE,
      releaseVersion: FOUNDATION_RELEASE_VERSION,
      signatureAlgorithm: SSH_ED25519,
      signatureHash: FOUNDATION_TAG_SIGNATURE_HASH,
      signatureNamespace: FOUNDATION_TAG_SIGNATURE_NAMESPACE,
      signerFingerprintSha256: parsed.signerFingerprintSha256,
      signerKeyId: parsed.signerKeyId,
      tagName: FOUNDATION_TAG,
      tagObjectSizeBytes: tagObjectBytes.length,
      tagObjectSha256: sha256(tagObjectBytes),
      targetCommit: parsed.targetCommit,
      unsignedPayloadSha256: sha256(unsignedText),
    };
    return Object.freeze(report);
  } finally {
    tagObjectBytes.fill(0);
    publicKey.openSshBlob.fill(0);
    publicKey.spkiDer.fill(0);
  }
}

/** Returns the canonical OpenSSH public-key text used by Git allowed-signers files. */
export function encodeFoundationOpenSshPublicKey(publicKeySpkiDer: Uint8Array): string {
  const imported = importEd25519PublicKey(publicKeySpkiDer, "Foundation public key");
  try {
    return `${SSH_ED25519} ${imported.openSshBlob.toString("base64")}`;
  } finally {
    imported.openSshBlob.fill(0);
    imported.spkiDer.fill(0);
  }
}

function encodeUnsignedTagPayload(bindings: {
  readonly archiveSha256: string;
  readonly ciEvidenceSha256: string;
  readonly manifestSha256: string;
  readonly readinessConclusionSha256: string;
  readonly signerFingerprintSha256: string;
  readonly signerKeyId: string;
  readonly targetCommit: string;
}): string {
  return [
    `object ${bindings.targetCommit}`,
    "type commit",
    `tag ${FOUNDATION_TAG}`,
    `tagger ${TAGGER}`,
    "",
    MESSAGE_TITLE,
    "",
    `archive-sha256: ${bindings.archiveSha256}`,
    `ci-evidence-sha256: ${bindings.ciEvidenceSha256}`,
    `manifest-sha256: ${bindings.manifestSha256}`,
    `objective-evidence-state: ${FOUNDATION_OBJECTIVE_EVIDENCE_STATE}`,
    `readiness-conclusion-sha256: ${bindings.readinessConclusionSha256}`,
    `release-version: ${FOUNDATION_RELEASE_VERSION}`,
    `signer-fingerprint-sha256: ${bindings.signerFingerprintSha256}`,
    `signer-key-id: ${bindings.signerKeyId}`,
    "",
  ].join("\n");
}

function parseUnsignedTagPayload(unsignedText: string): {
  readonly archiveSha256: string;
  readonly ciEvidenceSha256: string;
  readonly manifestSha256: string;
  readonly readinessConclusionSha256: string;
  readonly signerFingerprintSha256: string;
  readonly signerKeyId: string;
  readonly targetCommit: string;
} {
  const lines = unsignedText.split("\n");
  if (
    lines.length !== 16 ||
    lines[1] !== "type commit" ||
    lines[2] !== `tag ${FOUNDATION_TAG}` ||
    lines[3] !== `tagger ${TAGGER}` ||
    lines[4] !== "" ||
    lines[5] !== MESSAGE_TITLE ||
    lines[6] !== "" ||
    lines[10] !== `objective-evidence-state: ${FOUNDATION_OBJECTIVE_EVIDENCE_STATE}` ||
    lines[12] !== `release-version: ${FOUNDATION_RELEASE_VERSION}` ||
    lines[15] !== ""
  ) {
    fail("VERIFICATION_FAILED", "Foundation tag payload structure is invalid");
  }
  const targetCommit = parsePrefixedGitHash(lines[0], "object ", "Foundation tag target commit");
  const archiveSha256 = parsePrefixedHash(
    lines[7],
    "archive-sha256: ",
    "Foundation tag archive SHA-256",
  );
  const ciEvidenceSha256 = parsePrefixedHash(
    lines[8],
    "ci-evidence-sha256: ",
    "Foundation tag CI evidence SHA-256",
  );
  const manifestSha256 = parsePrefixedHash(
    lines[9],
    "manifest-sha256: ",
    "Foundation tag manifest SHA-256",
  );
  const readinessConclusionSha256 = parsePrefixedHash(
    lines[11],
    "readiness-conclusion-sha256: ",
    "Foundation tag readiness conclusion SHA-256",
  );
  const signerFingerprintSha256 = parsePrefixedHash(
    lines[13],
    "signer-fingerprint-sha256: ",
    "Foundation tag signer fingerprint",
  );
  const signerKeyId = parsePrefixedIdentifier(
    lines[14],
    "signer-key-id: ",
    "Foundation tag signer key ID",
  );
  assertKeyIdMatchesFingerprint(signerKeyId, signerFingerprintSha256);
  return Object.freeze({
    archiveSha256,
    ciEvidenceSha256,
    manifestSha256,
    readinessConclusionSha256,
    signerFingerprintSha256,
    signerKeyId,
    targetCommit,
  });
}

function encodeSshSigSignedData(unsignedPayload: Uint8Array): Buffer {
  const messageHash = createHash(FOUNDATION_TAG_SIGNATURE_HASH).update(unsignedPayload).digest();
  try {
    return Buffer.concat([
      SSHSIG_MAGIC,
      sshString(Buffer.from(FOUNDATION_TAG_SIGNATURE_NAMESPACE, "ascii")),
      sshString(Buffer.alloc(0)),
      sshString(Buffer.from(FOUNDATION_TAG_SIGNATURE_HASH, "ascii")),
      sshString(messageHash),
    ]);
  } finally {
    messageHash.fill(0);
  }
}

function encodeSshSigEnvelope(publicKeyBlob: Uint8Array, signature: Uint8Array): Buffer {
  const signatureBlob = Buffer.concat([
    sshString(Buffer.from(SSH_ED25519, "ascii")),
    sshString(signature),
  ]);
  return Buffer.concat([
    SSHSIG_MAGIC,
    uint32(SSHSIG_VERSION),
    sshString(publicKeyBlob),
    sshString(Buffer.from(FOUNDATION_TAG_SIGNATURE_NAMESPACE, "ascii")),
    sshString(Buffer.alloc(0)),
    sshString(Buffer.from(FOUNDATION_TAG_SIGNATURE_HASH, "ascii")),
    sshString(signatureBlob),
  ]);
}

function parseSshSigEnvelope(envelope: Buffer): ParsedSshSignature {
  const reader = new SshReader(envelope);
  if (!equalBytes(reader.readRaw(SSHSIG_MAGIC.length), SSHSIG_MAGIC)) {
    fail("VERIFICATION_FAILED", "Foundation tag SSH signature magic is invalid");
  }
  if (reader.readUint32() !== SSHSIG_VERSION) {
    fail("VERIFICATION_FAILED", "Foundation tag SSH signature version is unsupported");
  }
  const publicKeyBlob = reader.readString();
  const namespace = reader.readString();
  const reserved = reader.readString();
  const hashAlgorithm = reader.readString();
  const signatureBlob = reader.readString();
  reader.assertFinished();
  if (
    !equalBytes(namespace, Buffer.from(FOUNDATION_TAG_SIGNATURE_NAMESPACE, "ascii")) ||
    reserved.length !== 0 ||
    !equalBytes(hashAlgorithm, Buffer.from(FOUNDATION_TAG_SIGNATURE_HASH, "ascii"))
  ) {
    fail("VERIFICATION_FAILED", "Foundation tag SSH signature parameters are invalid");
  }
  const keyReader = new SshReader(publicKeyBlob);
  if (
    !equalBytes(keyReader.readString(), Buffer.from(SSH_ED25519, "ascii")) ||
    keyReader.readString().length !== 32
  ) {
    fail("VERIFICATION_FAILED", "Foundation tag SSH public key is invalid");
  }
  keyReader.assertFinished();
  const signatureReader = new SshReader(signatureBlob);
  if (!equalBytes(signatureReader.readString(), Buffer.from(SSH_ED25519, "ascii"))) {
    fail("VERIFICATION_FAILED", "Foundation tag SSH signature algorithm is invalid");
  }
  const signature = signatureReader.readString();
  signatureReader.assertFinished();
  if (signature.length !== 64) {
    fail("VERIFICATION_FAILED", "Foundation tag SSH signature length is invalid");
  }
  return Object.freeze({
    publicKeyBlob: Buffer.from(publicKeyBlob),
    signature: Buffer.from(signature),
  });
}

function armorSshSig(envelope: Uint8Array): string {
  const base64 = Buffer.from(envelope).toString("base64");
  const lines: string[] = [];
  for (let offset = 0; offset < base64.length; offset += ARMOR_LINE_LENGTH) {
    lines.push(base64.slice(offset, offset + ARMOR_LINE_LENGTH));
  }
  return `${ARMOR_BEGIN}\n${lines.join("\n")}\n${ARMOR_END}\n`;
}

function decodeCanonicalArmor(armor: string): Buffer {
  const lines = armor.split("\n");
  if (
    lines.length < 4 ||
    lines[0] !== ARMOR_BEGIN ||
    lines.at(-2) !== ARMOR_END ||
    lines.at(-1) !== ""
  ) {
    fail("VERIFICATION_FAILED", "Foundation tag SSH signature armor is invalid");
  }
  const encodedLines = lines.slice(1, -2);
  if (
    encodedLines.length === 0 ||
    encodedLines.some(
      (line, index) =>
        !/^[A-Za-z0-9+/]+={0,2}$/u.test(line) ||
        line.length > ARMOR_LINE_LENGTH ||
        (index < encodedLines.length - 1 && line.length !== ARMOR_LINE_LENGTH),
    )
  ) {
    fail("VERIFICATION_FAILED", "Foundation tag SSH signature armor is not canonical");
  }
  const encoded = encodedLines.join("");
  const envelope = Buffer.from(encoded, "base64");
  if (
    envelope.length === 0 ||
    envelope.toString("base64") !== encoded ||
    armorSshSig(envelope) !== armor
  ) {
    envelope.fill(0);
    fail("VERIFICATION_FAILED", "Foundation tag SSH signature armor is not canonical");
  }
  return envelope;
}

function importEd25519PublicKey(value: unknown, label: string): ImportedPublicKey {
  if (!(value instanceof Uint8Array) || utilTypes.isProxy(value) || value.byteLength > 512) {
    fail("INPUT_INVALID", `${label} is invalid`);
  }
  const spkiDer = Buffer.from(value);
  let key: KeyObject;
  try {
    key = createPublicKey({ format: "der", key: spkiDer, type: "spki" });
  } catch {
    spkiDer.fill(0);
    fail("INPUT_INVALID", `${label} is invalid`);
  }
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") {
    spkiDer.fill(0);
    fail("INPUT_INVALID", `${label} must be an Ed25519 public key`);
  }
  const canonicalSpki = key.export({ format: "der", type: "spki" });
  if (!equalBytes(spkiDer, canonicalSpki)) {
    spkiDer.fill(0);
    canonicalSpki.fill(0);
    fail("INPUT_INVALID", `${label} is not canonical`);
  }
  spkiDer.fill(0);
  const jwk = key.export({ format: "jwk" });
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") {
    canonicalSpki.fill(0);
    fail("INPUT_INVALID", `${label} is invalid`);
  }
  const rawPublicKey = Buffer.from(jwk.x, "base64url");
  if (rawPublicKey.length !== 32 || rawPublicKey.toString("base64url") !== jwk.x) {
    canonicalSpki.fill(0);
    rawPublicKey.fill(0);
    fail("INPUT_INVALID", `${label} is invalid`);
  }
  const openSshBlob = Buffer.concat([
    sshString(Buffer.from(SSH_ED25519, "ascii")),
    sshString(rawPublicKey),
  ]);
  rawPublicKey.fill(0);
  return Object.freeze({ key, openSshBlob, spkiDer: canonicalSpki });
}

function copyTagObjectBytes(value: unknown): Buffer {
  if (
    !(value instanceof Uint8Array) ||
    utilTypes.isProxy(value) ||
    value.byteLength === 0 ||
    value.byteLength > MAX_TAG_OBJECT_BYTES
  ) {
    fail("VERIFICATION_FAILED", "Foundation tag object bytes are invalid");
  }
  return Buffer.from(value);
}

function copySignature(value: unknown, code: "CUSTODY_FAILED"): Buffer {
  if (!(value instanceof Uint8Array) || utilTypes.isProxy(value) || value.byteLength !== 64) {
    fail(code, "Foundation tag signer returned an invalid signature");
  }
  return Buffer.from(value);
}

function sshString(value: Uint8Array): Buffer {
  return Buffer.concat([uint32(value.byteLength), Buffer.from(value)]);
}

function uint32(value: number): Buffer {
  const result = Buffer.allocUnsafe(4);
  result.writeUInt32BE(value, 0);
  return result;
}

class SshReader {
  readonly #bytes: Buffer;
  #offset = 0;

  constructor(bytes: Buffer) {
    this.#bytes = bytes;
  }

  readUint32(): number {
    if (this.#offset + 4 > this.#bytes.length) {
      fail("VERIFICATION_FAILED", "Foundation tag SSH signature is truncated");
    }
    const value = this.#bytes.readUInt32BE(this.#offset);
    this.#offset += 4;
    return value;
  }

  readRaw(length: number): Buffer {
    if (length < 0 || this.#offset + length > this.#bytes.length) {
      fail("VERIFICATION_FAILED", "Foundation tag SSH signature is truncated");
    }
    const value = this.#bytes.subarray(this.#offset, this.#offset + length);
    this.#offset += length;
    return value;
  }

  readString(): Buffer {
    const length = this.readUint32();
    return this.readRaw(length);
  }

  assertFinished(): void {
    if (this.#offset !== this.#bytes.length) {
      fail("VERIFICATION_FAILED", "Foundation tag SSH signature has trailing data");
    }
  }
}

function parsePrefixedHash(value: string | undefined, prefix: string, label: string): string {
  if (value === undefined || !value.startsWith(prefix)) {
    fail("VERIFICATION_FAILED", `${label} is missing`);
  }
  try {
    return validateHash(value.slice(prefix.length), label);
  } catch {
    fail("VERIFICATION_FAILED", `${label} is invalid`);
  }
}

function parsePrefixedGitHash(value: string | undefined, prefix: string, label: string): string {
  if (value === undefined || !value.startsWith(prefix)) {
    fail("VERIFICATION_FAILED", `${label} is missing`);
  }
  try {
    return validateGitHash(value.slice(prefix.length), label);
  } catch {
    fail("VERIFICATION_FAILED", `${label} is invalid`);
  }
}

function parsePrefixedIdentifier(value: string | undefined, prefix: string, label: string): string {
  if (value === undefined || !value.startsWith(prefix)) {
    fail("VERIFICATION_FAILED", `${label} is missing`);
  }
  try {
    return validateIdentifier(value.slice(prefix.length), label);
  } catch {
    fail("VERIFICATION_FAILED", `${label} is invalid`);
  }
}

function assertKeyIdMatchesFingerprint(keyId: string, fingerprint: string): void {
  if (keyId !== `rsi-release-${fingerprint.slice(0, 16)}`) {
    fail("INPUT_INVALID", "Foundation signer key ID does not match its fingerprint");
  }
}

function assertBinding(actual: string, expected: string, label: string): void {
  if (actual !== expected) {
    fail("VERIFICATION_FAILED", `Foundation tag ${label} binding is invalid`);
  }
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && timingSafeEqual(left, right);
}

function gitObjectHash(algorithm: "sha1" | "sha256", bytes: Uint8Array): string {
  const header = Buffer.from(`tag ${bytes.byteLength}\0`, "ascii");
  return createHash(algorithm).update(header).update(bytes).digest("hex");
}
