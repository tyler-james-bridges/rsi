import { createHash, timingSafeEqual } from "node:crypto";

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
import {
  decryptRecoveryEnvelope,
  encodeKeychainValue,
  encryptRecoveryEnvelope,
  validatePassphrase,
} from "./envelope.js";
import { fail, ReleaseKeyProvisioningError } from "./errors.js";
import {
  PROVISIONING_RECEIPT_TYPE,
  PROVISIONING_RECEIPT_VERSION,
  PROVISIONING_INTENT_TYPE,
  PROVISIONING_INTENT_VERSION,
  PROVISIONING_REPORT_TYPE,
  PROVISIONING_REPORT_VERSION,
  PUBLIC_IDENTITY_TYPE,
  PUBLIC_IDENTITY_VERSION,
  RELEASE_KEYCHAIN_ACCOUNT,
  RELEASE_KEYCHAIN_SERVICE,
  RELEASE_KEY_ALGORITHM,
  type KeychainHelperEvidenceV1,
  type RecoveryCopyIndex,
  type RecoveryCopyEvidenceV1,
  type RecoveryTarget,
  type ReleaseKeyProvisioningIntentV1,
  type ReleaseKeyMaterial,
  type ReleaseKeyProvisioningDependencies,
  type ReleaseKeyProvisioningOptions,
  type ReleaseKeyProvisioningReceiptV1,
  type ReleaseKeyProvisioningReportV1,
  type ReleaseKeyProvisioningRepositoryEligibilityV1,
  type ReleasePublicIdentityCandidateV1,
} from "./types.js";

export async function runReleaseKeyProvisioning(
  optionsValue: ReleaseKeyProvisioningOptions,
  dependencies: ReleaseKeyProvisioningDependencies,
): Promise<ReleaseKeyProvisioningReportV1> {
  const options = parseOptions(optionsValue);
  const model = await dependencies.platformModel();
  if (model !== "MacBook") {
    fail("HOST_REFUSED", "Release-key provisioning is restricted to the designated MacBook");
  }
  await dependencies.assertHostOffline();
  const platformIdentitySha256 = validateHash(
    await dependencies.platformIdentitySha256(),
    "Designated MacBook platform identity",
  );
  const helperEvidence = validateHelperEvidence(await dependencies.keychain.helperEvidence());
  const repositoryEligibility = validateRepositoryEligibility(
    await dependencies.assertRepositoryEligible(helperEvidence),
  );
  const repositoryCommitSha = repositoryEligibility.repositoryCommitSha;
  const [firstTarget, secondTarget] = await Promise.all([
    dependencies.inspectRecoveryTarget(options.backupDirectories[0], 1),
    dependencies.inspectRecoveryTarget(options.backupDirectories[1], 2),
  ]);
  assertDistinctTargets(firstTarget, secondTarget);

  const initializedAt = provisioningTimestamp(dependencies.now());
  const [existingIntentBytes, keychainPresent, existingIdentityBytes, existingReceiptBytes] =
    await Promise.all([
      dependencies.readIntent(),
      dependencies.keychain.inspectPresence(),
      dependencies.readPublicIdentity(options.publicIdentityPath),
      dependencies.readReceipt(options.receiptPath),
    ]);
  const targets = [firstTarget, secondTarget] as const;
  if (existingReceiptBytes !== undefined && existingIdentityBytes === undefined) {
    fail(
      "RESUME_REQUIRED",
      "A provisioning receipt without its bound public identity requires explicit remediation",
    );
  }
  if (
    options.mode === "create" &&
    (existingIntentBytes !== undefined ||
      keychainPresent ||
      firstTarget.envelopeExists ||
      secondTarget.envelopeExists ||
      existingIdentityBytes !== undefined ||
      existingReceiptBytes !== undefined)
  ) {
    fail("RESUME_REQUIRED", "Existing release-key state requires the fixed resume workflow");
  }
  if (options.mode === "resume" && existingIntentBytes === undefined) {
    fail("RESUME_REQUIRED", "The fixed provisioning intent is required for resume");
  }
  if (keychainPresent && !firstTarget.envelopeExists && !secondTarget.envelopeExists) {
    fail("RESUME_REQUIRED", "A Keychain identity without recovery media cannot be resumed");
  }

  let material: ReleaseKeyMaterial | undefined;
  let keychainValue: Buffer | undefined;
  let intentBytes: Buffer | undefined;
  let intent: ReleaseKeyProvisioningIntentV1;
  let durableStateExists =
    existingIntentBytes !== undefined ||
    keychainPresent ||
    firstTarget.envelopeExists ||
    secondTarget.envelopeExists ||
    existingIdentityBytes !== undefined ||
    existingReceiptBytes !== undefined;
  const passphraseHashes = new Map<RecoveryCopyIndex, Buffer>();
  const recoveryEvidence = new Map<RecoveryCopyIndex, RecoveryCopyEvidenceV1>();
  try {
    if (existingIntentBytes === undefined) {
      intent = createProvisioningIntent(
        targets,
        repositoryEligibility,
        platformIdentitySha256,
        initializedAt,
      );
      intentBytes = Buffer.from(canonicalJson(intent), "utf8");
      await dependencies.writeIntentCreateOnly(intentBytes);
      durableStateExists = true;
    } else {
      intentBytes = Buffer.from(existingIntentBytes);
      intent = parseProvisioningIntent(
        intentBytes,
        targets,
        repositoryEligibility,
        platformIdentitySha256,
      );
    }
    const provisioningIntentSha256 = sha256(intentBytes);

    if (
      options.mode === "create" ||
      (!firstTarget.envelopeExists &&
        !secondTarget.envelopeExists &&
        !keychainPresent &&
        existingIdentityBytes === undefined &&
        existingReceiptBytes === undefined)
    ) {
      await dependencies.assertHostOffline();
      material = dependencies.generateKeyMaterial();
    } else {
      for (const copyIndex of [1, 2] as const) {
        const target = copyIndex === 1 ? targets[0] : targets[1];
        if (!target.envelopeExists) continue;
        await dependencies.assertHostOffline();
        const recovered = await restoreExistingCopy(
          copyIndex,
          target,
          dependencies,
          passphraseHashes,
          recoveryEvidence,
        );
        if (material === undefined) {
          material = recovered;
        } else {
          try {
            assertSameMaterial(material, recovered);
          } finally {
            wipeMaterial(recovered);
          }
        }
      }
      if (material === undefined) {
        fail("RESUME_REQUIRED", "Release-key state cannot be recovered without an envelope");
      }
    }

    for (const copyIndex of [1, 2] as const) {
      const target = copyIndex === 1 ? targets[0] : targets[1];
      if (target.envelopeExists) continue;
      await dependencies.assertHostOffline();
      await createAndRestoreCopy(
        copyIndex,
        target,
        material,
        dependencies,
        passphraseHashes,
        recoveryEvidence,
        () => {
          durableStateExists = true;
        },
      );
    }
    assertDistinctPassphrases(passphraseHashes);
    const verifiedRecoveryCopies = orderedRecoveryEvidence(recoveryEvidence);

    keychainValue = encodeKeychainValue(material.privateKeyPkcs8Der);
    if (!keychainPresent) {
      await dependencies.assertHostOffline();
      try {
        await dependencies.keychain.addCreateOnly(keychainValue);
      } catch {
        fail(
          "RESUME_REQUIRED",
          "Keychain commit was not proven; preserve both recovery copies and resume",
        );
      }
    }
    await dependencies.assertHostOffline();
    if (!(await dependencies.keychain.verifyAclAndMatch(keychainValue))) {
      fail(
        "RESUME_REQUIRED",
        "Keychain identity or protection attributes are indeterminate; preserve state and resume",
      );
    }

    const newIdentity = createPublicIdentity(
      material,
      intent.initializedAt,
      helperEvidence,
      repositoryEligibility,
      platformIdentitySha256,
    );
    const identity =
      existingIdentityBytes === undefined
        ? newIdentity
        : parsePublicIdentity(
            existingIdentityBytes,
            material,
            helperEvidence,
            repositoryEligibility,
            platformIdentitySha256,
          );
    const identityBytes = Buffer.from(canonicalJson(identity), "utf8");
    const publicIdentitySha256 = sha256(identityBytes);
    if (existingIdentityBytes === undefined) {
      await dependencies.writePublicIdentityCreateOnly(options.publicIdentityPath, identityBytes);
    }

    const newReceipt = createReceipt(
      material,
      identity.createdAt,
      publicIdentitySha256,
      helperEvidence,
      repositoryEligibility,
      verifiedRecoveryCopies,
      provisioningIntentSha256,
      repositoryCommitSha,
      platformIdentitySha256,
    );
    const receipt =
      existingReceiptBytes === undefined
        ? newReceipt
        : parseProvisioningReceipt(
            existingReceiptBytes,
            material,
            publicIdentitySha256,
            helperEvidence,
            repositoryEligibility,
            verifiedRecoveryCopies,
            provisioningIntentSha256,
            repositoryCommitSha,
            platformIdentitySha256,
          );
    const receiptBytes = Buffer.from(canonicalJson(receipt), "utf8");
    if (existingReceiptBytes === undefined) {
      await dependencies.writeReceiptCreateOnly(options.receiptPath, receiptBytes);
    }
    return Object.freeze({
      copyCount: 2,
      createdAt: receipt.createdAt,
      helperCompatibilityEvidenceSha256: repositoryEligibility.helperCompatibilityEvidenceSha256,
      helperCompatibilityTestedCommitSha: repositoryEligibility.helperCompatibilityTestedCommitSha,
      keyId: material.keyId,
      platformIdentitySha256,
      publicIdentitySha256,
      receiptSha256: sha256(receiptBytes),
      reportType: PROVISIONING_REPORT_TYPE,
      signerFingerprintSha256: material.signerFingerprintSha256,
      status: "verified-keychain-and-distinct-recovery-targets",
      version: PROVISIONING_REPORT_VERSION,
    });
  } catch (error) {
    if (error instanceof ReleaseKeyProvisioningError && error.code === "RESUME_REQUIRED") {
      throw error;
    }
    if (durableStateExists) {
      fail("RESUME_REQUIRED", "Provisioning stopped after durable state; preserve it and resume");
    }
    throw error;
  } finally {
    keychainValue?.fill(0);
    if (material !== undefined) wipeMaterial(material);
    for (const hash of passphraseHashes.values()) hash.fill(0);
    existingIdentityBytes?.fill(0);
    existingReceiptBytes?.fill(0);
    existingIntentBytes?.fill(0);
    intentBytes?.fill(0);
  }
}

async function restoreExistingCopy(
  copyIndex: RecoveryCopyIndex,
  target: RecoveryTarget,
  dependencies: ReleaseKeyProvisioningDependencies,
  passphraseHashes: Map<RecoveryCopyIndex, Buffer>,
  recoveryEvidence: Map<RecoveryCopyIndex, RecoveryCopyEvidenceV1>,
): Promise<ReleaseKeyMaterial> {
  const remountedTarget = await dependencies.reverifyRecoveryTargetAfterRemount(target, copyIndex);
  await dependencies.assertHostOffline();
  const passphrase = await dependencies.passphrase(copyIndex, "restore");
  try {
    validatePassphrase(passphrase);
    passphraseHashes.set(copyIndex, createHash("sha256").update(passphrase).digest());
    const envelope = await dependencies.readEnvelope(remountedTarget);
    try {
      const material = decryptRecoveryEnvelope(envelope, passphrase, copyIndex);
      recoveryEvidence.set(
        copyIndex,
        createRecoveryEvidence(
          copyIndex,
          remountedTarget,
          envelope,
          provisioningTimestamp(dependencies.now()),
        ),
      );
      return material;
    } finally {
      envelope.fill(0);
    }
  } finally {
    passphrase.fill(0);
  }
}

async function createAndRestoreCopy(
  copyIndex: RecoveryCopyIndex,
  target: RecoveryTarget,
  material: ReleaseKeyMaterial,
  dependencies: ReleaseKeyProvisioningDependencies,
  passphraseHashes: Map<RecoveryCopyIndex, Buffer>,
  recoveryEvidence: Map<RecoveryCopyIndex, RecoveryCopyEvidenceV1>,
  markDurable: () => void,
): Promise<void> {
  const passphrase = await dependencies.passphrase(copyIndex, "create");
  const confirmation = await dependencies.passphrase(copyIndex, "confirm");
  let expectedPassphraseHash: Buffer | undefined;
  try {
    validatePassphrase(passphrase);
    validatePassphrase(confirmation);
    if (passphrase.length !== confirmation.length || !timingSafeEqual(passphrase, confirmation)) {
      fail("PASSPHRASE_REFUSED", "Recovery passphrase confirmation does not match");
    }
    expectedPassphraseHash = createHash("sha256").update(passphrase).digest();
    for (const existing of passphraseHashes.values()) {
      if (timingSafeEqual(existing, expectedPassphraseHash)) {
        fail("PASSPHRASE_REFUSED", "The two recovery copies require distinct passphrases");
      }
    }
    const envelope = encryptRecoveryEnvelope(material, passphrase, copyIndex);
    try {
      await dependencies.writeEnvelopeCreateOnly(target, envelope);
      markDurable();
    } finally {
      envelope.fill(0);
    }
  } finally {
    passphrase.fill(0);
    confirmation.fill(0);
  }

  const remountedTarget = await dependencies.reverifyRecoveryTargetAfterRemount(
    { ...target, envelopeExists: true },
    copyIndex,
  );
  await dependencies.assertHostOffline();
  const restoredPassphrase = await dependencies.passphrase(copyIndex, "restore");
  try {
    validatePassphrase(restoredPassphrase);
    const restoredHash = createHash("sha256").update(restoredPassphrase).digest();
    try {
      if (
        expectedPassphraseHash === undefined ||
        !timingSafeEqual(expectedPassphraseHash, restoredHash)
      ) {
        fail("PASSPHRASE_REFUSED", "Independent recovery passphrase check does not match");
      }
    } finally {
      restoredHash.fill(0);
    }
    const envelope = await dependencies.readEnvelope(remountedTarget);
    let recovered: ReleaseKeyMaterial | undefined;
    try {
      recovered = decryptRecoveryEnvelope(envelope, restoredPassphrase, copyIndex);
      assertSameMaterial(material, recovered);
      recoveryEvidence.set(
        copyIndex,
        createRecoveryEvidence(
          copyIndex,
          remountedTarget,
          envelope,
          provisioningTimestamp(dependencies.now()),
        ),
      );
    } finally {
      envelope.fill(0);
      if (recovered !== undefined) wipeMaterial(recovered);
    }
    passphraseHashes.set(copyIndex, expectedPassphraseHash);
    expectedPassphraseHash = undefined;
  } finally {
    restoredPassphrase.fill(0);
    expectedPassphraseHash?.fill(0);
  }
}

function parseOptions(value: ReleaseKeyProvisioningOptions): ReleaseKeyProvisioningOptions {
  const record = exactObject(
    value,
    [
      "backupDirectories",
      "confirmAccount",
      "confirmCopyCount",
      "mode",
      "publicIdentityPath",
      "receiptPath",
    ],
    "Release-key provisioning options",
  );
  const directories = exactArray(record.backupDirectories, "Recovery directories", 2);
  if (
    directories.length !== 2 ||
    typeof directories[0] !== "string" ||
    typeof directories[1] !== "string" ||
    directories[0] === directories[1] ||
    record.confirmAccount !== RELEASE_KEYCHAIN_ACCOUNT ||
    record.confirmCopyCount !== 2 ||
    (record.mode !== "create" && record.mode !== "resume") ||
    typeof record.publicIdentityPath !== "string" ||
    typeof record.receiptPath !== "string" ||
    record.publicIdentityPath === record.receiptPath
  ) {
    fail("INPUT_INVALID", "Release-key provisioning options are invalid");
  }
  return Object.freeze({
    backupDirectories: Object.freeze([directories[0], directories[1]] as [string, string]),
    confirmAccount: RELEASE_KEYCHAIN_ACCOUNT,
    confirmCopyCount: 2,
    mode: record.mode,
    publicIdentityPath: record.publicIdentityPath,
    receiptPath: record.receiptPath,
  });
}

function assertDistinctTargets(first: RecoveryTarget, second: RecoveryTarget): void {
  if (
    first.directoryPath === second.directoryPath ||
    first.envelopePath === second.envelopePath ||
    first.physicalDeviceId === second.physicalDeviceId ||
    first.physicalStoreId === second.physicalStoreId ||
    first.volumeId === second.volumeId ||
    (first.directoryDevice === second.directoryDevice &&
      first.directoryInode === second.directoryInode)
  ) {
    fail("TARGET_REFUSED", "Recovery copies require two distinct encrypted physical targets");
  }
}

function assertDistinctPassphrases(hashes: ReadonlyMap<RecoveryCopyIndex, Buffer>): void {
  const first = hashes.get(1);
  const second = hashes.get(2);
  if (
    first === undefined ||
    second === undefined ||
    first.length !== second.length ||
    timingSafeEqual(first, second)
  ) {
    fail("PASSPHRASE_REFUSED", "Recovery passphrases are missing or not independent");
  }
}

function assertSameMaterial(left: ReleaseKeyMaterial, right: ReleaseKeyMaterial): void {
  if (
    left.keyId !== right.keyId ||
    left.signerFingerprintSha256 !== right.signerFingerprintSha256 ||
    left.privateKeyPkcs8Der.length !== right.privateKeyPkcs8Der.length ||
    left.publicKeySpkiDer.length !== right.publicKeySpkiDer.length ||
    !timingSafeEqual(left.privateKeyPkcs8Der, right.privateKeyPkcs8Der) ||
    !timingSafeEqual(left.publicKeySpkiDer, right.publicKeySpkiDer)
  ) {
    fail("VERIFICATION_FAILED", "Recovery copies do not contain the same release identity");
  }
}

function provisioningTimestamp(value: Date): string {
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
    fail("INPUT_INVALID", "Provisioning clock is invalid");
  }
  return value.toISOString();
}

function createProvisioningIntent(
  targets: readonly [RecoveryTarget, RecoveryTarget],
  repositoryEligibility: ReleaseKeyProvisioningRepositoryEligibilityV1,
  platformIdentitySha256: string,
  initializedAt: string,
): ReleaseKeyProvisioningIntentV1 {
  return Object.freeze({
    helperCompatibilityEvidenceSha256: repositoryEligibility.helperCompatibilityEvidenceSha256,
    helperCompatibilityTestedCommitSha: repositoryEligibility.helperCompatibilityTestedCommitSha,
    initializedAt: validateCanonicalTimestamp(initializedAt, "Provisioning intent time"),
    intentType: PROVISIONING_INTENT_TYPE,
    platformIdentitySha256: validateHash(
      platformIdentitySha256,
      "Designated MacBook platform identity",
    ),
    recoveryTargets: Object.freeze([
      targetBinding(targets[0], 1),
      targetBinding(targets[1], 2),
    ] as const),
    repositoryCommitSha: repositoryEligibility.repositoryCommitSha,
    version: PROVISIONING_INTENT_VERSION,
  });
}

function parseProvisioningIntent(
  bytes: Buffer,
  targets: readonly [RecoveryTarget, RecoveryTarget],
  repositoryEligibility: ReleaseKeyProvisioningRepositoryEligibilityV1,
  platformIdentitySha256: string,
): ReleaseKeyProvisioningIntentV1 {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
  } catch {
    fail("RESUME_REQUIRED", "The fixed provisioning intent is invalid");
  }
  const record = exactObject(
    value,
    [
      "helperCompatibilityEvidenceSha256",
      "helperCompatibilityTestedCommitSha",
      "initializedAt",
      "intentType",
      "platformIdentitySha256",
      "recoveryTargets",
      "repositoryCommitSha",
      "version",
    ],
    "Release-key provisioning intent",
  );
  const expected = createProvisioningIntent(
    targets,
    repositoryEligibility,
    validateHash(platformIdentitySha256, "Designated MacBook platform identity"),
    validateCanonicalTimestamp(record.initializedAt, "Provisioning intent time"),
  );
  if (
    record.intentType !== PROVISIONING_INTENT_TYPE ||
    record.version !== PROVISIONING_INTENT_VERSION ||
    canonicalJson(record) !== canonicalJson(expected) ||
    new TextDecoder().decode(bytes) !== canonicalJson(expected)
  ) {
    fail(
      "RESUME_REQUIRED",
      "Provisioning resume must use the exact repository and recovery targets from its intent",
    );
  }
  return expected;
}

function targetBinding(target: RecoveryTarget, copyIndex: RecoveryCopyIndex) {
  return Object.freeze({
    copyIndex,
    directoryPath: target.directoryPath,
    physicalStoreIdentitySha256: sha256(
      `rsi-release-recovery-physical-store-v1\0${target.physicalStoreId}`,
    ),
    volumeIdentitySha256: sha256(`rsi-release-recovery-volume-v1\0${target.volumeId}`),
  });
}

function validateRepositoryEligibility(
  value: ReleaseKeyProvisioningRepositoryEligibilityV1,
): ReleaseKeyProvisioningRepositoryEligibilityV1 {
  const record = exactObject(
    value,
    [
      "helperCompatibilityEvidenceSha256",
      "helperCompatibilityTestedCommitSha",
      "repositoryCommitSha",
    ],
    "Provisioning repository eligibility",
  );
  return Object.freeze({
    helperCompatibilityEvidenceSha256: validateHash(
      record.helperCompatibilityEvidenceSha256,
      "Helper compatibility evidence hash",
    ),
    helperCompatibilityTestedCommitSha: validateGitHash(
      record.helperCompatibilityTestedCommitSha,
      "Helper compatibility tested commit",
    ),
    repositoryCommitSha: validateGitHash(
      record.repositoryCommitSha,
      "Provisioning repository commit",
    ),
  });
}

function validateHelperEvidence(value: KeychainHelperEvidenceV1): KeychainHelperEvidenceV1 {
  const record = exactObject(
    value,
    ["binarySha256", "compilerIdentitySha256", "sourceSha256"],
    "Keychain helper evidence",
  );
  return Object.freeze({
    binarySha256: validateHash(record.binarySha256, "Keychain helper binary hash"),
    compilerIdentitySha256: validateHash(
      record.compilerIdentitySha256,
      "Keychain helper compiler identity hash",
    ),
    sourceSha256: validateHash(record.sourceSha256, "Keychain helper source hash"),
  });
}

function createPublicIdentity(
  material: ReleaseKeyMaterial,
  createdAt: string,
  helperEvidence: KeychainHelperEvidenceV1,
  repositoryEligibility: ReleaseKeyProvisioningRepositoryEligibilityV1,
  platformIdentitySha256: string,
): ReleasePublicIdentityCandidateV1 {
  return Object.freeze({
    account: RELEASE_KEYCHAIN_ACCOUNT,
    algorithm: RELEASE_KEY_ALGORITHM,
    candidateType: PUBLIC_IDENTITY_TYPE,
    createdAt,
    helperBinarySha256: helperEvidence.binarySha256,
    helperCompatibilityEvidenceSha256: repositoryEligibility.helperCompatibilityEvidenceSha256,
    helperCompatibilityTestedCommitSha: repositoryEligibility.helperCompatibilityTestedCommitSha,
    helperCompilerIdentitySha256: helperEvidence.compilerIdentitySha256,
    helperSourceSha256: helperEvidence.sourceSha256,
    keyId: material.keyId,
    keychainProtection: "data-protection-when-unlocked-this-device-only-user-presence",
    platformIdentitySha256: validateHash(
      platformIdentitySha256,
      "Designated MacBook platform identity",
    ),
    publicKeySpkiDerBase64url: material.publicKeySpkiDer.toString("base64url"),
    service: RELEASE_KEYCHAIN_SERVICE,
    signerFingerprintSha256: material.signerFingerprintSha256,
    version: PUBLIC_IDENTITY_VERSION,
  });
}

function parsePublicIdentity(
  bytes: Buffer,
  material: ReleaseKeyMaterial,
  helperEvidence: KeychainHelperEvidenceV1,
  repositoryEligibility: ReleaseKeyProvisioningRepositoryEligibilityV1,
  platformIdentitySha256: string,
): ReleasePublicIdentityCandidateV1 {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
  } catch {
    fail("VERIFICATION_FAILED", "Existing public identity candidate is invalid");
  }
  const record = exactObject(
    value,
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
    "Release public identity candidate",
  );
  const expected = createPublicIdentity(
    material,
    validateCanonicalTimestamp(record.createdAt, "Public identity creation time"),
    helperEvidence,
    repositoryEligibility,
    platformIdentitySha256,
  );
  if (
    record.account !== expected.account ||
    record.algorithm !== expected.algorithm ||
    record.candidateType !== expected.candidateType ||
    record.helperBinarySha256 !== expected.helperBinarySha256 ||
    record.helperCompatibilityEvidenceSha256 !== expected.helperCompatibilityEvidenceSha256 ||
    record.helperCompatibilityTestedCommitSha !== expected.helperCompatibilityTestedCommitSha ||
    record.helperCompilerIdentitySha256 !== expected.helperCompilerIdentitySha256 ||
    record.helperSourceSha256 !== expected.helperSourceSha256 ||
    record.keyId !== expected.keyId ||
    record.keychainProtection !== expected.keychainProtection ||
    record.platformIdentitySha256 !== expected.platformIdentitySha256 ||
    record.publicKeySpkiDerBase64url !== expected.publicKeySpkiDerBase64url ||
    record.service !== expected.service ||
    record.signerFingerprintSha256 !== expected.signerFingerprintSha256 ||
    record.version !== expected.version ||
    new TextDecoder().decode(bytes) !== canonicalJson(expected)
  ) {
    fail("VERIFICATION_FAILED", "Existing public identity candidate does not match recovery");
  }
  return expected;
}

function createReceipt(
  material: ReleaseKeyMaterial,
  createdAt: string,
  publicIdentitySha256: string,
  helperEvidence: KeychainHelperEvidenceV1,
  repositoryEligibility: ReleaseKeyProvisioningRepositoryEligibilityV1,
  recoveryCopies: readonly [RecoveryCopyEvidenceV1, RecoveryCopyEvidenceV1],
  provisioningIntentSha256: string,
  repositoryCommitSha: string,
  platformIdentitySha256: string,
): ReleaseKeyProvisioningReceiptV1 {
  return Object.freeze({
    account: RELEASE_KEYCHAIN_ACCOUNT,
    copyCount: 2,
    createdAt,
    helperBinarySha256: helperEvidence.binarySha256,
    helperCompatibilityEvidenceSha256: repositoryEligibility.helperCompatibilityEvidenceSha256,
    helperCompatibilityTestedCommitSha: repositoryEligibility.helperCompatibilityTestedCommitSha,
    helperCompilerIdentitySha256: helperEvidence.compilerIdentitySha256,
    helperSourceSha256: helperEvidence.sourceSha256,
    keyId: material.keyId,
    keychainProtection: "data-protection-when-unlocked-this-device-only-user-presence",
    keychainStatus: "identity-verified",
    platformIdentitySha256: validateHash(
      platformIdentitySha256,
      "Designated MacBook platform identity",
    ),
    provisioningIntentSha256,
    publicIdentitySha256,
    recoveryCopies,
    receiptType: PROVISIONING_RECEIPT_TYPE,
    repositoryCommitSha,
    service: RELEASE_KEYCHAIN_SERVICE,
    signerFingerprintSha256: material.signerFingerprintSha256,
    status: "verified-keychain-and-two-recovery-copies",
    version: PROVISIONING_RECEIPT_VERSION,
  });
}

function parseProvisioningReceipt(
  bytes: Buffer,
  material: ReleaseKeyMaterial,
  publicIdentitySha256: string,
  helperEvidence: KeychainHelperEvidenceV1,
  repositoryEligibility: ReleaseKeyProvisioningRepositoryEligibilityV1,
  recoveryCopies: readonly [RecoveryCopyEvidenceV1, RecoveryCopyEvidenceV1],
  provisioningIntentSha256: string,
  repositoryCommitSha: string,
  platformIdentitySha256: string,
): ReleaseKeyProvisioningReceiptV1 {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
  } catch {
    fail("VERIFICATION_FAILED", "Existing provisioning receipt is invalid");
  }
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
    "Release-key provisioning receipt",
  );
  const recordedRecoveryCopies = parseRecordedRecoveryCopies(record.recoveryCopies, recoveryCopies);
  const expected = createReceipt(
    material,
    validateCanonicalTimestamp(record.createdAt, "Provisioning receipt creation time"),
    validateHash(publicIdentitySha256, "Public identity hash"),
    helperEvidence,
    repositoryEligibility,
    recordedRecoveryCopies,
    validateHash(provisioningIntentSha256, "Provisioning intent hash"),
    validateGitHash(repositoryCommitSha, "Provisioning repository commit"),
    validateHash(platformIdentitySha256, "Designated MacBook platform identity"),
  );
  if (
    canonicalJson(record) !== canonicalJson(expected) ||
    new TextDecoder().decode(bytes) !== canonicalJson(expected)
  ) {
    fail("VERIFICATION_FAILED", "Existing provisioning receipt does not match recovery");
  }
  return expected;
}

function parseRecordedRecoveryCopies(
  value: unknown,
  current: readonly [RecoveryCopyEvidenceV1, RecoveryCopyEvidenceV1],
): readonly [RecoveryCopyEvidenceV1, RecoveryCopyEvidenceV1] {
  const values = exactArray(value, "Recorded recovery-copy evidence", 2);
  if (values.length !== 2) {
    fail("VERIFICATION_FAILED", "Recorded recovery-copy evidence is incomplete");
  }
  const parsed = values.map((entry, index) => {
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
      "Recorded recovery-copy evidence",
    );
    const expected = current[index]!;
    if (
      record.copyIndex !== expected.copyIndex ||
      record.envelopeSha256 !== expected.envelopeSha256 ||
      record.physicalStoreIdentitySha256 !== expected.physicalStoreIdentitySha256 ||
      record.restoreStatus !== "restore-verified" ||
      record.volumeIdentitySha256 !== expected.volumeIdentitySha256
    ) {
      fail("VERIFICATION_FAILED", "Recorded recovery-copy evidence no longer matches media");
    }
    return Object.freeze({
      ...expected,
      restoredAt: validateCanonicalTimestamp(record.restoredAt, "Recorded recovery restore time"),
    });
  });
  if (parsed.length !== 2 || parsed[0] === undefined || parsed[1] === undefined) {
    fail("VERIFICATION_FAILED", "Recorded recovery-copy evidence is incomplete");
  }
  return Object.freeze([parsed[0], parsed[1]] as const);
}

function createRecoveryEvidence(
  copyIndex: RecoveryCopyIndex,
  target: RecoveryTarget,
  envelope: Buffer,
  restoredAt: string,
): RecoveryCopyEvidenceV1 {
  return Object.freeze({
    copyIndex,
    envelopeSha256: sha256(envelope),
    physicalStoreIdentitySha256: sha256(
      `rsi-release-recovery-physical-store-v1\0${target.physicalStoreId}`,
    ),
    restoredAt: validateCanonicalTimestamp(restoredAt, "Recovery restore time"),
    restoreStatus: "restore-verified",
    volumeIdentitySha256: sha256(`rsi-release-recovery-volume-v1\0${target.volumeId}`),
  });
}

function orderedRecoveryEvidence(
  values: ReadonlyMap<RecoveryCopyIndex, RecoveryCopyEvidenceV1>,
): readonly [RecoveryCopyEvidenceV1, RecoveryCopyEvidenceV1] {
  const first = values.get(1);
  const second = values.get(2);
  if (
    first === undefined ||
    second === undefined ||
    first.copyIndex !== 1 ||
    second.copyIndex !== 2 ||
    first.envelopeSha256 === second.envelopeSha256 ||
    first.physicalStoreIdentitySha256 === second.physicalStoreIdentitySha256 ||
    first.volumeIdentitySha256 === second.volumeIdentitySha256
  ) {
    fail("VERIFICATION_FAILED", "Recovery-copy evidence is incomplete or not independent");
  }
  return Object.freeze([first, second] as const);
}

function wipeMaterial(material: ReleaseKeyMaterial): void {
  material.privateKeyPkcs8Der.fill(0);
  material.publicKeySpkiDer.fill(0);
}
