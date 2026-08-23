export const RELEASE_KEYCHAIN_SERVICE = "dev.rsi.macbook.release-signing" as const;
export const RELEASE_KEYCHAIN_ACCOUNT = "release-ed25519-v1" as const;
export const RELEASE_KEY_ALGORITHM = "Ed25519" as const;
export const RECOVERY_ENVELOPE_TYPE = "rsi.release-key-recovery-envelope" as const;
export const RECOVERY_ENVELOPE_VERSION = 1 as const;
export const PROVISIONING_RECEIPT_TYPE = "rsi.release-key-provisioning-receipt" as const;
export const PROVISIONING_RECEIPT_VERSION = 1 as const;
export const PUBLIC_IDENTITY_TYPE = "rsi.release-public-identity-candidate" as const;
export const PUBLIC_IDENTITY_VERSION = 1 as const;
export const PROVISIONING_REPORT_TYPE = "rsi.release-key-provisioning-report" as const;
export const PROVISIONING_REPORT_VERSION = 1 as const;
export const PROVISIONING_INTENT_TYPE = "rsi.release-key-provisioning-intent" as const;
export const PROVISIONING_INTENT_VERSION = 1 as const;
export const RECOVERY_FILE_NAMES = [
  "rsi-release-ed25519-v1-copy-1.envelope.json",
  "rsi-release-ed25519-v1-copy-2.envelope.json",
] as const;

export type RecoveryCopyIndex = 1 | 2;
export type ProvisioningMode = "create" | "resume";
export type PassphrasePhase = "confirm" | "create" | "restore";

export interface RecoveryEnvelopeAadV1 {
  readonly account: typeof RELEASE_KEYCHAIN_ACCOUNT;
  readonly algorithm: typeof RELEASE_KEY_ALGORITHM;
  readonly cipher: {
    readonly name: "AES-256-GCM";
    readonly nonceBase64url: string;
    readonly tagBytes: 16;
  };
  readonly copyIndex: RecoveryCopyIndex;
  readonly envelopeType: typeof RECOVERY_ENVELOPE_TYPE;
  readonly keyId: string;
  readonly kdf: {
    readonly name: "scrypt";
    readonly n: 131072;
    readonly p: 1;
    readonly r: 8;
    readonly saltBase64url: string;
  };
  readonly publicKeySpkiDerBase64url: string;
  readonly service: typeof RELEASE_KEYCHAIN_SERVICE;
  readonly signerFingerprintSha256: string;
  readonly version: typeof RECOVERY_ENVELOPE_VERSION;
}

export interface RecoveryEnvelopeV1 {
  readonly aad: RecoveryEnvelopeAadV1;
  readonly authenticationTagBase64url: string;
  readonly ciphertextBase64url: string;
}

export interface ReleasePublicIdentityCandidateV1 {
  readonly account: typeof RELEASE_KEYCHAIN_ACCOUNT;
  readonly algorithm: typeof RELEASE_KEY_ALGORITHM;
  readonly candidateType: typeof PUBLIC_IDENTITY_TYPE;
  readonly createdAt: string;
  readonly helperBinarySha256: string;
  readonly helperCompatibilityEvidenceSha256: string;
  readonly helperCompatibilityTestedCommitSha: string;
  readonly helperCompilerIdentitySha256: string;
  readonly helperSourceSha256: string;
  readonly keyId: string;
  readonly keychainProtection: "data-protection-when-unlocked-this-device-only-user-presence";
  readonly platformIdentitySha256: string;
  readonly publicKeySpkiDerBase64url: string;
  readonly service: typeof RELEASE_KEYCHAIN_SERVICE;
  readonly signerFingerprintSha256: string;
  readonly version: typeof PUBLIC_IDENTITY_VERSION;
}

export interface ReleaseKeyProvisioningReceiptV1 {
  readonly account: typeof RELEASE_KEYCHAIN_ACCOUNT;
  readonly copyCount: 2;
  readonly createdAt: string;
  readonly helperBinarySha256: string;
  readonly helperCompatibilityEvidenceSha256: string;
  readonly helperCompatibilityTestedCommitSha: string;
  readonly helperCompilerIdentitySha256: string;
  readonly helperSourceSha256: string;
  readonly keyId: string;
  readonly keychainProtection: "data-protection-when-unlocked-this-device-only-user-presence";
  readonly keychainStatus: "identity-verified";
  readonly platformIdentitySha256: string;
  readonly provisioningIntentSha256: string;
  readonly publicIdentitySha256: string;
  readonly recoveryCopies: readonly [RecoveryCopyEvidenceV1, RecoveryCopyEvidenceV1];
  readonly receiptType: typeof PROVISIONING_RECEIPT_TYPE;
  readonly repositoryCommitSha: string;
  readonly service: typeof RELEASE_KEYCHAIN_SERVICE;
  readonly signerFingerprintSha256: string;
  readonly status: "verified-keychain-and-two-recovery-copies";
  readonly version: typeof PROVISIONING_RECEIPT_VERSION;
}

export interface KeychainHelperEvidenceV1 {
  readonly binarySha256: string;
  readonly compilerIdentitySha256: string;
  readonly sourceSha256: string;
}

export interface RecoveryTargetBindingV1 {
  readonly copyIndex: RecoveryCopyIndex;
  readonly directoryPath: string;
  readonly physicalStoreIdentitySha256: string;
  readonly volumeIdentitySha256: string;
}

export interface ReleaseKeyProvisioningIntentV1 {
  readonly helperCompatibilityEvidenceSha256: string;
  readonly helperCompatibilityTestedCommitSha: string;
  readonly initializedAt: string;
  readonly intentType: typeof PROVISIONING_INTENT_TYPE;
  readonly platformIdentitySha256: string;
  readonly recoveryTargets: readonly [RecoveryTargetBindingV1, RecoveryTargetBindingV1];
  readonly repositoryCommitSha: string;
  readonly version: typeof PROVISIONING_INTENT_VERSION;
}

export interface RecoveryCopyEvidenceV1 {
  readonly copyIndex: RecoveryCopyIndex;
  readonly envelopeSha256: string;
  /** Domain-separated hash of the APFS physical-store partition UUID; the raw UUID is not retained. */
  readonly physicalStoreIdentitySha256: string;
  readonly restoredAt: string;
  readonly restoreStatus: "restore-verified";
  /** Domain-separated hash of the encrypted APFS volume identity; the raw UUID is not retained. */
  readonly volumeIdentitySha256: string;
}

export interface ReleaseKeyProvisioningReportV1 {
  readonly copyCount: 2;
  readonly createdAt: string;
  readonly helperCompatibilityEvidenceSha256: string;
  readonly helperCompatibilityTestedCommitSha: string;
  readonly keyId: string;
  readonly platformIdentitySha256: string;
  readonly publicIdentitySha256: string;
  readonly receiptSha256: string;
  readonly reportType: typeof PROVISIONING_REPORT_TYPE;
  readonly signerFingerprintSha256: string;
  readonly status: "verified-keychain-and-distinct-recovery-targets";
  readonly version: typeof PROVISIONING_REPORT_VERSION;
}

export interface ReleaseKeyProvisioningOptions {
  readonly backupDirectories: readonly [string, string];
  readonly confirmAccount: typeof RELEASE_KEYCHAIN_ACCOUNT;
  readonly confirmCopyCount: 2;
  readonly mode: ProvisioningMode;
  readonly publicIdentityPath: string;
  readonly receiptPath: string;
}

export interface RecoveryTarget {
  readonly directoryDevice: bigint;
  readonly directoryInode: bigint;
  readonly directoryPath: string;
  readonly envelopeExists: boolean;
  readonly envelopePath: string;
  /** Ephemeral BSD whole-disk identifier used only for live eject; it may change after remount. */
  readonly physicalDeviceId: string;
  /** Stable APFS physical-store partition UUID used for durable identity binding. */
  readonly physicalStoreId: string;
  readonly volumeId: string;
}

export interface ReleaseKeyMaterial {
  readonly keyId: string;
  readonly privateKeyPkcs8Der: Buffer;
  readonly publicKeySpkiDer: Buffer;
  readonly signerFingerprintSha256: string;
}

export interface KeychainProvisioningAdapter {
  readonly addCreateOnly: (encodedKey: Buffer) => Promise<void>;
  readonly helperEvidence: () => Promise<KeychainHelperEvidenceV1>;
  readonly inspectPresence: () => Promise<boolean>;
  readonly verifyAclAndMatch: (encodedKey: Buffer) => Promise<boolean>;
}

export interface ReleaseKeyProvisioningRepositoryEligibilityV1 {
  readonly helperCompatibilityEvidenceSha256: string;
  readonly helperCompatibilityTestedCommitSha: string;
  readonly repositoryCommitSha: string;
}

export interface ReleaseKeyProvisioningDependencies {
  readonly assertHostOffline: () => Promise<void>;
  readonly assertRepositoryEligible: (
    helperEvidence: KeychainHelperEvidenceV1,
  ) => Promise<ReleaseKeyProvisioningRepositoryEligibilityV1>;
  readonly generateKeyMaterial: () => ReleaseKeyMaterial;
  readonly inspectRecoveryTarget: (
    directoryPath: string,
    copyIndex: RecoveryCopyIndex,
  ) => Promise<RecoveryTarget>;
  readonly keychain: KeychainProvisioningAdapter;
  readonly now: () => Date;
  readonly passphrase: (copyIndex: RecoveryCopyIndex, phase: PassphrasePhase) => Promise<Buffer>;
  readonly platformIdentitySha256: () => Promise<string>;
  readonly platformModel: () => Promise<string>;
  readonly readEnvelope: (target: RecoveryTarget) => Promise<Buffer>;
  readonly readIntent: () => Promise<Buffer | undefined>;
  readonly readPublicIdentity: (path: string) => Promise<Buffer | undefined>;
  readonly readReceipt: (path: string) => Promise<Buffer | undefined>;
  readonly reverifyRecoveryTargetAfterRemount: (
    target: RecoveryTarget,
    copyIndex: RecoveryCopyIndex,
  ) => Promise<RecoveryTarget>;
  readonly writeEnvelopeCreateOnly: (target: RecoveryTarget, bytes: Buffer) => Promise<void>;
  readonly writeIntentCreateOnly: (bytes: Buffer) => Promise<void>;
  readonly writePublicIdentityCreateOnly: (path: string, bytes: Buffer) => Promise<void>;
  readonly writeReceiptCreateOnly: (path: string, bytes: Buffer) => Promise<void>;
}
