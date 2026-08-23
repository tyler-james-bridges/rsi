export type ReleaseKeyProvisioningErrorCode =
  | "ENVELOPE_INVALID"
  | "HOST_REFUSED"
  | "INPUT_INVALID"
  | "KEYCHAIN_FAILED"
  | "OUTPUT_FAILED"
  | "PASSPHRASE_REFUSED"
  | "REPOSITORY_STATE"
  | "RESUME_REQUIRED"
  | "TARGET_REFUSED"
  | "VERIFICATION_FAILED";

export class ReleaseKeyProvisioningError extends Error {
  readonly code: ReleaseKeyProvisioningErrorCode;

  constructor(code: ReleaseKeyProvisioningErrorCode, message: string) {
    super(message);
    this.name = "ReleaseKeyProvisioningError";
    this.code = code;
  }
}

export function fail(code: ReleaseKeyProvisioningErrorCode, message: string): never {
  throw new ReleaseKeyProvisioningError(code, message);
}
