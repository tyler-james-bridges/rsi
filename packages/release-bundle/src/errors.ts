export type ReleaseBundleErrorCode =
  | "ARCHIVE_BOUNDS"
  | "ARCHIVE_CHANGED"
  | "ARCHIVE_FORMAT"
  | "ARCHIVE_UNSAFE"
  | "DESTINATION_EXISTS"
  | "DESTINATION_UNSAFE"
  | "INPUT_INVALID"
  | "INTEGRITY_MISMATCH"
  | "POLICY_VIOLATION"
  | "SECRET_DETECTED"
  | "SIGNATURE_INVALID"
  | "SIGNER_FAILED"
  | "TRUST_MISMATCH";

/** Deliberately content-free: messages never echo caller values, paths, or bytes. */
export class ReleaseBundleError extends Error {
  readonly code: ReleaseBundleErrorCode;

  constructor(code: ReleaseBundleErrorCode, safeMessage: string) {
    super(safeMessage);
    this.name = "ReleaseBundleError";
    this.code = code;
  }
}

export function fail(code: ReleaseBundleErrorCode, safeMessage: string): never {
  throw new ReleaseBundleError(code, safeMessage);
}
