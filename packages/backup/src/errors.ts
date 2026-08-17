export type BackupErrorCode =
  | "ARCHIVE_BOUNDS"
  | "ARCHIVE_CHANGED"
  | "ARCHIVE_FORMAT"
  | "ARCHIVE_UNSAFE"
  | "DESTINATION_EXISTS"
  | "DESTINATION_UNSAFE"
  | "INPUT_INVALID"
  | "INTEGRITY_MISMATCH"
  | "PUBLISH_BUSY"
  | "SIGNATURE_INVALID"
  | "SIGNER_FAILED"
  | "TRUST_MISMATCH";

/** Deliberately content-free: messages never echo caller values or paths. */
export class BackupError extends Error {
  readonly code: BackupErrorCode;

  constructor(code: BackupErrorCode, safeMessage: string) {
    super(safeMessage);
    this.name = "BackupError";
    this.code = code;
  }
}

export function fail(code: BackupErrorCode, safeMessage: string): never {
  throw new BackupError(code, safeMessage);
}
