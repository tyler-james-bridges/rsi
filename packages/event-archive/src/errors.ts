export type EventArchiveErrorCode =
  | "ARCHIVE_BOUNDS"
  | "ARCHIVE_CHANGED"
  | "ARCHIVE_FORMAT"
  | "ARCHIVE_UNSAFE"
  | "DESTINATION_EXISTS"
  | "DESTINATION_UNSAFE"
  | "IMPORT_TARGET_INVALID"
  | "INPUT_INVALID"
  | "INTEGRITY_MISMATCH"
  | "PUBLISH_BUSY"
  | "SIGNATURE_INVALID"
  | "SIGNER_FAILED"
  | "TRUST_MISMATCH";

/** Deliberately content-free: messages never echo caller values, paths, or payloads. */
export class EventArchiveError extends Error {
  readonly code: EventArchiveErrorCode;

  constructor(code: EventArchiveErrorCode, safeMessage: string) {
    super(safeMessage);
    this.name = "EventArchiveError";
    this.code = code;
  }
}

export function fail(code: EventArchiveErrorCode, safeMessage: string): never {
  throw new EventArchiveError(code, safeMessage);
}
