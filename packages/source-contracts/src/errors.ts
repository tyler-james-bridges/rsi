export type SourceContractErrorCode =
  "ASSET_MISMATCH" | "INPUT_INVALID" | "RESPONSE_INVALID" | "STALE_RESPONSE" | "UNSUPPORTED_SOURCE";

export class SourceContractError extends Error {
  readonly code: SourceContractErrorCode;

  constructor(code: SourceContractErrorCode) {
    super("Source contract validation failed");
    this.name = "SourceContractError";
    this.code = code;
  }
}
