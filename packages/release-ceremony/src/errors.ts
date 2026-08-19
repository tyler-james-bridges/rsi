export type FoundationCeremonyErrorCode =
  | "CI_EVIDENCE_INVALID"
  | "CUSTODY_FAILED"
  | "HOST_REFUSED"
  | "INPUT_INVALID"
  | "OUTPUT_FAILED"
  | "REPOSITORY_STATE"
  | "VERIFICATION_FAILED";

export class FoundationCeremonyError extends Error {
  readonly code: FoundationCeremonyErrorCode;

  constructor(code: FoundationCeremonyErrorCode, message: string) {
    super(message);
    this.name = "FoundationCeremonyError";
    this.code = code;
  }
}

export function fail(code: FoundationCeremonyErrorCode, message: string): never {
  throw new FoundationCeremonyError(code, message);
}
