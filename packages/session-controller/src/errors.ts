export type SessionControllerErrorCode =
  | "COMPONENT_VERIFICATION_FAILED"
  | "INPUT_INVALID"
  | "RECOVERY_BINDING_MISMATCH"
  | "UNAUTHENTICATED_REPORT";

export class SessionControllerError extends Error {
  readonly code: SessionControllerErrorCode;

  constructor(code: SessionControllerErrorCode) {
    super(code);
    this.name = "SessionControllerError";
    this.code = code;
  }
}
