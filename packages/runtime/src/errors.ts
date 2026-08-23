import type { RuntimeBoundaryReceipt } from "./types.js";

export type RuntimeConflictCode =
  | "AUTHORIZATION_ALREADY_USED"
  | "INVALID_TRANSITION"
  | "PROCESS_SUPERSEDED"
  | "REQUEST_CONFLICT"
  | "STALE_STATE";

export class RuntimeValidationError extends TypeError {
  readonly code = "VALIDATION" as const;

  constructor(message = "Runtime input is invalid") {
    super(message);
    this.name = "RuntimeValidationError";
  }
}

export class RuntimeConflictError extends Error {
  readonly code: RuntimeConflictCode;

  constructor(code: RuntimeConflictCode, message: string) {
    super(message);
    this.name = "RuntimeConflictError";
    this.code = code;
  }
}

export class RuntimeIntegrityError extends Error {
  readonly code = "INTEGRITY" as const;

  constructor(message: string) {
    super(message);
    this.name = "RuntimeIntegrityError";
  }
}

export class RuntimeBoundaryDeniedError extends Error {
  readonly code = "BOUNDARY_DENIED" as const;
  readonly receipt: Readonly<RuntimeBoundaryReceipt>;

  constructor(receipt: Readonly<RuntimeBoundaryReceipt>) {
    super(`Runtime boundary '${receipt.boundary}' was denied: ${receipt.reason}`);
    this.name = "RuntimeBoundaryDeniedError";
    this.receipt = receipt;
  }
}
