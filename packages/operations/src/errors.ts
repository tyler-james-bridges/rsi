export type OperationsConflictCode =
  "ATTEMPT_CONFLICT" | "BUDGET_CONFLICT" | "CURSOR_CONFLICT" | "INVALID_TRANSITION";

export class OperationsConflictError extends Error {
  readonly code: OperationsConflictCode;

  constructor(code: OperationsConflictCode, message: string) {
    super(message);
    this.name = "OperationsConflictError";
    this.code = code;
  }
}

export class OperationsValidationError extends TypeError {
  readonly code = "VALIDATION" as const;

  constructor(message: string) {
    super(message);
    this.name = "OperationsValidationError";
  }
}

export class OperationsIntegrityError extends Error {
  readonly code = "INTEGRITY" as const;

  constructor(message: string) {
    super(message);
    this.name = "OperationsIntegrityError";
  }
}

export class OperationsClosedError extends Error {
  readonly code = "CLOSED" as const;

  constructor() {
    super("The operations store is closed");
    this.name = "OperationsClosedError";
  }
}

export class BudgetExceededError extends Error {
  readonly code: "ATTEMPT_LIMIT_EXCEEDED" | "SPEND_LIMIT_EXCEEDED" | "WINDOW_CLOSED";

  constructor(
    code: "ATTEMPT_LIMIT_EXCEEDED" | "SPEND_LIMIT_EXCEEDED" | "WINDOW_CLOSED",
    message: string,
  ) {
    super(message);
    this.name = "BudgetExceededError";
    this.code = code;
  }
}

export class InvalidAttemptPermitError extends Error {
  readonly code = "INVALID_ATTEMPT_PERMIT" as const;

  constructor(message: string) {
    super(message);
    this.name = "InvalidAttemptPermitError";
  }
}
