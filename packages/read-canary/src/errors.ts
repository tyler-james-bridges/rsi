export class XReadCanaryValidationError extends TypeError {
  readonly code = "VALIDATION" as const;

  constructor(message = "X read canary input is invalid") {
    super(message);
    this.name = "XReadCanaryValidationError";
  }
}

export class XReadCanaryConflictError extends Error {
  readonly code = "CONFLICT" as const;

  constructor(message: string) {
    super(message);
    this.name = "XReadCanaryConflictError";
  }
}
