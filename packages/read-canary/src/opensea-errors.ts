export class OpenSeaReadCanaryValidationError extends TypeError {
  readonly code = "VALIDATION" as const;

  constructor(message = "OpenSea read canary input is invalid") {
    super(message);
    this.name = "OpenSeaReadCanaryValidationError";
  }
}

export class OpenSeaReadCanaryConflictError extends Error {
  readonly code = "CONFLICT" as const;

  constructor(message: string) {
    super(message);
    this.name = "OpenSeaReadCanaryConflictError";
  }
}
