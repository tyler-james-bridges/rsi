export class BaseRpcReadCanaryValidationError extends TypeError {
  readonly code = "VALIDATION" as const;

  constructor(message = "Base RPC read canary input is invalid") {
    super(message);
    this.name = "BaseRpcReadCanaryValidationError";
  }
}

export class BaseRpcReadCanaryConflictError extends Error {
  readonly code = "CONFLICT" as const;

  constructor(message: string) {
    super(message);
    this.name = "BaseRpcReadCanaryConflictError";
  }
}
