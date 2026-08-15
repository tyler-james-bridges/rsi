export type AlertConflictCode = "ALERT_CONFLICT" | "DELIVERY_CONFLICT" | "INVALID_TRANSITION";

export class AlertValidationError extends TypeError {
  readonly code = "VALIDATION" as const;

  constructor(message: string) {
    super(message);
    this.name = "AlertValidationError";
  }
}

export class AlertConflictError extends Error {
  readonly code: AlertConflictCode;

  constructor(code: AlertConflictCode, message: string) {
    super(message);
    this.name = "AlertConflictError";
    this.code = code;
  }
}

export class AlertIntegrityError extends Error {
  readonly code = "INTEGRITY" as const;

  constructor(message: string) {
    super(message);
    this.name = "AlertIntegrityError";
  }
}

export class AlertOutboxClosedError extends Error {
  readonly code = "CLOSED" as const;

  constructor() {
    super("The alert outbox is closed");
    this.name = "AlertOutboxClosedError";
  }
}
