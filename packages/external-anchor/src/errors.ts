export class ExternalAnchorError extends Error {
  override readonly name: string = "ExternalAnchorError";
}

export class ExternalAnchorValidationError extends ExternalAnchorError {
  override readonly name = "ExternalAnchorValidationError";
}

export class ExternalAnchorIntegrityError extends ExternalAnchorError {
  override readonly name = "ExternalAnchorIntegrityError";
}

export class ExternalAnchorConflictError extends ExternalAnchorError {
  override readonly name = "ExternalAnchorConflictError";

  constructor(
    readonly code: "ANCHOR_CONFLICT" | "JOURNAL_FORK" | "OBJECT_CONFLICT",
    message: string,
  ) {
    super(message);
  }
}

export type ExternalAnchorTransportErrorCode =
  "CONNECTION" | "RATE_LIMITED" | "TIMEOUT" | "TEMPORARY_UNAVAILABLE";

export class ExternalAnchorTransportError extends ExternalAnchorError {
  override readonly name = "ExternalAnchorTransportError";

  constructor(
    readonly code: ExternalAnchorTransportErrorCode,
    message = "External anchor transport failed",
  ) {
    super(message);
  }
}

export class ExternalAnchorOutboxClosedError extends ExternalAnchorError {
  override readonly name = "ExternalAnchorOutboxClosedError";

  constructor() {
    super("External anchor outbox is closed");
  }
}
