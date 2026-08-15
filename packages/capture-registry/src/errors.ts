export class CaptureRegistryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

export class CaptureRegistryValidationError extends CaptureRegistryError {}

export type CaptureRegistryConflictCode =
  | "ATTEMPT_CONFLICT"
  | "CAPTURE_CONFLICT"
  | "REGISTRY_FULL"
  | "ATTEMPT_NOT_PENDING"
  | "ATTEMPT_NOT_COMMITTED"
  | "DELETION_CONFLICT";

export class CaptureRegistryConflictError extends CaptureRegistryError {
  readonly code: CaptureRegistryConflictCode;

  constructor(code: CaptureRegistryConflictCode, message: string) {
    super(message);
    this.code = code;
  }
}

export class CaptureRegistryIntegrityError extends CaptureRegistryError {
  constructor(message = "Capture registry authentication failed") {
    super(message);
  }
}

export class CaptureRegistrySecurityError extends CaptureRegistryError {
  constructor(message = "Capture registry path is not safe") {
    super(message);
  }
}

export class CaptureRegistryClosedError extends CaptureRegistryError {
  constructor() {
    super("Capture registry is closed");
  }
}
