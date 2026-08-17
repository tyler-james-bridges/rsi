export class SessionLifecycleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

export class SessionLifecycleValidationError extends SessionLifecycleError {
  constructor(message = "Session lifecycle input does not match its exact schema") {
    super(message);
  }
}

export type SessionLifecycleConflictCode =
  | "ACTIVE_SESSION_CONFLICT"
  | "RETRY_CONFLICT"
  | "SESSION_NOT_FOUND"
  | "TERMINAL_SESSION"
  | "TRANSITION_CONFLICT"
  | "WRITER_CONFLICT";

export class SessionLifecycleConflictError extends SessionLifecycleError {
  readonly code: SessionLifecycleConflictCode;

  constructor(code: SessionLifecycleConflictCode, message: string) {
    super(message);
    this.code = code;
  }
}

export class SessionLifecycleIntegrityError extends SessionLifecycleError {
  constructor(message = "Session lifecycle authentication failed") {
    super(message);
  }
}

export class SessionLifecycleClosedError extends SessionLifecycleError {
  constructor() {
    super("Session lifecycle coordinator is closed");
  }
}
