export type SnapshotVaultErrorCode =
  "CLOSED" | "CONFLICT" | "INTEGRITY" | "NOT_FOUND" | "SECURITY" | "VALIDATION";

export class SnapshotVaultError extends Error {
  readonly code: SnapshotVaultErrorCode;

  constructor(code: SnapshotVaultErrorCode, message: string) {
    super(message);
    this.name = "SnapshotVaultError";
    this.code = code;
  }
}

export class SnapshotValidationError extends SnapshotVaultError {
  constructor(message: string) {
    super("VALIDATION", message);
    this.name = "SnapshotValidationError";
  }
}

export class SnapshotNotFoundError extends SnapshotVaultError {
  constructor() {
    super("NOT_FOUND", "Snapshot not found");
    this.name = "SnapshotNotFoundError";
  }
}

export class SnapshotIntegrityError extends SnapshotVaultError {
  constructor() {
    super("INTEGRITY", "Snapshot authentication or integrity verification failed");
    this.name = "SnapshotIntegrityError";
  }
}

export class SnapshotConflictError extends SnapshotVaultError {
  constructor() {
    super("CONFLICT", "Snapshot address already exists with different metadata");
    this.name = "SnapshotConflictError";
  }
}

export class SnapshotSecurityError extends SnapshotVaultError {
  constructor(message = "Snapshot vault filesystem safety check failed") {
    super("SECURITY", message);
    this.name = "SnapshotSecurityError";
  }
}

export class SnapshotVaultClosedError extends SnapshotVaultError {
  constructor() {
    super("CLOSED", "Snapshot vault is closed");
    this.name = "SnapshotVaultClosedError";
  }
}
