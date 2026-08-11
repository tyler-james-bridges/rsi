import type { CheckpointJournalVerificationReport, CheckpointStoreIssue } from "./types.js";

export class InvalidCheckpointError extends TypeError {
  constructor(message: string) {
    super(message);
    this.name = "InvalidCheckpointError";
  }
}

export class CheckpointConcurrencyError extends Error {
  constructor(message = "The checkpoint journal is locked by another operation") {
    super(message);
    this.name = "CheckpointConcurrencyError";
  }
}

export class CheckpointJournalIntegrityError extends Error {
  readonly report: CheckpointJournalVerificationReport;

  constructor(report: CheckpointJournalVerificationReport) {
    const summary = report.issues
      .slice(0, 3)
      .map((issue) => issue.code)
      .join(", ");
    super(`Checkpoint-journal verification failed${summary === "" ? "" : `: ${summary}`}`);
    this.name = "CheckpointJournalIntegrityError";
    this.report = report;
  }
}

export class CheckpointStoreIntegrityError extends Error {
  readonly issues: readonly CheckpointStoreIssue[];

  constructor(message: string, issues: readonly CheckpointStoreIssue[] = []) {
    super(message);
    this.name = "CheckpointStoreIntegrityError";
    this.issues = Object.freeze([...issues]);
  }
}
