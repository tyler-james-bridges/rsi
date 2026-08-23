export class ResearchLedgerIntegrityError extends Error {
  constructor(message = "Research ledger integrity verification failed") {
    super(message);
    this.name = "ResearchLedgerIntegrityError";
  }
}

export class ResearchLedgerConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ResearchLedgerConflictError";
  }
}
