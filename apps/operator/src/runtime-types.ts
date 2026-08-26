export type RuntimeOperatorAction =
  "runtime-enter-propose-only" | "runtime-enter-research" | "runtime-stop";

export type RuntimeOperatorControlCommand =
  | Readonly<{ action: "runtime-stop"; requestId: string }>
  | Readonly<{
      action: "runtime-enter-research";
      expectedMode: "PROPOSE_ONLY" | "STOPPED";
      expectedRevision: number;
      requestId: string;
    }>
  | Readonly<{
      action: "runtime-enter-propose-only";
      expectedMode: "RESEARCH";
      expectedRevision: number;
      requestId: string;
    }>;

export interface OperatorRuntimeProvider {
  readonly supportedActions: readonly RuntimeOperatorAction[];
  executeRuntimeControl(command: RuntimeOperatorControlCommand): Promise<unknown> | unknown;
  getRuntimeSnapshot(): Promise<unknown> | unknown;
}

export interface OperatorRuntimeSnapshotV1 {
  readonly schemaVersion: 1;
  readonly mode: "PROPOSE_ONLY" | "RESEARCH" | "STOPPED";
  readonly revision: number;
  readonly modeChangedAt: string;
  readonly processInstanceId: string;
  readonly auditHead: Readonly<{
    sequence: number;
    hash: string;
  }>;
  readonly capabilities: Readonly<{
    researchCollection: boolean;
    proposalPersistence: boolean;
    policyApproval: false;
    paidRead: false;
    transactionBroadcast: false;
    walletSign: false;
    executionAdapter: false;
    externalPublish: false;
  }>;
}
