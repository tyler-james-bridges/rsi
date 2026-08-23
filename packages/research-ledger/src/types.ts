import type { ResearchProposalV1 } from "@rsi/domain/proposals";
import type { RuntimeBoundaryAuthorization } from "@rsi/runtime";

export interface PersistResearchProposalInput {
  readonly authorization: RuntimeBoundaryAuthorization<"proposal_persist">;
  readonly proposal: ResearchProposalV1;
}

export interface ResearchProposalRecordV1 {
  readonly schemaVersion: 1;
  readonly eventHash: string;
  readonly eventSequence: number;
  readonly persistedAt: string;
  readonly proposal: ResearchProposalV1;
}

export interface ResearchLedgerProjectionV1 {
  readonly schemaVersion: 1;
  readonly candidateCount: number;
  readonly abstentionCount: number;
  readonly proposals: readonly ResearchProposalRecordV1[];
}
