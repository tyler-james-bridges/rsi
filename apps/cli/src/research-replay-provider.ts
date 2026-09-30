import { randomUUID } from "node:crypto";

import type {
  OperatorResearchReplayCommand,
  OperatorResearchReplayProvider,
  OperatorResearchReplayReceiptV1,
} from "@rsi/operator";
import {
  RECORDED_REPLAY_EVALUATED_AT,
  RecordedReplayScenarioSchema,
  assessRecordedReplay,
  buildRecordedReplayProposal,
} from "@rsi/research/replay";
import { SqliteResearchLedger, type ResearchProposalRecordV1 } from "@rsi/research-ledger";
import { RuntimeConflictError, SqliteRuntimeController } from "@rsi/runtime";

const RECORDED_REPLAY_STRATEGY_VERSION = "rsi-recorded-replay-v1";

function proposalIdFor(command: OperatorResearchReplayCommand): string {
  return `rsi-proposal:${command.scenario}-${command.requestId}`;
}

function replayReceipt(
  command: OperatorResearchReplayCommand,
  record: ResearchProposalRecordV1,
  duplicate: boolean,
): Readonly<OperatorResearchReplayReceiptV1> {
  if (record.proposal.strategyVersion !== RECORDED_REPLAY_STRATEGY_VERSION) {
    throw new TypeError("Recorded replay identity is bound to a different strategy");
  }
  return Object.freeze({
    schemaVersion: 1,
    kind: "recorded_fixture_replay",
    requestId: command.requestId,
    scenario: command.scenario,
    proposalId: record.proposal.proposalId,
    disposition: record.proposal.disposition,
    replayEvaluatedAt: RECORDED_REPLAY_EVALUATED_AT,
    persistedAt: record.persistedAt,
    duplicate,
  });
}

export interface RecordedResearchReplayProviderOptions {
  readonly runtime: SqliteRuntimeController;
  readonly research: SqliteResearchLedger;
  readonly isClosing?: () => boolean;
}

export interface RecordedResearchReplayProvider extends OperatorResearchReplayProvider {
  executeResearchReplay(
    command: OperatorResearchReplayCommand,
  ): Readonly<OperatorResearchReplayReceiptV1>;
}

export function createRecordedResearchReplayProvider(
  options: Readonly<RecordedResearchReplayProviderOptions>,
): RecordedResearchReplayProvider {
  const isClosing = options.isClosing ?? (() => false);
  return Object.freeze({
    executeResearchReplay(
      command: OperatorResearchReplayCommand,
    ): Readonly<OperatorResearchReplayReceiptV1> {
      if (isClosing()) {
        throw new RuntimeConflictError(
          "STALE_STATE",
          "Recorded replay is unavailable while the Stage 0 host is closing",
        );
      }
      const scenario = RecordedReplayScenarioSchema.parse(command.scenario);
      const proposalId = proposalIdFor(command);
      const collectionAuthorization = options.runtime.requestBoundaryAuthorization({
        actionId: `recorded-replay:${scenario}:${command.requestId}`,
        authorizationId: randomUUID(),
        boundary: "research_collection",
      });
      let existing: ResearchProposalRecordV1 | undefined;
      let assessment: ReturnType<typeof assessRecordedReplay> | undefined;
      collectionAuthorization.consumeAndDispatch(() => {
        existing = options.research.getProposal(proposalId);
        if (existing === undefined) assessment = assessRecordedReplay(scenario);
      });

      let proposal: ReturnType<typeof buildRecordedReplayProposal> | undefined;
      const completion = collectionAuthorization.guardCompletion((facts) => {
        if (existing !== undefined) return;
        if (assessment === undefined) {
          throw new TypeError("Recorded replay produced no assessment");
        }
        proposal = buildRecordedReplayProposal({
          assessment,
          requestId: command.requestId,
          createdAt: facts.checkedAt,
        });
      });
      if (completion.decision !== "allowed") {
        throw new RuntimeConflictError(
          "STALE_STATE",
          "Runtime mode changed before the recorded replay completed",
        );
      }
      if (existing !== undefined) {
        options.runtime
          .requestBoundaryAuthorization({
            actionId: proposalId,
            authorizationId: randomUUID(),
            boundary: "proposal_persist",
          })
          .consume();
        return replayReceipt(command, existing, true);
      }
      if (proposal === undefined) throw new TypeError("Recorded replay produced no proposal");

      const persistenceAuthorization = options.runtime.requestBoundaryAuthorization({
        actionId: proposalId,
        authorizationId: randomUUID(),
        boundary: "proposal_persist",
      });
      const record = options.research.persistProposal({
        authorization: persistenceAuthorization,
        proposal,
      });
      return replayReceipt(command, record, false);
    },
  });
}
