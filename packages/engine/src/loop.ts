import { createHash } from "node:crypto";

import {
  StrategyPatchSchema,
  StrategySchema,
  type Strategy,
  type StrategyPatch,
} from "@rsi/domain";

export type CandidateStage =
  | "proposed"
  | "attack_passed"
  | "canary_active"
  | "canary_complete"
  | "evaluated"
  | "promoted"
  | "rejected";

export interface CandidateStrategy {
  candidateId: string;
  stage: CandidateStage;
  baseVersion: string;
  strategy: Strategy;
  patch: StrategyPatch;
  evidenceRoot: string;
  createdAt: string;
  rejectionReason?: string;
  evaluation?: {
    sampleSize: number;
    recommendPromotion: boolean;
    notes: string;
  };
}

export interface ImprovementLoopOptions {
  maxCanaryAllocationBps: number;
  maxCanaryDrawdownBps: number;
  minEvaluationSampleSize: number;
}

const DEFAULT_OPTIONS: ImprovementLoopOptions = {
  maxCanaryAllocationBps: 100,
  maxCanaryDrawdownBps: 500,
  minEvaluationSampleSize: 10,
};

function candidateId(value: unknown): string {
  return `candidate:${createHash("sha256")
    .update(JSON.stringify(value))
    .digest("hex")
    .slice(0, 24)}`;
}

export class RecursiveImprovementLoop {
  #champion: Strategy;
  readonly #candidates = new Map<string, CandidateStrategy>();
  readonly #options: ImprovementLoopOptions;

  constructor(rawChampion: Strategy, options: Partial<ImprovementLoopOptions> = {}) {
    this.#champion = StrategySchema.parse(structuredClone(rawChampion));
    this.#options = { ...DEFAULT_OPTIONS, ...options };
  }

  get champion(): Strategy {
    return structuredClone(this.#champion);
  }

  propose(
    nextVersion: string,
    rawPatch: unknown,
    evidenceRoot: string,
    now = new Date(),
  ): CandidateStrategy {
    const patch = StrategyPatchSchema.parse(rawPatch);
    const nextStrategy = StrategySchema.parse({
      ...this.#champion,
      ...patch,
      version: nextVersion,
      sourceWeights: {
        ...this.#champion.sourceWeights,
        ...patch.sourceWeights,
      },
    });

    if (nextStrategy.version === this.#champion.version) {
      throw new Error("candidate strategy must use a new version");
    }

    const candidate: CandidateStrategy = {
      candidateId: candidateId({
        baseVersion: this.#champion.version,
        evidenceRoot,
        nextStrategy,
      }),
      stage: "proposed",
      baseVersion: this.#champion.version,
      strategy: nextStrategy,
      patch,
      evidenceRoot,
      createdAt: now.toISOString(),
    };
    this.#candidates.set(candidate.candidateId, candidate);
    return structuredClone(candidate);
  }

  recordAttackResult(
    id: string,
    result: { passed: boolean; hardInvariantEscapes: number; notes: string },
  ): CandidateStrategy {
    const candidate = this.#requireStage(id, "proposed");
    if (!result.passed || result.hardInvariantEscapes !== 0) {
      candidate.stage = "rejected";
      candidate.rejectionReason = `adversarial replay failed: ${result.notes}`;
    } else {
      candidate.stage = "attack_passed";
    }
    return structuredClone(candidate);
  }

  startLiveCanary(id: string, allocationBps: number): CandidateStrategy {
    const candidate = this.#requireStage(id, "attack_passed");
    if (
      !Number.isInteger(allocationBps) ||
      allocationBps <= 0 ||
      allocationBps > this.#options.maxCanaryAllocationBps
    ) {
      throw new Error(
        `live canary allocation must be 1-${this.#options.maxCanaryAllocationBps} bps`,
      );
    }
    candidate.stage = "canary_active";
    return structuredClone(candidate);
  }

  recordCanaryResult(
    id: string,
    result: { hardInvariantEscapes: number; maxDrawdownBps: number; notes: string },
  ): CandidateStrategy {
    const candidate = this.#requireStage(id, "canary_active");
    if (
      result.hardInvariantEscapes !== 0 ||
      result.maxDrawdownBps > this.#options.maxCanaryDrawdownBps
    ) {
      candidate.stage = "rejected";
      candidate.rejectionReason = `live canary safety regression: ${result.notes}`;
    } else {
      candidate.stage = "canary_complete";
    }
    return structuredClone(candidate);
  }

  recordEvaluation(
    id: string,
    result: { sampleSize: number; recommendPromotion: boolean; notes: string },
  ): CandidateStrategy {
    const candidate = this.#requireStage(id, "canary_complete");
    if (result.sampleSize < this.#options.minEvaluationSampleSize) {
      throw new Error(
        `evaluation requires at least ${this.#options.minEvaluationSampleSize} observations`,
      );
    }
    candidate.stage = "evaluated";
    candidate.evaluation = { ...result };
    return structuredClone(candidate);
  }

  promote(id: string): Strategy {
    const candidate = this.#requireStage(id, "evaluated");
    if (!candidate.evaluation?.recommendPromotion) {
      candidate.stage = "rejected";
      candidate.rejectionReason = "evaluator did not recommend promotion";
      throw new Error(candidate.rejectionReason);
    }
    if (candidate.baseVersion !== this.#champion.version) {
      candidate.stage = "rejected";
      candidate.rejectionReason = "champion changed while candidate was under evaluation";
      throw new Error(candidate.rejectionReason);
    }

    candidate.stage = "promoted";
    this.#champion = structuredClone(candidate.strategy);
    return this.champion;
  }

  getCandidate(id: string): CandidateStrategy | undefined {
    const candidate = this.#candidates.get(id);
    return candidate === undefined ? undefined : structuredClone(candidate);
  }

  #requireStage(id: string, stage: CandidateStage): CandidateStrategy {
    const candidate = this.#candidates.get(id);
    if (candidate === undefined) {
      throw new Error(`unknown candidate: ${id}`);
    }
    if (candidate.stage !== stage) {
      throw new Error(`candidate ${id} is ${candidate.stage}; expected ${stage}`);
    }
    return candidate;
  }
}
