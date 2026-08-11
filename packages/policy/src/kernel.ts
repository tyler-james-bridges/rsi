import { createHash } from "node:crypto";

import {
  ObservationSchema,
  PolicyConfigSchema,
  ExecutionIntentSchema,
  assetKey,
  type ExecutionIntent,
  type Observation,
  type PolicyConfig,
} from "@rsi/domain";

export type PolicyReasonCode =
  | "INVALID_INTENT"
  | "INVALID_EVIDENCE"
  | "POLICY_VERSION_MISMATCH"
  | "POLICY_HASH_MISMATCH"
  | "DUPLICATE_INTENT"
  | "INTENT_TIME_INVALID"
  | "INTENT_EXPIRED"
  | "INTENT_FROM_FUTURE"
  | "CHAIN_NOT_ALLOWED"
  | "MARKETPLACE_TARGET_NOT_ALLOWED"
  | "COLLECTION_NOT_ALLOWED"
  | "PAYMENT_ASSET_NOT_ALLOWED"
  | "SPEND_LIMIT_MISSING"
  | "SPEND_LIMIT_EXCEEDED"
  | "DAILY_SPEND_LIMIT_EXCEEDED"
  | "MISSING_EVIDENCE"
  | "STALE_EVIDENCE"
  | "EVIDENCE_INTEGRITY_FLAG"
  | "EVIDENCE_ASSET_MISMATCH"
  | "INSUFFICIENT_INDEPENDENT_EVIDENCE"
  | "CANONICAL_EVIDENCE_MISSING";

export interface PolicyRejection {
  approved: false;
  decisionId: string;
  evaluatedAt: string;
  policyHash: string;
  reasons: readonly PolicyReasonCode[];
}

export interface PolicyApproval {
  approved: true;
  decisionId: string;
  evaluatedAt: string;
  policyHash: string;
  intentHash: string;
  reasons: readonly [];
  intent: ExecutionIntent;
}

export type PolicyDecision = PolicyApproval | PolicyRejection;

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }

  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nested]) => [key, canonicalize(nested)]),
    );
  }

  return value;
}

export function canonicalHash(value: unknown): `0x${string}` {
  const serialized = JSON.stringify(canonicalize(value));
  return `0x${createHash("sha256").update(serialized).digest("hex")}`;
}

export function executionIntentHash(rawIntent: unknown): `0x${string}` {
  return canonicalHash(ExecutionIntentSchema.parse(rawIntent));
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const nested of Object.values(value as Record<string, unknown>)) {
      deepFreeze(nested);
    }
    Object.freeze(value);
  }
  return value;
}

function includesContract(
  entries: readonly { chainId: number; address: string }[],
  chainId: number,
  address: string,
): boolean {
  return entries.some(
    (entry) => entry.chainId === chainId && entry.address.toLowerCase() === address.toLowerCase(),
  );
}

function claimMatchesIntent(observation: Observation, intent: ExecutionIntent): boolean {
  const action = intent.action;
  return observation.claims.some(
    (claim) =>
      claim.asset.chainId === action.chainId &&
      claim.asset.address.toLowerCase() === action.collectionContract.toLowerCase() &&
      claim.asset.tokenId === action.tokenId,
  );
}

function isCanonicalMarketplaceEvidence(
  observation: Observation,
  intent: ExecutionIntent,
): boolean {
  if (observation.source.kind !== "onchain" && observation.source.kind !== "opensea") {
    return false;
  }

  const canonicalClaimTypes = new Set([
    "collection_identity",
    "ownership",
    "listing",
    "executable_bid",
  ]);

  return observation.claims.some(
    (claim) =>
      canonicalClaimTypes.has(claim.type) &&
      claim.asset.chainId === intent.action.chainId &&
      claim.asset.address.toLowerCase() === intent.action.collectionContract.toLowerCase() &&
      claim.asset.tokenId === intent.action.tokenId,
  );
}

function utcDay(date: Date): string {
  return date.toISOString().slice(0, 10);
}

export class PolicyKernel {
  readonly policyHash: `0x${string}`;
  readonly policy: Readonly<PolicyConfig>;

  readonly #processedIntentIds = new Set<string>();
  readonly #dailySpend = new Map<string, bigint>();

  constructor(rawPolicy: PolicyConfig) {
    const policy = PolicyConfigSchema.parse(structuredClone(rawPolicy));
    this.policy = deepFreeze(policy);
    this.policyHash = canonicalHash(policy);
  }

  authorize(
    rawIntent: unknown,
    rawObservations: readonly unknown[],
    now = new Date(),
  ): PolicyDecision {
    const intentResult = ExecutionIntentSchema.safeParse(rawIntent);
    if (!intentResult.success) {
      return this.#reject(["INVALID_INTENT"], now);
    }

    const observationsResult = rawObservations.map((value) => ObservationSchema.safeParse(value));
    if (observationsResult.some((result) => !result.success)) {
      return this.#reject(["INVALID_EVIDENCE"], now, intentResult.data.intentId);
    }

    const intent = intentResult.data;
    const observations = observationsResult.map((result) => {
      if (!result.success) throw new Error("unreachable invalid observation");
      return result.data;
    });
    const reasons = this.#evaluate(intent, observations, now);

    if (reasons.length > 0) {
      return this.#reject(reasons, now, intent.intentId);
    }

    this.#processedIntentIds.add(intent.intentId);
    const spendKey = this.#dailySpendKey(intent, now);
    const previousSpend = this.#dailySpend.get(spendKey) ?? 0n;
    this.#dailySpend.set(spendKey, previousSpend + BigInt(intent.action.maxTotalSpend));

    const approvedIntent = deepFreeze(structuredClone(intent));
    const intentHash = executionIntentHash(approvedIntent);
    const evaluatedAt = now.toISOString();
    return deepFreeze({
      approved: true,
      decisionId: canonicalHash({
        approved: true,
        evaluatedAt,
        intentHash,
        policyHash: this.policyHash,
      }),
      evaluatedAt,
      policyHash: this.policyHash,
      intentHash,
      reasons: [],
      intent: approvedIntent,
    });
  }

  #evaluate(
    intent: ExecutionIntent,
    observations: readonly Observation[],
    now: Date,
  ): PolicyReasonCode[] {
    const reasons = new Set<PolicyReasonCode>();
    const action = intent.action;
    const createdAt = new Date(intent.createdAt);
    const expiresAt = new Date(intent.expiresAt);
    const maxClockSkewMs = this.policy.maxClockSkewSeconds * 1_000;

    if (intent.policyVersion !== this.policy.policyVersion) {
      reasons.add("POLICY_VERSION_MISMATCH");
    }
    if (intent.policyHash.toLowerCase() !== this.policyHash.toLowerCase()) {
      reasons.add("POLICY_HASH_MISMATCH");
    }
    if (this.#processedIntentIds.has(intent.intentId)) {
      reasons.add("DUPLICATE_INTENT");
    }
    if (createdAt.getTime() >= expiresAt.getTime()) {
      reasons.add("INTENT_TIME_INVALID");
    }
    if (expiresAt.getTime() <= now.getTime()) {
      reasons.add("INTENT_EXPIRED");
    }
    if (createdAt.getTime() > now.getTime() + maxClockSkewMs) {
      reasons.add("INTENT_FROM_FUTURE");
    }
    if (!this.policy.allowedChains.includes(action.chainId)) {
      reasons.add("CHAIN_NOT_ALLOWED");
    }
    if (
      !includesContract(
        this.policy.allowedMarketplaceTargets,
        action.chainId,
        action.targetContract,
      )
    ) {
      reasons.add("MARKETPLACE_TARGET_NOT_ALLOWED");
    }
    if (
      !includesContract(this.policy.allowedCollections, action.chainId, action.collectionContract)
    ) {
      reasons.add("COLLECTION_NOT_ALLOWED");
    }
    if (!includesContract(this.policy.allowedPaymentAssets, action.chainId, action.paymentAsset)) {
      reasons.add("PAYMENT_ASSET_NOT_ALLOWED");
    }

    const paymentAssetKey = assetKey(action.chainId, action.paymentAsset);
    const perTransactionLimit = this.policy.maxPerTransactionByAsset[paymentAssetKey];
    const dailyLimit = this.policy.maxDailySpendByAsset[paymentAssetKey];
    if (perTransactionLimit === undefined || dailyLimit === undefined) {
      reasons.add("SPEND_LIMIT_MISSING");
    } else {
      const requestedSpend = BigInt(action.maxTotalSpend);
      if (requestedSpend > BigInt(perTransactionLimit)) {
        reasons.add("SPEND_LIMIT_EXCEEDED");
      }
      const priorDailySpend = this.#dailySpend.get(this.#dailySpendKey(intent, now)) ?? 0n;
      if (priorDailySpend + requestedSpend > BigInt(dailyLimit)) {
        reasons.add("DAILY_SPEND_LIMIT_EXCEEDED");
      }
    }

    const observationsById = new Map(
      observations.map((observation) => [observation.observationId, observation]),
    );
    const referenced = intent.evidenceIds
      .map((id) => observationsById.get(id))
      .filter((value): value is Observation => value !== undefined);

    if (referenced.length !== intent.evidenceIds.length) {
      reasons.add("MISSING_EVIDENCE");
    }

    const maxEvidenceAgeMs = this.policy.maxEvidenceAgeSeconds * 1_000;
    for (const observation of referenced) {
      const acquiredAt = new Date(observation.acquiredAt);
      const validUntil = new Date(observation.validUntil);
      if (
        now.getTime() - acquiredAt.getTime() > maxEvidenceAgeMs ||
        validUntil.getTime() <= now.getTime()
      ) {
        reasons.add("STALE_EVIDENCE");
      }
      if (
        observation.integrity.injectionFlags.length > 0 ||
        observation.integrity.homographFlags.length > 0
      ) {
        reasons.add("EVIDENCE_INTEGRITY_FLAG");
      }
      if (!claimMatchesIntent(observation, intent)) {
        reasons.add("EVIDENCE_ASSET_MISMATCH");
      }
    }

    const independentClusters = new Set(
      referenced.map((observation) => observation.integrity.coordinationClusterId),
    );
    if (independentClusters.size < this.policy.minIndependentEvidenceClusters) {
      reasons.add("INSUFFICIENT_INDEPENDENT_EVIDENCE");
    }

    if (
      this.policy.requireCanonicalMarketplaceEvidence &&
      !referenced.some((observation) => isCanonicalMarketplaceEvidence(observation, intent))
    ) {
      reasons.add("CANONICAL_EVIDENCE_MISSING");
    }

    return [...reasons].sort();
  }

  #dailySpendKey(intent: ExecutionIntent, now: Date): string {
    return `${utcDay(now)}:${assetKey(intent.action.chainId, intent.action.paymentAsset)}`;
  }

  #reject(reasons: readonly PolicyReasonCode[], now: Date, intentId = "invalid"): PolicyRejection {
    const evaluatedAt = now.toISOString();
    const sortedReasons = [...new Set(reasons)].sort();
    return deepFreeze({
      approved: false,
      decisionId: canonicalHash({
        approved: false,
        evaluatedAt,
        intentId,
        policyHash: this.policyHash,
        reasons: sortedReasons,
      }),
      evaluatedAt,
      policyHash: this.policyHash,
      reasons: sortedReasons,
    });
  }
}
