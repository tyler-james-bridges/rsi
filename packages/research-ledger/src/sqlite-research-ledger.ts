import { types as utilTypes } from "node:util";

import { ResearchProposalV1Schema, type ResearchProposalV1 } from "@rsi/domain/proposals";
import {
  RuntimeBoundaryReceiptSchema,
  isRuntimeBoundaryAuthorization,
  type RuntimeBoundaryAuthorization,
} from "@rsi/runtime";
import { canonicalJson, SqliteEventStore, type StoredEvent } from "@rsi/store";
import { z } from "zod";

import { ResearchLedgerConflictError, ResearchLedgerIntegrityError } from "./errors.js";
import type {
  PersistResearchProposalInput,
  ResearchLedgerProjectionV1,
  ResearchProposalRecordV1,
} from "./types.js";

const RESEARCH_PROPOSAL_AGGREGATE = "research:proposals";
const RESEARCH_PROPOSAL_EVENT = "research.proposal.persisted.v1";
const AUTHENTIC_LEDGERS = new WeakSet<object>();

const CanonicalTimestampSchema = z
  .string()
  .max(32)
  .refine((value) => {
    const milliseconds = Date.parse(value);
    return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
  }, "must be a canonical UTC timestamp");

const StoredProposalPayloadSchema = z.strictObject({
  schemaVersion: z.literal(1),
  persistedAt: CanonicalTimestampSchema,
  proposal: ResearchProposalV1Schema,
});

type StoredProposalPayload = z.infer<typeof StoredProposalPayloadSchema>;

function idempotencyKey(proposalId: string): string {
  return `research-proposal-v1:${proposalId}`;
}

function assertPlainData(value: unknown, ancestors: WeakSet<object>): void {
  if (value === null || typeof value !== "object") return;
  if (utilTypes.isProxy(value) || ancestors.has(value)) {
    throw new TypeError("Research proposal input must be acyclic plain data");
  }
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) {
      throw new TypeError("Research proposal input must be plain data");
    }
    const keys = Reflect.ownKeys(value);
    if (
      keys.length !== value.length + 1 ||
      keys.some(
        (key) => typeof key !== "string" || (key !== "length" && !/^(0|[1-9][0-9]*)$/.test(key)),
      )
    ) {
      throw new TypeError("Research proposal input is invalid");
    }
    ancestors.add(value);
    try {
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
          throw new TypeError("Research proposal input is invalid");
        }
        assertPlainData(descriptor.value, ancestors);
      }
    } finally {
      ancestors.delete(value);
    }
    return;
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError("Research proposal input must be plain data");
  }
  ancestors.add(value);
  try {
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string") throw new TypeError("Research proposal input is invalid");
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
        throw new TypeError("Research proposal input is invalid");
      }
      assertPlainData(descriptor.value, ancestors);
    }
  } finally {
    ancestors.delete(value);
  }
}

function parsePersistInput(value: unknown): {
  authorization: PersistResearchProposalInput["authorization"];
  proposal: ResearchProposalV1;
} {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new TypeError("Research proposal persistence input is invalid");
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== 2 ||
    keys.some((key) => typeof key !== "string" || !["authorization", "proposal"].includes(key))
  ) {
    throw new TypeError("Research proposal persistence input is invalid");
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw new TypeError("Research proposal persistence input is invalid");
    }
  }
  const input = value as Readonly<Record<string, unknown>>;
  if (
    !isRuntimeBoundaryAuthorization(input.authorization) ||
    input.authorization.boundary !== "proposal_persist"
  ) {
    throw new TypeError("A genuine proposal persistence authorization is required");
  }
  assertPlainData(input.proposal, new WeakSet<object>());
  const proposal = ResearchProposalV1Schema.safeParse(input.proposal);
  if (!proposal.success) throw new TypeError("Research proposal is invalid");
  if (input.authorization.actionId !== proposal.data.proposalId) {
    throw new ResearchLedgerConflictError("Runtime authorization is not bound to this proposal");
  }
  return {
    authorization: input.authorization as PersistResearchProposalInput["authorization"],
    proposal: proposal.data,
  };
}

function parseStoredProposal(event: StoredEvent): ResearchProposalRecordV1 {
  if (event.aggregateId !== RESEARCH_PROPOSAL_AGGREGATE || event.type !== RESEARCH_PROPOSAL_EVENT) {
    throw new ResearchLedgerIntegrityError(`Foreign research event at sequence ${event.sequence}`);
  }
  const parsed = StoredProposalPayloadSchema.safeParse(event.payload);
  if (!parsed.success) {
    throw new ResearchLedgerIntegrityError(
      `Invalid proposal payload at sequence ${event.sequence}`,
    );
  }
  if (
    event.idempotencyKey !== idempotencyKey(parsed.data.proposal.proposalId) ||
    event.occurredAt !== parsed.data.persistedAt
  ) {
    throw new ResearchLedgerIntegrityError(
      `Invalid proposal binding at sequence ${event.sequence}`,
    );
  }
  return freezeRecord({
    schemaVersion: 1,
    eventHash: event.eventHash,
    eventSequence: event.sequence,
    persistedAt: parsed.data.persistedAt,
    proposal: parsed.data.proposal,
  });
}

function replay(store: SqliteEventStore): readonly ResearchProposalRecordV1[] {
  const integrity = store.verifyIntegrity();
  if (!integrity.valid) throw new ResearchLedgerIntegrityError();
  const records = store.list({ order: "asc" }).map(parseStoredProposal);
  const proposalIds = new Set<string>();
  for (const record of records) {
    if (proposalIds.has(record.proposal.proposalId)) {
      throw new ResearchLedgerIntegrityError("Duplicate proposal identity in research ledger");
    }
    proposalIds.add(record.proposal.proposalId);
  }
  return Object.freeze(records);
}

function assertAllowedReceipt(
  receiptValue: unknown,
  authorization: RuntimeBoundaryAuthorization<"proposal_persist">,
) {
  const result = RuntimeBoundaryReceiptSchema.safeParse(receiptValue);
  if (!result.success) {
    throw new ResearchLedgerConflictError("Runtime returned an invalid authorization receipt");
  }
  const receipt = result.data;
  if (
    receipt.decision !== "allowed" ||
    receipt.reason !== "ALLOWED" ||
    receipt.actionId !== authorization.actionId ||
    receipt.authorizationId !== authorization.authorizationId ||
    receipt.boundary !== authorization.boundary ||
    receipt.mode !== "PROPOSE_ONLY" ||
    receipt.mode !== authorization.requestedMode ||
    receipt.modeRevision !== authorization.requestedRevision ||
    receipt.processInstanceId !== authorization.processInstanceId ||
    Date.parse(receipt.checkedAt) < Date.parse(authorization.requestedAt) ||
    Date.parse(receipt.checkedAt) >= Date.parse(authorization.expiresAt)
  ) {
    throw new ResearchLedgerConflictError("Runtime did not authorize this proposal persistence");
  }
  return receipt;
}

function freezeRecord(record: ResearchProposalRecordV1): ResearchProposalRecordV1 {
  deepFreeze(record.proposal);
  return Object.freeze(record);
}

function deepFreeze(value: unknown): void {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return;
  for (const item of Object.values(value)) deepFreeze(item);
  Object.freeze(value);
}

function sameProposal(record: ResearchProposalRecordV1, proposal: ResearchProposalV1): boolean {
  return canonicalJson(record.proposal) === canonicalJson(proposal);
}

export class SqliteResearchLedger {
  readonly path: string;
  readonly #store: SqliteEventStore;

  static open(path: string): SqliteResearchLedger {
    if (typeof path !== "string" || path.trim() === "") {
      throw new TypeError("Research ledger path must be a non-empty string");
    }
    const store = new SqliteEventStore(path);
    try {
      replay(store);
      const ledger = new SqliteResearchLedger(store);
      AUTHENTIC_LEDGERS.add(ledger);
      Object.freeze(ledger);
      return ledger;
    } catch (error) {
      store.close();
      throw error;
    }
  }

  private constructor(store: SqliteEventStore) {
    this.#store = store;
    this.path = store.path;
  }

  persistProposal(inputValue: PersistResearchProposalInput): ResearchProposalRecordV1;
  persistProposal(inputValue: unknown): ResearchProposalRecordV1 {
    this.#assertAuthentic();
    const input = parsePersistInput(inputValue);
    const existing = this.#findById(input.proposal.proposalId);
    if (existing !== undefined) {
      if (!sameProposal(existing, input.proposal)) {
        throw new ResearchLedgerConflictError(
          "Proposal identity is already bound to different content",
        );
      }
      return existing;
    }

    const receipt = assertAllowedReceipt(input.authorization.consume(), input.authorization);
    if (
      Date.parse(receipt.checkedAt) < Date.parse(input.proposal.createdAt) ||
      Date.parse(receipt.checkedAt) > Date.parse(input.proposal.expiresAt)
    ) {
      throw new ResearchLedgerConflictError(
        "Research proposal must be persisted during its declared lifetime",
      );
    }
    const payload: StoredProposalPayload = {
      schemaVersion: 1,
      persistedAt: receipt.checkedAt,
      proposal: input.proposal,
    };
    try {
      const event = this.#store.append({
        aggregateId: RESEARCH_PROPOSAL_AGGREGATE,
        idempotencyKey: idempotencyKey(input.proposal.proposalId),
        occurredAt: receipt.checkedAt,
        payload,
        type: RESEARCH_PROPOSAL_EVENT,
      });
      return parseStoredProposal(event);
    } catch (error) {
      // A concurrent identical writer may have committed after our initial
      // lookup. Returning that exact record is safe; all other conflicts fail.
      const concurrent = this.#findById(input.proposal.proposalId);
      if (concurrent !== undefined && sameProposal(concurrent, input.proposal)) {
        return concurrent;
      }
      throw error;
    }
  }

  getProposal(proposalId: string): ResearchProposalRecordV1 | undefined {
    this.#assertAuthentic();
    if (!/^rsi-proposal:[A-Za-z0-9._-]{1,96}$/.test(proposalId)) {
      throw new TypeError("Proposal identity is invalid");
    }
    return this.#findById(proposalId);
  }

  getProjection(limit = 50): Readonly<ResearchLedgerProjectionV1> {
    this.#assertAuthentic();
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
      throw new TypeError("Research projection limit must be from 1 through 100");
    }
    const records = replay(this.#store);
    const proposals = [...records].reverse().slice(0, limit);
    let candidateCount = 0;
    let abstentionCount = 0;
    for (const record of records) {
      if (record.proposal.disposition.kind === "candidate") candidateCount += 1;
      else abstentionCount += 1;
    }
    return Object.freeze({
      schemaVersion: 1,
      candidateCount,
      abstentionCount,
      proposals: Object.freeze(proposals),
    });
  }

  close(): void {
    this.#assertAuthentic();
    this.#store.close();
  }

  [Symbol.dispose](): void {
    this.close();
  }

  #findById(proposalId: string): ResearchProposalRecordV1 | undefined {
    return replay(this.#store).find((record) => record.proposal.proposalId === proposalId);
  }

  #assertAuthentic(): void {
    if (
      !AUTHENTIC_LEDGERS.has(this) ||
      Object.getPrototypeOf(this) !== SqliteResearchLedger.prototype
    ) {
      throw new TypeError("Research ledger is unavailable");
    }
  }
}

Object.freeze(SqliteResearchLedger.prototype);
Object.freeze(SqliteResearchLedger);
