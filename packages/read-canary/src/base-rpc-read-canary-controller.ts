import { randomUUID } from "node:crypto";
import { types as utilTypes } from "node:util";

import { SqliteCaptureRegistry, isSqliteCaptureRegistry } from "@rsi/capture-registry";
import {
  ingestBaseRpcAnchor,
  type BaseRpcAnchorIngestionResult,
} from "@rsi/ingestion/base-rpc-anchor";
import { SqliteOperationsStore, isSqliteOperationsStore } from "@rsi/operations";
import {
  RuntimeBoundaryDeniedError,
  SqliteRuntimeController,
  isSqliteRuntimeController,
  type RuntimeBoundaryAuthorization,
} from "@rsi/runtime";
import { SqliteEventStore, isSqliteEventStore } from "@rsi/store";
import { SnapshotVault, isSnapshotVault } from "@rsi/vault";
import {
  BASE_RPC_ANCHOR_BODY,
  BASE_RPC_ANCHOR_OPERATION,
  BASE_RPC_ANCHOR_RESERVED_ATOMIC,
  baseRpcAnchorRuntimeActionId,
  createBaseRpcAnchorCollector,
  isBaseRpcCollectorError,
  prepareBaseRpcAnchorCollectorRequest,
} from "@rsi/base-rpc-collector";

import {
  BASE_RPC_READ_CANARY_ENDPOINT,
  BASE_RPC_READ_CANARY_LEDGER_RESERVE_USD_MICRO,
  BASE_RPC_READ_CANARY_OPERATION,
  BASE_RPC_READ_CANARY_PLAN_ID,
  BASE_RPC_READ_CANARY_PROVIDER_ID,
  BASE_RPC_READ_CANARY_REQUEST_FINGERPRINT,
  BASE_RPC_READ_CANARY_RPC_METHODS,
  baseRpcReadCanaryRuntimeActionId,
} from "./base-rpc-constants.js";
import {
  BaseRpcReadCanaryConflictError,
  BaseRpcReadCanaryValidationError,
} from "./base-rpc-errors.js";
import {
  BaseRpcReadCanaryPreparedEventPayloadSchema,
  BaseRpcReadCanaryRunCommandSchema,
  parseBaseRpcReadCanaryInput,
} from "./base-rpc-schemas.js";
import type {
  BaseRpcReadCanaryDurableReceiptV1,
  BaseRpcReadCanaryFailureCode,
  BaseRpcReadCanaryProjectionV1,
  BaseRpcReadCanaryReceiptV1,
  BaseRpcReadCanaryRunCommand,
} from "./base-rpc-types.js";
import {
  AGGREGATE_ID,
  PREPARED_EVENT_TYPE,
  PREPARED_KEY,
  finalizeResult,
  getBaseRpcReadCanaryPlan,
  jsonValue,
  loadResult,
  now,
  parsePreparedEvent,
  persistLiveResult,
  projectPublicReceipt,
  readBaseRpcReadCanaryProjection,
  receiptKey,
  recoverPreparedCanary,
  terminalizeFailure,
  type BaseRpcReadCanaryRecoveryOptions,
  type PreparedPayload,
} from "./base-rpc-recovery-core.js";

const AUTHENTIC_CONTROLLERS = new WeakSet<object>();

export interface BaseRpcReadCanaryControllerOptions {
  readonly runtime: SqliteRuntimeController;
  readonly operationsStore: SqliteOperationsStore;
  readonly captureRegistry: SqliteCaptureRegistry;
  readonly eventStore: SqliteEventStore;
  readonly vault: SnapshotVault;
  readonly apiKey: string;
}

function exactOptions(
  value: BaseRpcReadCanaryControllerOptions,
): BaseRpcReadCanaryControllerOptions {
  if (
    typeof value !== "object" ||
    value === null ||
    utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new BaseRpcReadCanaryValidationError("Base RPC read canary options are invalid");
  }
  const expected = [
    "runtime",
    "operationsStore",
    "captureRegistry",
    "eventStore",
    "vault",
    "apiKey",
  ];
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expected.length ||
    keys.some((key) => typeof key !== "string" || !expected.includes(key))
  ) {
    throw new BaseRpcReadCanaryValidationError("Base RPC read canary options are invalid");
  }
  for (const key of keys) {
    if (typeof key !== "string") throw new BaseRpcReadCanaryValidationError();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw new BaseRpcReadCanaryValidationError("Base RPC read canary options are invalid");
    }
  }
  if (
    !isSqliteRuntimeController(value.runtime) ||
    !isSqliteOperationsStore(value.operationsStore) ||
    !isSqliteCaptureRegistry(value.captureRegistry) ||
    !isSqliteEventStore(value.eventStore) ||
    !isSnapshotVault(value.vault) ||
    typeof value.apiKey !== "string"
  ) {
    throw new BaseRpcReadCanaryValidationError("Authentic canary dependencies are required");
  }
  return value;
}

function safeFailureCode(error: unknown): BaseRpcReadCanaryFailureCode {
  if (isBaseRpcCollectorError(error)) return error.code;
  if (error instanceof RuntimeBoundaryDeniedError) return "RUNTIME_DENIED";
  return "UNKNOWN_FAILURE";
}

export { getBaseRpcReadCanaryPlan, readBaseRpcReadCanaryProjection };

export class BaseRpcReadCanaryController {
  readonly #runtime: SqliteRuntimeController;
  readonly #operationsStore: SqliteOperationsStore;
  readonly #captureRegistry: SqliteCaptureRegistry;
  readonly #eventStore: SqliteEventStore;
  readonly #vault: SnapshotVault;
  #apiKey: string | null;
  #activeAbort: AbortController | null = null;
  #used = false;

  constructor(optionsValue: BaseRpcReadCanaryControllerOptions) {
    const options = exactOptions(optionsValue);
    this.#runtime = options.runtime;
    this.#operationsStore = options.operationsStore;
    this.#captureRegistry = options.captureRegistry;
    this.#eventStore = options.eventStore;
    this.#vault = options.vault;
    this.#apiKey = options.apiKey;
    AUTHENTIC_CONTROLLERS.add(this);
  }

  get running(): boolean {
    this.#assertAuthentic();
    return this.#activeAbort !== null;
  }

  getProjection(): Readonly<BaseRpcReadCanaryProjectionV1> {
    this.#assertAuthentic();
    return readBaseRpcReadCanaryProjection(this.#eventStore, "configured", this.running);
  }

  abortActive(): void {
    this.#assertAuthentic();
    this.#activeAbort?.abort();
  }

  async execute(commandValue: unknown): Promise<Readonly<BaseRpcReadCanaryReceiptV1>> {
    this.#assertAuthentic();
    const command = parseBaseRpcReadCanaryInput(
      BaseRpcReadCanaryRunCommandSchema,
      commandValue,
      "Base RPC read canary command",
    );
    const preparedEvent = this.#eventStore.getByIdempotencyKey(PREPARED_KEY);
    if (preparedEvent !== undefined) {
      const prepared = parsePreparedEvent(preparedEvent);
      if (
        prepared.requestId !== command.requestId ||
        prepared.expectedRuntimeRevision !== command.expectedRuntimeRevision
      ) {
        throw new BaseRpcReadCanaryConflictError(
          "The one-shot Base RPC read canary is already claimed",
        );
      }
      const existingReceipt = this.#eventStore.getByIdempotencyKey(receiptKey(command.requestId));
      if (existingReceipt !== undefined) {
        return projectPublicReceipt(
          await recoverPreparedCanary(this.#recoveryDependencies(), prepared),
        );
      }
      if (this.#activeAbort !== null) {
        throw new BaseRpcReadCanaryConflictError("A Base RPC read canary is already running");
      }
      if (this.#used || this.#apiKey === null) {
        throw new BaseRpcReadCanaryConflictError("This canary controller is one-shot");
      }
      this.#activeAbort = new AbortController();
      try {
        return projectPublicReceipt(await this.#resume(command, prepared));
      } finally {
        this.#apiKey = null;
        this.#used = true;
        this.#activeAbort = null;
      }
    }
    if (this.#activeAbort !== null) {
      throw new BaseRpcReadCanaryConflictError("A Base RPC read canary is already running");
    }
    if (this.#used || this.#apiKey === null) {
      throw new BaseRpcReadCanaryConflictError("This canary controller is one-shot");
    }

    this.#activeAbort = new AbortController();
    try {
      return projectPublicReceipt(await this.#run(command, this.#activeAbort.signal));
    } finally {
      this.#apiKey = null;
      this.#used = true;
      this.#activeAbort = null;
    }
  }

  close(): void {
    this.#assertAuthentic();
    this.#activeAbort?.abort();
    this.#apiKey = null;
    this.#used = true;
  }

  async #run(
    command: BaseRpcReadCanaryRunCommand,
    signal: AbortSignal,
  ): Promise<Readonly<BaseRpcReadCanaryDurableReceiptV1>> {
    const snapshot = this.#runtime.getSnapshot();
    if (snapshot.mode !== "RESEARCH" || snapshot.revision !== command.expectedRuntimeRevision) {
      throw new BaseRpcReadCanaryConflictError("Runtime state changed before canary preparation");
    }

    const request = prepareBaseRpcAnchorCollectorRequest();
    if (
      request.fingerprint !== BASE_RPC_READ_CANARY_REQUEST_FINGERPRINT ||
      request.body !== BASE_RPC_ANCHOR_BODY ||
      request.method !== "POST" ||
      request.url !== BASE_RPC_READ_CANARY_ENDPOINT ||
      BASE_RPC_ANCHOR_OPERATION !== BASE_RPC_READ_CANARY_OPERATION ||
      BASE_RPC_ANCHOR_RESERVED_ATOMIC !== BASE_RPC_READ_CANARY_LEDGER_RESERVE_USD_MICRO
    ) {
      throw new BaseRpcReadCanaryConflictError("Canary request contract changed");
    }
    const permit = SqliteOperationsStore.createAttemptPermit();
    const actionId = baseRpcAnchorRuntimeActionId(permit.attemptId, request.fingerprint);
    if (actionId !== baseRpcReadCanaryRuntimeActionId(permit.attemptId)) {
      throw new BaseRpcReadCanaryConflictError("Canary runtime action binding changed");
    }
    const runtimeAuthorization = this.#runtime.requestBoundaryAuthorization({
      actionId,
      authorizationId: randomUUID(),
      boundary: "research_collection",
    });
    if (
      runtimeAuthorization.requestedRevision !== command.expectedRuntimeRevision ||
      runtimeAuthorization.requestedMode !== "RESEARCH"
    ) {
      throw new BaseRpcReadCanaryConflictError("Runtime state changed before canary authorization");
    }

    const budgetId = randomUUID();
    const prepared = BaseRpcReadCanaryPreparedEventPayloadSchema.parse({
      schemaVersion: 1,
      planId: BASE_RPC_READ_CANARY_PLAN_ID,
      providerId: BASE_RPC_READ_CANARY_PROVIDER_ID,
      requestId: command.requestId,
      attemptId: permit.attemptId,
      budgetId,
      expectedRuntimeRevision: command.expectedRuntimeRevision,
      runtimeAuthorizationId: runtimeAuthorization.authorizationId,
      runtimeProcessInstanceId: runtimeAuthorization.processInstanceId,
      requestFingerprint: request.fingerprint,
      rpcMethods: [...BASE_RPC_READ_CANARY_RPC_METHODS],
      blockTag: "finalized",
      preparedAt: runtimeAuthorization.requestedAt,
      expiresAt: runtimeAuthorization.expiresAt,
      maximumRequests: 1,
      maximumAnchors: 1,
      ledgerReserveUsdMicros: BASE_RPC_READ_CANARY_LEDGER_RESERVE_USD_MICRO,
    });
    try {
      this.#eventStore.append({
        aggregateId: AGGREGATE_ID,
        idempotencyKey: PREPARED_KEY,
        occurredAt: prepared.preparedAt,
        payload: jsonValue(prepared),
        type: PREPARED_EVENT_TYPE,
      });
    } catch {
      throw new BaseRpcReadCanaryConflictError(
        "The one-shot Base RPC read canary was claimed concurrently",
      );
    }

    try {
      this.#operationsStore.createBudget({
        budgetId,
        createdAt: runtimeAuthorization.requestedAt,
        currency: "USD_MICRO",
        endsAt: runtimeAuthorization.expiresAt,
        maxAtomic: BASE_RPC_ANCHOR_RESERVED_ATOMIC,
        maxAttempts: 1,
        profile: "canary",
        startsAt: runtimeAuthorization.requestedAt,
      });
      this.#operationsStore.reserveAttempt({
        attemptId: permit.attemptId,
        authorizationExpiresAt: runtimeAuthorization.expiresAt,
        budgetId,
        createdAt: runtimeAuthorization.requestedAt,
        idempotencyKey: `base-rpc-read-canary:${command.requestId}`,
        lane: "contract",
        operation: BASE_RPC_READ_CANARY_OPERATION,
        permitToken: permit.token,
        reservedAtomic: BASE_RPC_ANCHOR_RESERVED_ATOMIC,
        sessionId: command.requestId,
        sourcePlane: "canonical_chain",
      });
      const networkAuthorization = this.#operationsStore.createNetworkAttemptAuthorization(permit);
      const apiKey = this.#apiKey;
      if (apiKey === null)
        throw new BaseRpcReadCanaryConflictError("Canary credential is unavailable");
      const collector = createBaseRpcAnchorCollector({
        attemptAuthorization: networkAuthorization,
        apiKey,
        runtimeAuthorization,
      });
      const result = await ingestBaseRpcAnchor(
        {
          captureRegistry: this.#captureRegistry,
          collector,
          now,
          operationsStore: this.#operationsStore,
          signal,
          store: this.#eventStore,
          vault: this.#vault,
        },
        {
          attemptId: permit.attemptId,
          expiresAt: runtimeAuthorization.expiresAt,
          lane: "contract",
          profile: "canary",
          sessionId: command.requestId,
        },
      );
      return await this.#complete(prepared, result, runtimeAuthorization);
    } catch (error) {
      const dependencies = this.#recoveryDependencies();
      const durableResult = loadResult(dependencies, prepared);
      const attempt = this.#captureRegistry.getAttempt(prepared.attemptId);
      if (durableResult !== null || attempt?.state === "committed") {
        try {
          return await recoverPreparedCanary(dependencies, prepared);
        } catch (recoveryError) {
          throw new AggregateError(
            [error, recoveryError],
            "Canary execution failed and its durable capture requires restart recovery",
          );
        }
      }
      return terminalizeFailure(dependencies, prepared, safeFailureCode(error));
    }
  }

  async #resume(
    command: BaseRpcReadCanaryRunCommand,
    prepared: PreparedPayload,
  ): Promise<Readonly<BaseRpcReadCanaryDurableReceiptV1>> {
    if (
      prepared.requestId !== command.requestId ||
      prepared.expectedRuntimeRevision !== command.expectedRuntimeRevision
    ) {
      throw new BaseRpcReadCanaryConflictError("Canary command is rebound");
    }
    if (this.#runtime.getSnapshot().processInstanceId === prepared.runtimeProcessInstanceId) {
      throw new BaseRpcReadCanaryConflictError("The claimed canary is still owned by this runtime");
    }
    return recoverPreparedCanary(this.#recoveryDependencies(), prepared);
  }

  async #complete(
    prepared: PreparedPayload,
    result: Readonly<BaseRpcAnchorIngestionResult>,
    runtimeAuthorization: RuntimeBoundaryAuthorization<"research_collection">,
  ): Promise<Readonly<BaseRpcReadCanaryDurableReceiptV1>> {
    const dependencies = this.#recoveryDependencies();
    return finalizeResult(
      dependencies,
      prepared,
      persistLiveResult(dependencies, prepared, result, runtimeAuthorization),
    );
  }

  #recoveryDependencies(): BaseRpcReadCanaryRecoveryOptions {
    return {
      runtime: this.#runtime,
      operationsStore: this.#operationsStore,
      captureRegistry: this.#captureRegistry,
      eventStore: this.#eventStore,
      vault: this.#vault,
    };
  }

  #assertAuthentic(): void {
    if (
      !AUTHENTIC_CONTROLLERS.has(this) ||
      Object.getPrototypeOf(this) !== BaseRpcReadCanaryController.prototype
    ) {
      throw new BaseRpcReadCanaryConflictError("Base RPC read canary controller is not authentic");
    }
  }
}

Object.freeze(BaseRpcReadCanaryController.prototype);
Object.freeze(BaseRpcReadCanaryController);

export function isBaseRpcReadCanaryController(
  value: unknown,
): value is BaseRpcReadCanaryController {
  return (
    typeof value === "object" &&
    value !== null &&
    !utilTypes.isProxy(value) &&
    AUTHENTIC_CONTROLLERS.has(value) &&
    Object.getPrototypeOf(value) === BaseRpcReadCanaryController.prototype
  );
}
