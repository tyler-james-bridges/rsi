import {
  parseBaseRpcAnchorContext,
  parseBaseRpcAnchorStorageDependencies,
  recoverBaseRpcAnchorFromStorage,
  type BaseRpcAnchorIngestionContext,
  type BaseRpcAnchorIngestionResult,
  type BaseRpcAnchorStorageDependencies,
} from "./base-rpc-anchor-storage.js";

/**
 * Recover one already committed Base RPC capture using authenticated local
 * storage only. This module's static dependency graph is egress-free.
 */
export async function recoverBaseRpcAnchor(
  dependenciesInput: Readonly<BaseRpcAnchorStorageDependencies>,
  contextInput: unknown,
): Promise<Readonly<BaseRpcAnchorIngestionResult>> {
  if (arguments.length !== 2) {
    throw new Error("Base RPC recovery accepts only storage dependencies and context");
  }
  const dependencies = parseBaseRpcAnchorStorageDependencies(dependenciesInput);
  const context = parseBaseRpcAnchorContext(contextInput);
  return recoverBaseRpcAnchorFromStorage(dependencies, context);
}

export type {
  BaseRpcAnchorCaptureStatus,
  BaseRpcAnchorIngestionContext,
  BaseRpcAnchorIngestionResult,
  BaseRpcAnchorStorageDependencies,
} from "./base-rpc-anchor-storage.js";
