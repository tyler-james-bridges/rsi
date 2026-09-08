/**
 * Credentialless, collectorless restart boundary. Its local import graph is
 * deliberately separate from the live Base RPC controller.
 */
export {
  recoverBaseRpcReadCanary,
  type BaseRpcReadCanaryRecoveryOptions,
} from "./base-rpc-recovery-core.js";
export type { BaseRpcReadCanaryReceiptV1 } from "./base-rpc-types.js";
