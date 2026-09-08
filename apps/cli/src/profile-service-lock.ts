import { resolve } from "node:path";

import {
  PROFILE_SERVICE_LOCK_ERROR_MESSAGES,
  ProfileServiceLockError,
  acquireCanaryProfileLockForDatabasePath,
  bindProfileServiceLock,
  type CanaryProfileLockLease,
  type ProfileServiceLockErrorCode,
} from "./profile-service-lock-core.js";

const PRODUCTION_CANARY_DATABASE_PATH = resolve(
  import.meta.dirname,
  "../.local/rsi-runtime.sqlite",
);

export { PROFILE_SERVICE_LOCK_ERROR_MESSAGES, ProfileServiceLockError, bindProfileServiceLock };
export type { ProfileServiceLockErrorCode };

export interface ProductionCanaryProfileLock extends CanaryProfileLockLease {
  /** Idempotent for this owning handle. Refuses to remove an artifact it cannot prove it owns. */
  release(): Promise<void>;
}

/**
 * Claims the one code-owned production canary profile before any storage, recovery, or credential
 * boundary is entered. X, OpenSea, Base RPC, and marker backfill intentionally share this scope.
 */
export async function acquireProductionCanaryProfileLock(): Promise<ProductionCanaryProfileLock> {
  return acquireCanaryProfileLockForDatabasePath(PRODUCTION_CANARY_DATABASE_PATH);
}
