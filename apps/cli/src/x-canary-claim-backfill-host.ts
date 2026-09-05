import { lstat } from "node:fs/promises";
import { dirname } from "node:path";

import { createDarwinXOneShotClaimHost } from "@rsi/credential-host/one-shot-claim";
import { SqliteEventStore } from "@rsi/store";

import {
  IncompleteCanaryResourceCleanupError,
  acquireCanaryResource,
  closeCanaryResourceSet,
  rethrowCanaryStartupFailureAfterProfileLockDecision,
} from "./canary-operator-startup-cleanup.js";
import { productionXCanaryEventStorePath } from "./production-canary-config.js";
import { acquireProductionCanaryProfileLock } from "./profile-service-lock.js";
import { assertActiveProductionRuntime } from "./production-runtime.js";
import {
  backfillXCanaryClaimWithHost,
  type XCanaryClaimBackfillReceipt,
} from "./x-canary-claim-backfill-core.js";

const OWNER_ONLY_DIRECTORY_MODE = 0o700n;
const EFFECTIVE_USER_ID = typeof process.geteuid === "function" ? BigInt(process.geteuid()) : null;

export async function backfillXCanaryClaim(
  typedPlanIdAcknowledgement: string,
): Promise<Readonly<XCanaryClaimBackfillReceipt>> {
  assertActiveProductionRuntime();
  const eventStorePath = productionXCanaryEventStorePath();
  const profileLock = await acquireProductionCanaryProfileLock();
  let eventStore: SqliteEventStore | undefined;
  try {
    const [directoryEntry, eventStoreEntry] = await Promise.all([
      lstat(dirname(eventStorePath), { bigint: true }),
      lstat(eventStorePath, { bigint: true }),
    ]);
    if (
      EFFECTIVE_USER_ID === null ||
      !directoryEntry.isDirectory() ||
      directoryEntry.isSymbolicLink() ||
      (directoryEntry.mode & 0o777n) !== OWNER_ONLY_DIRECTORY_MODE ||
      directoryEntry.uid !== EFFECTIVE_USER_ID ||
      !eventStoreEntry.isFile() ||
      eventStoreEntry.isSymbolicLink() ||
      eventStoreEntry.nlink !== 1n ||
      eventStoreEntry.uid !== EFFECTIVE_USER_ID
    ) {
      throw new TypeError("The canonical completed X receipt is unavailable");
    }
    eventStore = acquireCanaryResource(() => new SqliteEventStore(eventStorePath));
    const receipt = await backfillXCanaryClaimWithHost(
      eventStore,
      createDarwinXOneShotClaimHost(),
      typedPlanIdAcknowledgement,
    );
    await closeCanaryResourceSet([() => eventStore?.close()]);
    await profileLock.release();
    return receipt;
  } catch (error) {
    try {
      await closeCanaryResourceSet([() => eventStore?.close()]);
    } catch (cleanupError) {
      throw new IncompleteCanaryResourceCleanupError([error, cleanupError]);
    }
    return rethrowCanaryStartupFailureAfterProfileLockDecision(
      error,
      profileLock,
      "RSI X marker backfill and lock release both failed",
    );
  }
}
