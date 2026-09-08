import { randomUUID } from "node:crypto";

import { SqliteRuntimeController } from "@rsi/runtime";
import { SqliteEventStore } from "@rsi/store";
import { SnapshotVault } from "@rsi/vault";
import { vi } from "vitest";

export interface PausedSnapshotCapture {
  readonly started: Promise<void>;
  release(): void;
  restore(): void;
}

/** Pauses the first capture after transport has returned but before encrypted persistence begins. */
export function pauseNextSnapshotCapture(): PausedSnapshotCapture {
  const originalCapture = SnapshotVault.prototype.capture;
  let notifyStarted!: () => void;
  const started = new Promise<void>((resolve) => {
    notifyStarted = resolve;
  });
  let releaseCapture!: () => void;
  const released = new Promise<void>((resolve) => {
    releaseCapture = resolve;
  });
  let paused = false;
  const spy = vi.spyOn(SnapshotVault.prototype, "capture").mockImplementation(async function (
    this: SnapshotVault,
    ...args: Parameters<SnapshotVault["capture"]>
  ) {
    if (!paused) {
      paused = true;
      notifyStarted();
      await released;
    }
    return originalCapture.apply(this, args);
  });
  return Object.freeze({
    started,
    release: releaseCapture,
    restore: (): void => spy.mockRestore(),
  });
}

export interface FinalStopMicrotaskProbe {
  readonly attempt: Promise<"committed" | "rejected">;
  readonly requestId: string;
  restore(): void;
}

/** Attempts a direct mutation in the first microtask after the final (second) shutdown STOP. */
export function probeRuntimeMutationAfterFinalStop(
  runtime: SqliteRuntimeController,
): FinalStopMicrotaskProbe {
  const originalAppend = SqliteEventStore.prototype.append;
  const requestId = randomUUID();
  let settleAttempt!: (outcome: "committed" | "rejected") => void;
  const attempt = new Promise<"committed" | "rejected">((resolve) => {
    settleAttempt = resolve;
  });
  let shutdownStops = 0;
  const spy = vi.spyOn(SqliteEventStore.prototype, "append").mockImplementation(function (
    this: SqliteEventStore,
    ...args: Parameters<SqliteEventStore["append"]>
  ) {
    const event = originalAppend.apply(this, args);
    if (args[0].type === "runtime.stop.enforced.v1") {
      shutdownStops += 1;
      if (shutdownStops === 2) {
        queueMicrotask(() => {
          try {
            const snapshot = runtime.getSnapshot();
            runtime.transition({
              expectedMode: snapshot.mode,
              expectedRevision: snapshot.revision,
              occurredAt: new Date().toISOString(),
              requestId,
              targetMode: "RESEARCH",
            });
            settleAttempt("committed");
          } catch {
            settleAttempt("rejected");
          }
        });
      }
    }
    return event;
  });
  return Object.freeze({
    attempt,
    requestId,
    restore: (): void => spy.mockRestore(),
  });
}
