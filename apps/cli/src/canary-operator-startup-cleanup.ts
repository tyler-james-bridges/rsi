export class IncompleteCanaryCleanupError extends AggregateError {
  constructor(errors: readonly unknown[], message: string) {
    super(errors, message);
    this.name = "IncompleteCanaryCleanupError";
  }
}

export class IncompleteCanaryOperatorStartupCleanupError extends IncompleteCanaryCleanupError {
  constructor(startupError: unknown, cleanupError: unknown) {
    super(
      [startupError, cleanupError],
      "RSI canary startup cleanup did not complete; the profile lock must remain held",
    );
    this.name = "IncompleteCanaryOperatorStartupCleanupError";
  }
}

export class IncompleteCanaryResourceCleanupError extends IncompleteCanaryCleanupError {
  constructor(cleanupErrors: readonly unknown[]) {
    super(
      cleanupErrors,
      "RSI canary resource cleanup did not complete; the profile lock must remain held",
    );
    this.name = "IncompleteCanaryResourceCleanupError";
  }
}

export class IncompleteCanaryResourceAcquisitionError extends IncompleteCanaryCleanupError {
  constructor(acquisitionError: unknown) {
    super(
      [acquisitionError],
      "RSI canary resource acquisition did not return a cleanup handle; the profile lock must remain held",
    );
    this.name = "IncompleteCanaryResourceAcquisitionError";
  }
}

/** Conservatively retains the lock when a stateful constructor throws without returning a handle. */
export function acquireCanaryResource<T>(acquire: () => T): T {
  try {
    return acquire();
  } catch (error) {
    throw new IncompleteCanaryResourceAcquisitionError(error);
  }
}

/** Async counterpart for stateful factories such as the capture Vault and loopback server. */
export async function acquireCanaryResourceAsync<T>(acquire: () => Promise<T>): Promise<T> {
  try {
    return await acquire();
  } catch (error) {
    throw new IncompleteCanaryResourceAcquisitionError(error);
  }
}

/** Attempts every cleanup step and reports any uncertainty as one fail-closed error. */
export async function closeCanaryResourceSet(
  cleanupSteps: readonly (() => void | Promise<void>)[],
): Promise<void> {
  const failures: unknown[] = [];
  for (const cleanup of cleanupSteps) {
    try {
      await cleanup();
    } catch (error) {
      failures.push(error);
    }
  }
  if (failures.length > 0) throw new IncompleteCanaryResourceCleanupError(failures);
}

/**
 * Converts a failed startup into either its original, cleanly closed error or a branded
 * incomplete-cleanup error that tells the outer profile-lock owner to remain fail-closed.
 */
export async function rethrowCanaryStartupFailureAfterCleanup(
  startupError: unknown,
  close: () => Promise<void>,
): Promise<never> {
  try {
    await close();
  } catch (cleanupError) {
    throw new IncompleteCanaryOperatorStartupCleanupError(startupError, cleanupError);
  }
  throw startupError;
}

export interface CanaryStartupProfileLock {
  release(): Promise<void>;
}

/** Releases only after startup cleanup is proven complete; uncertainty deliberately strands the
 * artifact for reviewed manual recovery instead of admitting a second process. */
export async function rethrowCanaryStartupFailureAfterProfileLockDecision(
  startupError: unknown,
  profileLock: CanaryStartupProfileLock,
  combinedFailureMessage: string,
): Promise<never> {
  if (startupError instanceof IncompleteCanaryCleanupError) throw startupError;
  try {
    await profileLock.release();
  } catch (releaseError) {
    throw new AggregateError([startupError, releaseError], combinedFailureMessage);
  }
  throw startupError;
}
