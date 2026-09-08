export const PRODUCTION_STARTUP_SIGNALS = ["SIGINT", "SIGTERM"] as const;

export type ProductionStartupSignal = (typeof PRODUCTION_STARTUP_SIGNALS)[number];

export interface ProductionSignalListeners {
  readonly SIGINT: readonly NodeJS.SignalsListener[];
  readonly SIGTERM: readonly NodeJS.SignalsListener[];
}

function rawSignalListeners(signal: ProductionStartupSignal): readonly NodeJS.SignalsListener[] {
  return process.rawListeners(signal) as NodeJS.SignalsListener[];
}

export function captureProductionSignalListeners(): ProductionSignalListeners {
  return {
    SIGINT: rawSignalListeners("SIGINT"),
    SIGTERM: rawSignalListeners("SIGTERM"),
  };
}

export function invokeAddedProductionSignalListener(
  before: ProductionSignalListeners,
  signal: ProductionStartupSignal,
): void {
  const added = rawSignalListeners(signal).filter((listener) => !before[signal].includes(listener));
  if (added.length !== 1) {
    throw new Error(`expected exactly one new ${signal} listener, received ${added.length}`);
  }
  added[0]!.call(process, signal);
}

export function removeAddedProductionSignalListeners(before: ProductionSignalListeners): void {
  for (const signal of PRODUCTION_STARTUP_SIGNALS) {
    for (const listener of rawSignalListeners(signal)) {
      if (!before[signal].includes(listener)) process.off(signal, listener);
    }
  }
}

export function productionSignalListenersMatch(before: ProductionSignalListeners): boolean {
  return PRODUCTION_STARTUP_SIGNALS.every((signal) => {
    const after = rawSignalListeners(signal);
    return (
      after.length === before[signal].length &&
      after.every((listener, index) => listener === before[signal][index])
    );
  });
}

export interface Deferred<T> {
  readonly promise: Promise<T>;
  resolve(value: T): void;
}

export function deferred<T>(): Deferred<T> {
  let resolvePromise: ((value: T) => void) | undefined;
  const promise = new Promise<T>((resolve) => {
    resolvePromise = resolve;
  });
  return {
    promise,
    resolve(value: T): void {
      if (resolvePromise === undefined) throw new Error("deferred resolver is unavailable");
      resolvePromise(value);
    },
  };
}
