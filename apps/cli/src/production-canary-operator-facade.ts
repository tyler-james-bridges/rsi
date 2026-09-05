import type { RuntimeSnapshotV1 } from "@rsi/runtime";

export interface ReadOnlyCanaryRuntime {
  getSnapshot(): Readonly<RuntimeSnapshotV1>;
}

export interface RunningProductionCanaryOperator<Paths extends object> {
  readonly origin: string;
  readonly paths: Readonly<Paths>;
  readonly runtime: Readonly<ReadOnlyCanaryRuntime>;
  close(): Promise<void>;
}

interface InternalRunningCanaryOperator<Paths extends object> {
  readonly origin: string;
  readonly paths: Readonly<Paths>;
  readonly runtime: ReadOnlyCanaryRuntime;
  close(): Promise<void>;
}

/** Removes every mutable runtime capability from the production host result. */
export function createProductionCanaryOperatorFacade<Paths extends object>(
  operator: InternalRunningCanaryOperator<Paths>,
): RunningProductionCanaryOperator<Paths> {
  const runtime = Object.freeze({
    getSnapshot: (): Readonly<RuntimeSnapshotV1> => operator.runtime.getSnapshot(),
  });
  return Object.freeze({
    origin: operator.origin,
    paths: operator.paths,
    runtime,
    close: (): Promise<void> => operator.close(),
  });
}
