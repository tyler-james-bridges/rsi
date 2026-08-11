import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";

import { startOperatorServer } from "@rsi/operator";
import {
  ALL_FIXTURE_SCENARIOS,
  RsiFixturePipeline,
  SqliteOperatorSnapshotProvider,
  createFixturePolicy,
} from "@rsi/pipeline";

import { operatorUsage, parseOperatorOptions } from "./operator-options.js";

const FIXTURE_TIME = new Date("2026-08-11T12:00:00.000Z");

const options = parseOperatorOptions(process.argv.slice(2));
if (options === null) {
  console.log(operatorUsage());
  process.exitCode = 0;
} else {
  const databasePath =
    options.databasePath === ":memory:" ? options.databasePath : resolve(options.databasePath);
  if (databasePath !== ":memory:") await mkdir(dirname(databasePath), { recursive: true });

  const pipeline = RsiFixturePipeline.open(databasePath, createFixturePolicy());
  let operator: Awaited<ReturnType<typeof startOperatorServer>> | undefined;

  try {
    if (options.seed) {
      for (const scenario of ALL_FIXTURE_SCENARIOS) {
        await pipeline.runScenario(scenario, {
          runId: `operator-demo-v1-${scenario}`,
          now: FIXTURE_TIME,
        });
      }
    }

    const provider = new SqliteOperatorSnapshotProvider(pipeline.store);
    operator = await startOperatorServer(provider, { port: options.port });
    console.log(
      JSON.stringify({
        mode: "read-only-operator-api",
        executionEnabled: false,
        databasePath,
        seededRecordedFixtures: options.seed,
        origin: operator.origin,
      }),
    );

    let closing = false;
    const close = async (): Promise<void> => {
      if (closing) return;
      closing = true;
      await operator?.close();
      pipeline.close();
    };
    process.once("SIGINT", () => void close());
    process.once("SIGTERM", () => void close());
  } catch (error) {
    await operator?.close();
    pipeline.close();
    throw error;
  }
}
