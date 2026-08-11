import { z } from "zod";

import type { RecordedFixtureScenario } from "@rsi/research";

export const FixtureScenarioNameSchema = z.enum([
  "safe",
  "prompt-injection",
  "coordinated-shill",
  "stale-evidence",
  "contract-substitution",
]);

export type FixtureScenarioName = z.infer<typeof FixtureScenarioNameSchema>;

const freezeScenarioNames = <const T extends readonly RecordedFixtureScenario[]>(...names: T): T =>
  Object.freeze(names);

export const FIXTURE_SCENARIOS: Readonly<
  Record<FixtureScenarioName, readonly RecordedFixtureScenario[]>
> = Object.freeze({
  safe: freezeScenarioNames("safeSocial", "safeMarketplace", "safeOnchain"),
  "prompt-injection": freezeScenarioNames("promptInjection", "safeMarketplace", "safeOnchain"),
  "coordinated-shill": freezeScenarioNames(
    "coordinatedShillA",
    "coordinatedShillB",
    "safeMarketplace",
  ),
  "stale-evidence": freezeScenarioNames("staleSocial", "safeMarketplace", "safeOnchain"),
  "contract-substitution": freezeScenarioNames(
    "contractSubstitution",
    "safeMarketplace",
    "safeOnchain",
  ),
});

export const ALL_FIXTURE_SCENARIOS = Object.freeze(
  FixtureScenarioNameSchema.options satisfies readonly FixtureScenarioName[],
);
