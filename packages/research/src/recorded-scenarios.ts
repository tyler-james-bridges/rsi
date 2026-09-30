import { z } from "zod";

function freezeCatalog<T extends Record<string, object>>(catalog: T): Readonly<T> {
  for (const entry of Object.values(catalog)) Object.freeze(entry);
  return Object.freeze(catalog);
}

export const RECORDED_FIXTURE_SCENARIOS = freezeCatalog({
  safeSocial: {
    file: "safe-social.json",
    category: "safe",
  },
  safeMarketplace: {
    file: "safe-opensea.json",
    category: "canonical",
  },
  safeOnchain: {
    file: "safe-onchain.json",
    category: "canonical",
  },
  coordinatedShillA: {
    file: "coordinated-shill-a.json",
    category: "coordinated-shill",
  },
  coordinatedShillB: {
    file: "coordinated-shill-b.json",
    category: "coordinated-shill",
  },
  promptInjection: {
    file: "prompt-injection.json",
    category: "prompt-injection",
  },
  staleSocial: {
    file: "stale-social.json",
    category: "stale",
  },
  contractSubstitution: {
    file: "contract-substitution.json",
    category: "contract-substitution",
  },
} as const);

export type RecordedFixtureScenario = keyof typeof RECORDED_FIXTURE_SCENARIOS;

export const RecordedReplayScenarioSchema = z.enum([
  "safe",
  "coordinated-shill",
  "prompt-injection",
  "stale-evidence",
  "contract-substitution",
]);

export type RecordedReplayScenario = z.infer<typeof RecordedReplayScenarioSchema>;

const freezeScenarioNames = <const T extends readonly RecordedFixtureScenario[]>(...names: T): T =>
  Object.freeze(names);

export const RECORDED_REPLAY_FIXTURE_SCENARIOS: Readonly<
  Record<RecordedReplayScenario, readonly RecordedFixtureScenario[]>
> = Object.freeze({
  safe: freezeScenarioNames("safeSocial", "safeMarketplace", "safeOnchain"),
  "coordinated-shill": freezeScenarioNames(
    "coordinatedShillA",
    "coordinatedShillB",
    "safeMarketplace",
  ),
  "prompt-injection": freezeScenarioNames("promptInjection", "safeMarketplace", "safeOnchain"),
  "stale-evidence": freezeScenarioNames("staleSocial", "safeMarketplace", "safeOnchain"),
  "contract-substitution": freezeScenarioNames(
    "contractSubstitution",
    "safeMarketplace",
    "safeOnchain",
  ),
});

export const ALL_RECORDED_REPLAY_SCENARIOS = Object.freeze(
  RecordedReplayScenarioSchema.options satisfies readonly RecordedReplayScenario[],
);
