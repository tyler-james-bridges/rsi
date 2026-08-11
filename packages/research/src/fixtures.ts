import { readFile } from "node:fs/promises";

import { captureRawFixture, type RawFixtureCapture } from "./capture.js";

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

export async function loadRecordedFixture(
  scenario: RecordedFixtureScenario,
): Promise<RawFixtureCapture> {
  const entry = RECORDED_FIXTURE_SCENARIOS[scenario];
  const bytes = await readFile(new URL(`../fixtures/${entry.file}`, import.meta.url));
  return captureRawFixture(bytes, { contentType: "application/json" });
}

export async function loadRecordedFixtures(
  scenarios: readonly RecordedFixtureScenario[] = Object.keys(
    RECORDED_FIXTURE_SCENARIOS,
  ) as RecordedFixtureScenario[],
): Promise<RawFixtureCapture[]> {
  return Promise.all(scenarios.map(loadRecordedFixture));
}
