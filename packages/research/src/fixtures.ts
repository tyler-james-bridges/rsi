import { readFile } from "node:fs/promises";

import { captureRawFixture, type RawFixtureCapture } from "./capture.js";
import { RECORDED_FIXTURE_SCENARIOS, type RecordedFixtureScenario } from "./recorded-scenarios.js";

export { RECORDED_FIXTURE_SCENARIOS } from "./recorded-scenarios.js";
export type { RecordedFixtureScenario } from "./recorded-scenarios.js";

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
