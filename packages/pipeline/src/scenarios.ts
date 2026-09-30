import {
  ALL_RECORDED_REPLAY_SCENARIOS,
  RECORDED_REPLAY_FIXTURE_SCENARIOS,
  RecordedReplayScenarioSchema,
  type RecordedReplayScenario,
} from "@rsi/research/scenarios";

export const FixtureScenarioNameSchema = RecordedReplayScenarioSchema;
export type FixtureScenarioName = RecordedReplayScenario;
export const FIXTURE_SCENARIOS = RECORDED_REPLAY_FIXTURE_SCENARIOS;
export const ALL_FIXTURE_SCENARIOS = ALL_RECORDED_REPLAY_SCENARIOS;
