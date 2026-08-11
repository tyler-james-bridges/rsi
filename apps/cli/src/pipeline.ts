import {
  ALL_FIXTURE_SCENARIOS,
  RsiFixturePipeline,
  SqliteOperatorSnapshotProvider,
  createFixturePolicy,
} from "@rsi/pipeline";

const databasePath = process.argv[2] ?? ":memory:";
const now = new Date("2026-08-11T12:00:00.000Z");
const pipeline = RsiFixturePipeline.open(databasePath, createFixturePolicy());

try {
  const results = [];
  for (const scenario of ALL_FIXTURE_SCENARIOS) {
    const report = await pipeline.runScenario(scenario, {
      runId: `demo-v1-${scenario}`,
      now,
    });
    results.push({
      scenario,
      approved: report.decision.approved,
      reasons: report.decision.reasons,
      observations: report.observationCount,
      independentClusters: report.correlation.freshIndependentClusterCount,
      canonicalEvidence: report.correlation.freshCanonicalEvidenceCount,
      decisionId: report.decision.decisionId,
    });
  }

  const provider = new SqliteOperatorSnapshotProvider(pipeline.store);
  console.log(
    JSON.stringify(
      {
        mode: "recorded-fixtures",
        executionEnabled: false,
        databasePath,
        results,
        summary: provider.getSummary(),
      },
      null,
      2,
    ),
  );
} finally {
  pipeline.close();
}
