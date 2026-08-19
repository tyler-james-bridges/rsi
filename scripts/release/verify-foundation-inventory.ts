import { fileURLToPath } from "node:url";

import { collectFoundationReleaseInventory } from "../../packages/release-ceremony/src/inventory.js";

const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));

async function main(): Promise<void> {
  const inventory = await collectFoundationReleaseInventory({
    mode: "candidate",
    repositoryRoot,
  });
  const report = inventory.report;
  process.stdout.write(
    `${JSON.stringify({
      artifactCount: report.artifactCount,
      artifactSetSha256: report.artifactSetSha256,
      commitSha: report.commitSha,
      configSetSha256: report.configSetSha256,
      gitTreeSha: report.gitTreeSha,
      lockfileSha256: report.lockfileSha256,
      releaseVersion: report.releaseVersion,
      sourceTreeSha256: report.sourceTreeSha256,
      status: "unsigned-inventory-candidate-validated",
      trackedFileCount: report.trackedFileCount,
    })}\n`,
  );
}

await main().catch(() => {
  process.stderr.write("Foundation release-inventory verification failed.\n");
  process.exitCode = 1;
});
