import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
const tsxCli = fileURLToPath(new URL("../../node_modules/tsx/dist/cli.mjs", import.meta.url));
const childEnvironment = Object.freeze({
  CI: "1",
  LANG: "C",
  LC_ALL: "C",
  NO_COLOR: "1",
  PATH: process.env.PATH ?? "/usr/bin:/bin",
});

function run(sourcePath) {
  const result = spawnSync(process.execPath, [tsxCli, sourcePath], {
    cwd: root,
    encoding: "utf8",
    env: childEnvironment,
    maxBuffer: 2 * 1024 * 1024,
    shell: false,
    timeout: 30_000,
  });
  if (result.status !== 0) throw new Error(`${sourcePath} failed`);
  try {
    return JSON.parse(result.stdout);
  } catch {
    throw new Error(`${sourcePath} did not emit one JSON document`);
  }
}

let phase = "policy";
try {
  const policy = run("apps/cli/src/index.ts");
  if (typeof policy.approved !== "boolean" || !Array.isArray(policy.reasons)) {
    throw new Error("demo emitted an invalid policy decision");
  }

  phase = "pipeline";
  const pipeline = run("apps/cli/src/pipeline.ts");
  if (pipeline.mode !== "recorded-fixtures" || pipeline.executionEnabled !== false) {
    throw new Error("pipeline demo crossed its offline boundary");
  }

  phase = "ingestion";
  const ingestion = run("apps/cli/src/ingestion.ts");
  if (
    ingestion.mode !== "offline-replay" ||
    ingestion.networkUsed !== false ||
    ingestion.credentialsUsed !== false ||
    ingestion.executionEnabled !== false
  ) {
    throw new Error("ingestion demo crossed its offline boundary");
  }

  process.stdout.write("Three offline demos passed their boundary assertions.\n");
} catch {
  process.stderr.write(`Offline demo verification failed during ${phase}.\n`);
  process.exitCode = 1;
}
