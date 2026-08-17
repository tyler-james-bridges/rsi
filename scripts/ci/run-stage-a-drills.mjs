import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { fileURLToPath, pathToFileURL } from "node:url";

import { STAGE_A_DRILLS } from "./stage-a-drill-catalog.mjs";

const rootUrl = new URL("../../", import.meta.url);
const root = fileURLToPath(rootUrl);
const guardUrl = pathToFileURL(
  fileURLToPath(new URL("deny-external-network.mjs", import.meta.url)),
);
const inheritedNodeOptions = process.env.NODE_OPTIONS?.trim();
const nodeOptions = [inheritedNodeOptions, `--import=${guardUrl.href}`].filter(Boolean).join(" ");
const childEnvironment = Object.freeze({
  CI: "1",
  LANG: "C",
  LC_ALL: "C",
  NO_COLOR: "1",
  NODE_OPTIONS: nodeOptions,
  PATH: process.env.PATH ?? "/usr/bin:/bin",
  TZ: "UTC",
});

function run(label, command, args, timeout) {
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: "utf8",
    env: childEnvironment,
    maxBuffer: 16 * 1024 * 1024,
    shell: false,
    timeout,
  });
  if (result.status !== 0) {
    process.stderr.write(`Stage A drill gate failed during ${label}.\n`);
    process.exit(1);
  }
}

async function verifyCatalog() {
  const ids = new Set();
  for (const drill of STAGE_A_DRILLS) {
    if (!/^D(?:0[1-9]|1[0-9]|20)$/u.test(drill.id) || ids.has(drill.id)) {
      throw new Error("Stage A drill catalog identity is invalid");
    }
    ids.add(drill.id);
    const source = await readFile(new URL(drill.evidencePath, rootUrl), "utf8");
    if (!source.includes(drill.evidenceText)) {
      throw new Error("Stage A drill evidence declaration is stale");
    }
  }
  if (ids.size !== 20) throw new Error("Stage A drill catalog is incomplete");
}

try {
  await verifyCatalog();
  run(
    "network-denial smoke test",
    process.execPath,
    [fileURLToPath(new URL("network-guard-smoke.mjs", import.meta.url))],
    20_000,
  );
  run("repository test suite", "pnpm", ["test"], 180_000);
  run("offline demos", "pnpm", ["ci:demos"], 60_000);
  process.stdout.write(
    `Stage A offline drill gate passed ${STAGE_A_DRILLS.length} declared families with external destinations denied.\n`,
  );
} catch {
  process.stderr.write("Stage A drill gate failed during catalog verification.\n");
  process.exitCode = 1;
}
