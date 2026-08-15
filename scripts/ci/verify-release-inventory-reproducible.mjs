import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
const command = ["exec", "tsx", "scripts/release/verify-foundation-inventory.ts"];

function runVerifier() {
  const result = spawnSync("pnpm", command, {
    cwd: root,
    encoding: "utf8",
    env: process.env,
    maxBuffer: 4 * 1024 * 1024,
    shell: false,
    timeout: 30_000,
  });
  if (result.status !== 0) {
    process.stderr.write(result.stderr || "Foundation inventory verification failed.\n");
    process.exit(1);
  }
  return result.stdout;
}

const first = runVerifier();
const second = runVerifier();
if (first.length === 0 || first !== second) {
  process.stderr.write("Foundation inventory verification was not reproducible.\n");
  process.exit(1);
}
process.stdout.write(first);
