import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
const command = ["scripts/release/verify-source-inventory.mjs"];

function runVerifier() {
  const result = spawnSync(process.execPath, command, {
    cwd: root,
    encoding: "buffer",
    env: process.env,
    maxBuffer: 4 * 1024 * 1024,
    shell: false,
    timeout: 60_000,
  });
  if (result.status !== 0 || result.signal !== null) {
    process.stderr.write(
      Buffer.isBuffer(result.stderr) && result.stderr.length > 0
        ? result.stderr
        : "Source inventory verification failed.\n",
    );
    process.exit(1);
  }
  return result.stdout;
}

const first = runVerifier();
const second = runVerifier();
if (first.length === 0 || !first.equals(second)) {
  process.stderr.write("Source inventory verification was not reproducible.\n");
  process.exit(1);
}
process.stdout.write(first);
