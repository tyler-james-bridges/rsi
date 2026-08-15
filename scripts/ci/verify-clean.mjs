import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
const result = spawnSync("git", ["status", "--porcelain=v1", "--untracked-files=all"], {
  cwd: root,
  encoding: "utf8",
  maxBuffer: 1024 * 1024,
  shell: false,
});

if (result.status !== 0) {
  process.stderr.write("Unable to verify repository cleanliness.\n");
  process.exitCode = 1;
} else {
  const changedCount = result.stdout.split(/\r?\n/u).filter(Boolean).length;
  if (changedCount > 0) {
    process.stderr.write(
      `Generated or dirty repository state detected (${changedCount} path(s)).\n`,
    );
    process.exitCode = 1;
  } else {
    process.stdout.write("Repository remained clean after verification.\n");
  }
}
