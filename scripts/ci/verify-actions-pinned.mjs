import { readdir, readFile } from "node:fs/promises";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";

const workflowsDirectory = fileURLToPath(new URL("../../.github/workflows/", import.meta.url));
const entries = await readdir(workflowsDirectory, { withFileTypes: true });
const workflowFiles = entries
  .filter((entry) => entry.isFile() && [".yaml", ".yml"].includes(extname(entry.name)))
  .map((entry) => join(workflowsDirectory, entry.name));

let usesCount = 0;
let violationCount = 0;
for (const file of workflowFiles) {
  const content = await readFile(file, "utf8");
  for (const match of content.matchAll(/^\s*-?\s*uses:\s*([^\s#]+)/gmu)) {
    usesCount += 1;
    const reference = match[1];
    if (reference === undefined || reference.startsWith("./")) continue;
    const separator = reference.lastIndexOf("@");
    const revision = separator === -1 ? "" : reference.slice(separator + 1);
    if (!/^[0-9a-f]{40}$/u.test(revision)) violationCount += 1;
  }
}

if (workflowFiles.length === 0 || usesCount === 0 || violationCount > 0) {
  process.stderr.write(
    `Action pin verification failed (${workflowFiles.length} workflow(s), ${usesCount} use(s), ${violationCount} violation(s)).\n`,
  );
  process.exitCode = 1;
} else {
  process.stdout.write(`Verified ${usesCount} full-SHA action reference(s).\n`);
}
