import { access, readdir, readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
const contractDirectory = resolve(root, "docs/production-readiness");
const traceabilityPath = resolve(contractDirectory, "v1/traceability.md");
const specificationPath = resolve(contractDirectory, "v1/production-readiness-spec.md");

function fail() {
  process.stderr.write("Production-contract verification failed.\n");
  process.exit(1);
}

async function markdownFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const results = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) results.push(...(await markdownFiles(path)));
    else if (entry.isFile() && entry.name.endsWith(".md")) results.push(path);
  }
  return results;
}

function exactDecisionCoverage(traceability) {
  const values = [...traceability.matchAll(/`DEC-Q(\d{3})`/gu)].map((match) => match[1]);
  const expected = Array.from({ length: 195 }, (_, index) => String(index + 1).padStart(3, "0"));
  return (
    values.length === expected.length && values.every((value, index) => value === expected[index])
  );
}

function referencesAreDefined(traceability, specification) {
  const definedRequirements = new Set(
    [...specification.matchAll(/^### (OBS-[A-Z0-9-]+) —/gmu)].map((match) => match[1]),
  );
  const referencedRequirements = new Set(traceability.match(/OBS-[A-Z0-9-]+/gu) ?? []);
  if ([...referencedRequirements].some((value) => !definedRequirements.has(value))) return false;

  const definedEvidence = new Set(
    [...traceability.matchAll(/^\| `(E-[A-Z0-9]+)`\s+\|/gmu)].map((match) => match[1]),
  );
  const decisionTableStart = traceability.indexOf("## Decisions Q1-Q37");
  if (decisionTableStart < 0) return false;
  const referencedEvidence = new Set(
    traceability.slice(decisionTableStart).match(/E-[A-Z0-9]+/gu) ?? [],
  );
  return [...referencedEvidence].every((value) => definedEvidence.has(value));
}

async function localLinksResolve(path, markdown) {
  for (const match of markdown.matchAll(/\[[^\]]*\]\(([^)]+)\)/gu)) {
    const target = match[1]?.trim();
    if (
      target === undefined ||
      target === "" ||
      target.startsWith("#") ||
      /^[a-z][a-z0-9+.-]*:/iu.test(target)
    ) {
      continue;
    }
    const withoutFragment = target.split("#", 1)[0];
    if (withoutFragment === undefined || withoutFragment === "") continue;
    let decoded;
    try {
      decoded = decodeURIComponent(withoutFragment.replace(/^<|>$/gu, ""));
    } catch {
      return false;
    }
    try {
      await access(resolve(dirname(path), decoded));
    } catch {
      return false;
    }
  }
  return true;
}

try {
  const [traceability, specification, files] = await Promise.all([
    readFile(traceabilityPath, "utf8"),
    readFile(specificationPath, "utf8"),
    markdownFiles(contractDirectory),
  ]);
  if (!exactDecisionCoverage(traceability) || !referencesAreDefined(traceability, specification)) {
    fail();
  }
  for (const path of files) {
    if (!(await localLinksResolve(path, await readFile(path, "utf8")))) fail();
  }
  process.stdout.write(
    `Production contract verified: 195 decisions, closed references, ${files.length} linked documents.\n`,
  );
} catch {
  fail();
}
