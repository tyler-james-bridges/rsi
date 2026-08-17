import { readFile } from "node:fs/promises";

const root = new URL("../../", import.meta.url);
const APPROVED_NODE_VERSION = "24.19.0";
const APPROVED_PNPM_VERSION = "11.20.0";
const APPROVED_NODE_TYPES_VERSION = "24.13.3";
const packageJson = JSON.parse(await readFile(new URL("package.json", root), "utf8"));
const preflightPackageJson = JSON.parse(
  await readFile(new URL("packages/preflight/package.json", root), "utf8"),
);
const expectedNode = packageJson.engines?.node;
const packageManager = packageJson.packageManager;
const expectedPnpm =
  typeof packageManager === "string" ? packageManager.match(/^pnpm@(.+)$/u)?.[1] : undefined;
const expectedNodeTypes = packageJson.devDependencies?.["@types/node"];
const nvmPin = (await readFile(new URL(".nvmrc", root), "utf8")).trim();
const nodeVersionPin = (await readFile(new URL(".node-version", root), "utf8")).trim();
const pnpmVersion = /(?:^|\s)pnpm\/([^\s]+)/u.exec(process.env.npm_config_user_agent ?? "")?.[1];

const failures = [];
if (
  typeof expectedNode !== "string" ||
  expectedNode !== APPROVED_NODE_VERSION ||
  expectedNode !== nvmPin ||
  expectedNode !== nodeVersionPin
) {
  failures.push("Node pins disagree");
}
if (process.versions.node !== expectedNode)
  failures.push("active Node does not match the exact pin");
if (expectedNodeTypes !== APPROVED_NODE_TYPES_VERSION) {
  failures.push("Node type declarations do not match the approved exact pin");
}
if (expectedPnpm !== APPROVED_PNPM_VERSION) {
  failures.push("packageManager does not match the approved exact pnpm pin");
}
if (packageJson.engines?.pnpm !== expectedPnpm)
  failures.push("pnpm engine and packageManager pins disagree");
if (pnpmVersion !== expectedPnpm) failures.push("active pnpm does not match the exact pin");
if (
  preflightPackageJson.engines?.node !== APPROVED_NODE_VERSION ||
  preflightPackageJson.engines?.pnpm !== APPROVED_PNPM_VERSION
) {
  failures.push("preflight package engines do not match the approved runtime pins");
}

if (failures.length > 0) {
  process.stderr.write(`Runtime verification failed (${failures.length} condition(s)).\n`);
  process.exitCode = 1;
} else {
  process.stdout.write(`Runtime pins verified: Node ${expectedNode}, pnpm ${expectedPnpm}.\n`);
}
