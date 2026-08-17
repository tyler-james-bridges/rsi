import { spawnSync } from "node:child_process";
import { lstat, readFile } from "node:fs/promises";
import { extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
const rootPrefix = root.endsWith(sep) ? root : `${root}${sep}`;
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const MAX_HISTORY_BYTES = 64 * 1024 * 1024;
const forbiddenTrackedNames = [
  /(?:^|\/)\.env(?:\..+)?$/u,
  /\.(?:key|pem|keystore|p12|pfx)$/iu,
  /(?:^|\/)(?:id_rsa|id_ed25519)$/u,
];
const secretPatterns = [
  /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/u,
  /\bAKIA[0-9A-Z]{16}\b/u,
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/u,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/u,
  /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/u,
  /\bAIza[0-9A-Za-z_-]{30,}\b/u,
  /\bsk-[A-Za-z0-9_-]{20,}\b/u,
  /https?:\/\/[^\s/@:]+:[^\s/@]+@[^\s/]+/iu,
];

function git(args, maxBuffer = 4 * 1024 * 1024) {
  return spawnSync("git", args, { cwd: root, encoding: "utf8", maxBuffer, shell: false });
}

function containsSecret(content) {
  return secretPatterns.some((pattern) => pattern.test(content));
}

const filesResult = git(["ls-files", "-co", "--exclude-standard", "-z"]);
let findings = 0;
let scannedFiles = 0;
if (filesResult.status !== 0) {
  findings += 1;
} else {
  const files = filesResult.stdout.split("\0").filter(Boolean);
  for (const relativePath of files) {
    const forbiddenName = forbiddenTrackedNames.some((pattern) => pattern.test(relativePath));
    if (forbiddenName && relativePath !== ".env.example") {
      findings += 1;
      continue;
    }
    if (
      [".png", ".jpg", ".jpeg", ".gif", ".pdf", ".sqlite", ".db"].includes(extname(relativePath))
    ) {
      continue;
    }
    const absolutePath = resolve(root, relativePath);
    if (!absolutePath.startsWith(rootPrefix)) {
      findings += 1;
      continue;
    }
    let metadata;
    try {
      metadata = await lstat(absolutePath);
    } catch {
      findings += 1;
      continue;
    }
    // Reject links and special files instead of following a repository path to
    // an unbounded device or content outside the checkout.
    if (!metadata.isFile() || metadata.size > MAX_FILE_BYTES) {
      findings += 1;
      continue;
    }
    let content;
    try {
      content = await readFile(absolutePath, "utf8");
    } catch {
      findings += 1;
      continue;
    }
    if (Buffer.byteLength(content) > MAX_FILE_BYTES) {
      findings += 1;
      continue;
    }
    scannedFiles += 1;
    if (containsSecret(content)) findings += 1;
  }
}

const historyResult = git(["log", "--all", "-p", "--no-ext-diff", "--binary"], MAX_HISTORY_BYTES);
if (historyResult.status !== 0 || containsSecret(historyResult.stdout)) findings += 1;

if (findings > 0) {
  process.stderr.write(`Secret scan failed (${findings} content-free finding(s)).\n`);
  process.exitCode = 1;
} else {
  process.stdout.write(`Secret scan passed across ${scannedFiles} file(s) and full Git history.\n`);
}
