import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(fileURLToPath(new URL("../../", import.meta.url)));
const gitEnvironment = {
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_OPTIONAL_LOCKS: "0",
  LANG: "C",
  LC_ALL: "C",
  PATH: process.env.PATH ?? "/usr/bin:/bin",
};
const gitObjectAlgorithms = new Map([
  ["sha1", { digest: "sha1", length: 40 }],
  ["sha256", { digest: "sha256", length: 64 }],
]);

function fail(message) {
  throw new Error(message);
}

function git(args, options = {}) {
  const result = spawnSync("git", ["--no-replace-objects", ...args], {
    cwd: repositoryRoot,
    encoding: options.encoding ?? "buffer",
    env: gitEnvironment,
    input: options.input,
    maxBuffer: options.maxBuffer ?? 64 * 1024 * 1024,
    shell: false,
    timeout: 30_000,
  });
  if (result.status !== 0 || result.signal !== null) {
    fail("Git source inspection failed.");
  }
  return result.stdout;
}

function gitText(args) {
  return git(args, { encoding: "utf8" }).trim();
}

function assertCleanRepository() {
  const status = git([
    "status",
    "--porcelain=v1",
    "-z",
    "--untracked-files=all",
    "--ignore-submodules=none",
  ]);
  if (status.length !== 0) {
    fail("Source inventory requires a clean Git working tree and index.");
  }
}

function validateObjectId(value, objectFormat, label) {
  const algorithm = gitObjectAlgorithms.get(objectFormat);
  if (algorithm === undefined || !new RegExp(`^[0-9a-f]{${algorithm.length}}$`, "u").test(value)) {
    fail(`${label} is not a full ${objectFormat} Git object ID.`);
  }
  return value;
}

function parseTree(treeSha, objectFormat) {
  const output = git(["ls-tree", "-rz", "--full-tree", "--no-abbrev", treeSha]);
  const entries = [];
  let offset = 0;

  while (offset < output.length) {
    const end = output.indexOf(0, offset);
    if (end < 0) fail("Git tree output is not NUL terminated.");
    const record = output.subarray(offset, end);
    const separator = record.indexOf(0x09);
    if (separator <= 0 || separator === record.length - 1) {
      fail("Git tree entry is malformed.");
    }

    const header = record.subarray(0, separator).toString("ascii");
    const match = /^(\d{6}) ([a-z]+) ([0-9a-f]+)$/u.exec(header);
    if (match === null) fail("Git tree entry header is malformed.");
    const [, mode, type, objectIdValue] = match;
    if ((mode !== "100644" && mode !== "100755") || type !== "blob") {
      fail("Source inventory supports regular tracked blobs only.");
    }

    const objectId = validateObjectId(objectIdValue, objectFormat, "Tracked blob");
    entries.push({ mode, objectId, path: Buffer.from(record.subarray(separator + 1)) });
    offset = end + 1;
  }

  if (entries.length === 0) fail("Git source tree contains no tracked blobs.");
  entries.sort((left, right) => Buffer.compare(left.path, right.path));
  for (let index = 0; index < entries.length; index += 1) {
    if (
      entries[index].path.length === 0 ||
      (index > 0 && Buffer.compare(entries[index - 1].path, entries[index].path) === 0)
    ) {
      fail("Git source tree contains an invalid tracked path.");
    }
  }
  return entries;
}

function frame(hash, label, value) {
  hash.update(`${label}\0${value.length}\0`, "ascii");
  hash.update(value);
  hash.update("\0", "ascii");
}

function hashGitBlob(bytes, objectFormat) {
  const algorithm = gitObjectAlgorithms.get(objectFormat);
  if (algorithm === undefined) fail("Unsupported Git object format.");
  return createHash(algorithm.digest)
    .update(`blob ${bytes.length}\0`, "ascii")
    .update(bytes)
    .digest("hex");
}

function readCommittedBlobs(entries) {
  const input = Buffer.from(`${entries.map((entry) => entry.objectId).join("\n")}\n`, "ascii");
  const output = git(["cat-file", "--batch"], {
    input,
    maxBuffer: 256 * 1024 * 1024,
  });
  const blobs = [];
  let offset = 0;

  for (const entry of entries) {
    const headerEnd = output.indexOf(0x0a, offset);
    if (headerEnd < 0) fail("Git blob batch output is malformed.");
    const header = output.subarray(offset, headerEnd).toString("ascii");
    const match = /^([0-9a-f]+) ([a-z]+) ([0-9]+)$/u.exec(header);
    if (match === null) fail("Git blob batch header is malformed.");
    const [, returnedObjectId, type, sizeValue] = match;
    const size = Number(sizeValue);
    const blobStart = headerEnd + 1;
    const blobEnd = blobStart + size;
    if (
      returnedObjectId !== entry.objectId ||
      type !== "blob" ||
      !Number.isSafeInteger(size) ||
      size < 0 ||
      blobEnd >= output.length ||
      output[blobEnd] !== 0x0a
    ) {
      fail("Git blob batch response does not match the committed tree.");
    }
    blobs.push(output.subarray(blobStart, blobEnd));
    offset = blobEnd + 1;
  }

  if (offset !== output.length) fail("Git blob batch output contains trailing data.");
  return blobs;
}

function isWithin(base, path) {
  const fromRoot = relative(base, path);
  return (
    fromRoot === "" ||
    (fromRoot !== ".." && !fromRoot.startsWith(`..${sep}`) && !isAbsolute(fromRoot))
  );
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function sameFileState(left, right) {
  return (
    sameFileIdentity(left, right) &&
    left.mode === right.mode &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

function readWorkingTreeBlob(entry, repositoryRealRoot) {
  const relativePath = entry.path.toString("utf8");
  if (!Buffer.from(relativePath, "utf8").equals(entry.path)) {
    fail("Working tree contains a tracked path that is not valid UTF-8.");
  }
  const absolutePath = resolve(repositoryRoot, relativePath);
  if (!isWithin(repositoryRoot, absolutePath)) fail("Tracked path escapes the working tree.");

  let pathBefore;
  let descriptor;
  try {
    const realPath = realpathSync(absolutePath);
    if (realPath !== resolve(repositoryRealRoot, relativePath)) {
      fail(`Tracked working-tree path traverses a symlink: ${JSON.stringify(relativePath)}`);
    }
    pathBefore = lstatSync(absolutePath, { bigint: true });
    if (!pathBefore.isFile() || pathBefore.isSymbolicLink()) {
      fail(`Tracked working-tree path is not a regular file: ${JSON.stringify(relativePath)}`);
    }
    descriptor = openSync(absolutePath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  } catch {
    fail(`Tracked working-tree file is missing or unreadable: ${JSON.stringify(relativePath)}`);
  }

  try {
    const descriptorBefore = fstatSync(descriptor, { bigint: true });
    if (!descriptorBefore.isFile() || !sameFileIdentity(pathBefore, descriptorBefore)) {
      fail(`Tracked working-tree path changed while opening: ${JSON.stringify(relativePath)}`);
    }
    if (process.platform !== "win32") {
      const isExecutable = (descriptorBefore.mode & 0o111n) !== 0n;
      if (isExecutable !== (entry.mode === "100755")) {
        fail(`Tracked working-tree mode does not match HEAD: ${JSON.stringify(relativePath)}`);
      }
    }

    const bytes = readFileSync(descriptor);
    const descriptorAfter = fstatSync(descriptor, { bigint: true });
    const pathAfter = lstatSync(absolutePath, { bigint: true });
    if (
      !sameFileState(descriptorBefore, descriptorAfter) ||
      !pathAfter.isFile() ||
      pathAfter.isSymbolicLink() ||
      !sameFileState(descriptorAfter, pathAfter)
    ) {
      fail(`Tracked working-tree file changed while reading: ${JSON.stringify(relativePath)}`);
    }
    return bytes;
  } finally {
    closeSync(descriptor);
  }
}

function deriveSourceInventorySha256(entries, objectFormat, repositoryRealRoot) {
  const hash = createHash("sha256");
  hash.update("rsi.git-source-inventory.v1\0", "ascii");
  const blobs = readCommittedBlobs(entries);

  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    const blob = blobs[index];
    if (hashGitBlob(blob, objectFormat) !== entry.objectId) {
      fail("Committed blob does not match its Git object ID.");
    }
    if (!readWorkingTreeBlob(entry, repositoryRealRoot).equals(blob)) {
      fail(
        `Working-tree content does not match HEAD: ${JSON.stringify(entry.path.toString("utf8"))}`,
      );
    }
    frame(hash, "mode", Buffer.from(entry.mode, "ascii"));
    frame(hash, "object", Buffer.from(entry.objectId, "ascii"));
    frame(hash, "path", entry.path);
    frame(hash, "blob", blob);
  }

  return hash.digest("hex");
}

function main() {
  assertCleanRepository();
  const repositoryRealRoot = realpathSync(repositoryRoot);
  const objectFormat = gitText(["rev-parse", "--show-object-format=storage"]);
  if (!gitObjectAlgorithms.has(objectFormat)) fail("Unsupported Git object format.");

  const commitSha = validateObjectId(
    gitText(["rev-parse", "--verify", "HEAD^{commit}"]),
    objectFormat,
    "HEAD commit",
  );
  const treeSha = validateObjectId(
    gitText(["rev-parse", "--verify", `${commitSha}^{tree}`]),
    objectFormat,
    "HEAD tree",
  );
  const entries = parseTree(treeSha, objectFormat);
  const sourceInventorySha256 = deriveSourceInventorySha256(
    entries,
    objectFormat,
    repositoryRealRoot,
  );

  if (gitText(["rev-parse", "--verify", "HEAD^{commit}"]) !== commitSha) {
    fail("HEAD changed during source inventory verification.");
  }
  assertCleanRepository();

  process.stdout.write(
    `${JSON.stringify({
      commitSha,
      sourceInventorySha256,
      trackedFileCount: entries.length,
      treeSha,
    })}\n`,
  );
}

try {
  main();
} catch (error) {
  const message = error instanceof Error ? error.message : "Source inventory verification failed.";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
}
