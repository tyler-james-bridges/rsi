import { spawnSync } from "node:child_process";
import { generateKeyPairSync, sign as signEd25519, type KeyObject } from "node:crypto";
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  createSignedReleaseBundle,
  deriveReleaseArtifactBindings,
  ReleaseBundleError,
  restoreSignedReleaseBundle,
  verifySignedReleaseBundle,
  type CreateSignedReleaseBundleOptions,
  type ReleaseArtifactInputV1,
  type ReleaseBundleReceiptV1,
  type ReleaseBundleSignerV1,
} from "../src/index.js";
import {
  ARCHIVE_MAGIC,
  manifestSignatureMessage,
  type ManifestEnvelopeV1,
  type ReleaseBundleManifestV1,
} from "../src/archive.js";
import { REQUIRED_CONFIG_SCHEMA_NAMES, REQUIRED_TEST_CHECKS } from "../src/artifacts.js";
import { canonicalJson, sha256 } from "../src/canonical.js";

const COMMIT = "a".repeat(40);
const TREE = "b".repeat(40);
const RELEASE_VERSION = "1.2.3";
const CREATED_AT = "2026-08-14T18:00:00.000Z";
const TEST_COMPLETED_AT = "2026-08-14T17:59:00.000Z";
const encoder = new TextEncoder();

interface Fixture {
  readonly artifacts: readonly ReleaseArtifactInputV1[];
  readonly options: CreateSignedReleaseBundleOptions;
  readonly privateKey: KeyObject;
  readonly publicKeySpkiDer: Uint8Array;
  readonly signer: ReleaseBundleSignerV1;
}

describe("signed release bundle", () => {
  let root: string;

  beforeEach(async () => {
    root = await realpath(await mkdtemp(join(tmpdir(), "rsi-release-test-")));
    await chmod(root, 0o700);
  });

  afterEach(async () => {
    await rm(root, { force: true, recursive: true });
  });

  it("creates and verifies a closed restorable release component", async () => {
    const fixture = makeFixture(join(root, "observer.rsi-release"));
    const receipt = await createSignedReleaseBundle(fixture.options);
    const report = await verifySignedReleaseBundle({
      archivePath: fixture.options.destinationPath,
      trust: trust(receipt, fixture.publicKeySpkiDer),
    });

    expect(report).toMatchObject({
      artifactSetSha256: receipt.artifactSetSha256,
      bundleId: receipt.bundleId,
      commitSha: COMMIT,
      companionType: "signed-release-bundle",
      gitTreeSha: TREE,
      recoveryCompleteness: "release-component",
      releaseVersion: RELEASE_VERSION,
      requiredCompanionArtifacts: ["sanitized-state-evidence", "sanitized-event-archive"],
      status: "verified-restorable-release-component",
      version: 1,
    });
    expect(report.artifactCount).toBe(fixture.artifacts.length);
    expect(receipt.requiredCompanionArtifacts).toEqual([
      "sanitized-state-evidence",
      "sanitized-event-archive",
    ]);
    const archiveStat = await lstat(fixture.options.destinationPath);
    expect(archiveStat.isFile()).toBe(true);
    expect(archiveStat.nlink).toBe(1);
    expect(archiveStat.mode & 0o777).toBe(0o600);
    const archiveBytes = await readFile(fixture.options.destinationPath);
    const manifestStart = ARCHIVE_MAGIC.length + 4;
    const manifestLength = archiveBytes.readUInt32BE(ARCHIVE_MAGIC.length);
    const envelopeText = archiveBytes
      .subarray(manifestStart, manifestStart + manifestLength)
      .toString("utf8");
    const envelope = JSON.parse(envelopeText) as ManifestEnvelopeV1;
    expect(canonicalJson(envelope)).toBe(envelopeText);
    expect(envelope.manifest.artifacts.map(({ path }) => path)).toEqual(
      [...envelope.manifest.artifacts.map(({ path }) => path)].sort(),
    );
  });

  it("derives deterministic bindings and rejects a mismatched claimed binding", async () => {
    const fixture = makeFixture(join(root, "bindings.rsi-release"));
    const forward = deriveReleaseArtifactBindings(fixture.artifacts);
    const reverse = deriveReleaseArtifactBindings([...fixture.artifacts].reverse());
    expect(reverse).toEqual(forward);
    expect(forward.configSetSha256).toBe(
      sha256(
        canonicalJson({
          configSchemaHashesType: "rsi.backup.config-schema-hashes",
          schemas: REQUIRED_CONFIG_SCHEMA_NAMES.map((name) => {
            const schema = fixture.artifacts.find(
              ({ path }) => path === `config-schemas/${name}.schema.json`,
            )!;
            return { name, schemaSha256: sha256(schema.bytes), version: 1 };
          }),
          version: 1,
        }),
      ),
    );

    await expect(
      createSignedReleaseBundle({
        ...fixture.options,
        release: { ...fixture.options.release, sourceTreeSha256: "f".repeat(64) },
      }),
    ).rejects.toMatchObject({ code: "INTEGRITY_MISMATCH" });
    await expect(lstat(fixture.options.destinationPath)).rejects.toBeDefined();
  });

  it("uses retained receipts to reject tamper, truncation, and rollback", async () => {
    const first = makeFixture(join(root, "first.rsi-release"));
    const firstReceipt = await createSignedReleaseBundle(first.options);
    const original = await readFile(first.options.destinationPath);

    const tamperedPath = join(root, "tampered.rsi-release");
    const tampered = Buffer.from(original);
    tampered[tampered.length - 1] = tampered[tampered.length - 1]! ^ 1;
    await writePrivate(tamperedPath, tampered);
    await expect(
      verifySignedReleaseBundle({
        archivePath: tamperedPath,
        trust: trust(firstReceipt, first.publicKeySpkiDer),
      }),
    ).rejects.toMatchObject({ code: "TRUST_MISMATCH" });

    const truncatedPath = join(root, "truncated.rsi-release");
    const truncated = original.subarray(0, original.length - 7);
    await writePrivate(truncatedPath, truncated);
    await expect(
      verifySignedReleaseBundle({
        archivePath: truncatedPath,
        trust: trust(
          {
            ...firstReceipt,
            archiveSha256: sha256(truncated),
            archiveSizeBytes: truncated.length,
          },
          first.publicKeySpkiDer,
        ),
      }),
    ).rejects.toBeInstanceOf(ReleaseBundleError);

    const secondArtifacts = makeArtifacts("1.2.4", "c".repeat(40));
    const secondBindings = deriveReleaseArtifactBindings(secondArtifacts);
    const second = makeFixture(join(root, "second.rsi-release"), {
      artifacts: secondArtifacts,
      commitSha: "c".repeat(40),
      predecessorManifestSha256: firstReceipt.manifestSha256,
      releaseVersion: "1.2.4",
    });
    expect(second.options.release).toMatchObject(secondBindings);
    const secondReceipt = await createSignedReleaseBundle(second.options);

    await expect(
      verifySignedReleaseBundle({
        archivePath: first.options.destinationPath,
        trust: trust(secondReceipt, first.publicKeySpkiDer),
      }),
    ).rejects.toMatchObject({ code: "TRUST_MISMATCH" });
  });

  it("rejects a correctly re-signed semantic downgrade", async () => {
    const fixture = makeFixture(join(root, "original.rsi-release"));
    const receipt = await createSignedReleaseBundle(fixture.options);
    const original = await readFile(fixture.options.destinationPath);
    const forged = forgeArchive(original, fixture.privateKey, (manifest) => {
      (manifest as unknown as { recoveryCompleteness: string }).recoveryCompleteness =
        "evidence-only";
    });
    const forgedPath = join(root, "downgraded.rsi-release");
    await writePrivate(forgedPath, forged.bytes);
    const matchingArchiveReceipt = {
      ...receipt,
      archiveSha256: sha256(forged.bytes),
      archiveSizeBytes: forged.bytes.length,
      manifestSha256: sha256(canonicalJson(forged.envelope.manifest)),
    };

    await expect(
      verifySignedReleaseBundle({
        archivePath: forgedPath,
        trust: trust(matchingArchiveReceipt, fixture.publicKeySpkiDer),
      }),
    ).rejects.toMatchObject({ code: "ARCHIVE_FORMAT" });
  });

  it("rejects a forged signature even when archive receipt fields are recomputed", async () => {
    const fixture = makeFixture(join(root, "signed.rsi-release"));
    const receipt = await createSignedReleaseBundle(fixture.options);
    const bytes = await readFile(fixture.options.destinationPath);
    const changed = rewriteEnvelope(bytes, (envelope) => {
      envelope.signature = `${envelope.signature.startsWith("A") ? "B" : "A"}${envelope.signature.slice(1)}`;
    });
    const path = join(root, "bad-signature.rsi-release");
    await writePrivate(path, changed.bytes);

    await expect(
      verifySignedReleaseBundle({
        archivePath: path,
        trust: trust(
          {
            ...receipt,
            archiveSha256: sha256(changed.bytes),
            archiveSizeBytes: changed.bytes.length,
          },
          fixture.publicKeySpkiDer,
        ),
      }),
    ).rejects.toMatchObject({ code: "SIGNATURE_INVALID" });
  });

  it("enforces traversal, closed-inventory, and secret-smuggling policy", () => {
    const artifacts = makeArtifacts();
    const runtimeIndex = artifacts.findIndex(
      ({ path }) => path === "source/packages/observer/src/index.ts",
    );
    const configIndex = artifacts.findIndex(
      ({ path }) => path === "config-schemas/vault.schema.json",
    );

    expect(() =>
      deriveReleaseArtifactBindings([
        ...artifacts.slice(0, runtimeIndex),
        { ...artifacts[runtimeIndex]!, path: "source/../escape.ts" },
        ...artifacts.slice(runtimeIndex + 1),
      ]),
    ).toThrowError(ReleaseBundleError);
    expect(() =>
      deriveReleaseArtifactBindings([
        ...artifacts.slice(0, runtimeIndex),
        {
          ...artifacts[runtimeIndex]!,
          path: "source/packages/observer/node_modules/foreign/index.ts",
        },
        ...artifacts.slice(runtimeIndex + 1),
      ]),
    ).toThrowError(ReleaseBundleError);
    expect(() =>
      deriveReleaseArtifactBindings([
        ...artifacts.slice(0, configIndex),
        ...artifacts.slice(configIndex + 1),
      ]),
    ).toThrowError(ReleaseBundleError);

    const secret = ["sk", "fixture"].join("-") + "A".repeat(32);
    expect(() =>
      deriveReleaseArtifactBindings([
        ...artifacts.slice(0, runtimeIndex),
        {
          ...artifacts[runtimeIndex]!,
          bytes: utf8(`export const unsafe = ${JSON.stringify(secret)};\n`),
        },
        ...artifacts.slice(runtimeIndex + 1),
      ]),
    ).toThrowError(expect.objectContaining({ code: "SECRET_DETECTED" }));

    const encodedKey = ["LS0tLS1CRUdJTi", "BQUklWQVRFIEtFWS0tLS0t"].join("");
    expect(() =>
      deriveReleaseArtifactBindings([
        ...artifacts.slice(0, runtimeIndex),
        {
          ...artifacts[runtimeIndex]!,
          bytes: utf8(`export const encoded = ${JSON.stringify(encodedKey)};\n`),
        },
        ...artifacts.slice(runtimeIndex + 1),
      ]),
    ).toThrowError(expect.objectContaining({ code: "SECRET_DETECTED" }));
  });

  it("does not flag its own scanner implementation as a secret", async () => {
    const artifacts = makeArtifacts();
    const runtimeIndex = artifacts.findIndex(
      ({ path }) => path === "source/packages/observer/src/index.ts",
    );
    const scannerSource = new Uint8Array(
      await readFile(new URL("../src/artifacts.ts", import.meta.url)),
    );
    expect(() =>
      deriveReleaseArtifactBindings([
        ...artifacts.slice(0, runtimeIndex),
        { ...artifacts[runtimeIndex]!, bytes: scannerSource },
        ...artifacts.slice(runtimeIndex + 1),
      ]),
    ).not.toThrow();
  });

  it("rejects accessors, proxies, shared memory, and private-key-shaped signer input", async () => {
    const fixture = makeFixture(join(root, "hostile.rsi-release"));
    const artifacts = [...fixture.artifacts];
    const original = artifacts[0]!;
    let accessorRead = false;
    const hostile: Record<string, unknown> = {
      mediaType: original.mediaType,
      path: original.path,
      role: original.role,
    };
    Object.defineProperty(hostile, "bytes", {
      enumerable: true,
      get() {
        accessorRead = true;
        return original.bytes;
      },
    });
    expect(() => deriveReleaseArtifactBindings([hostile, ...artifacts.slice(1)])).toThrowError(
      ReleaseBundleError,
    );
    expect(accessorRead).toBe(false);
    expect(() => deriveReleaseArtifactBindings(new Proxy(artifacts, {}))).toThrowError(
      ReleaseBundleError,
    );

    const bytesWithAccessor = utf8("safe\n");
    let byteAccessorRead = false;
    Object.defineProperty(bytesWithAccessor, "buffer", {
      get() {
        byteAccessorRead = true;
        return new ArrayBuffer(5);
      },
    });
    expect(() =>
      deriveReleaseArtifactBindings([
        { ...original, bytes: bytesWithAccessor },
        ...artifacts.slice(1),
      ]),
    ).toThrowError(ReleaseBundleError);
    expect(byteAccessorRead).toBe(false);

    const shared = new Uint8Array(new SharedArrayBuffer(32));
    expect(() =>
      deriveReleaseArtifactBindings([{ ...original, bytes: shared }, ...artifacts.slice(1)]),
    ).toThrowError(ReleaseBundleError);

    await expect(
      createSignedReleaseBundle({
        ...fixture.options,
        signer: {
          ...fixture.signer,
          privateKey: fixture.privateKey,
        } as never,
      }),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });
  });

  it("rejects signer-message mutation and unverifiable callback output", async () => {
    const fixture = makeFixture(join(root, "mutating-signer.rsi-release"));
    await expect(
      createSignedReleaseBundle({
        ...fixture.options,
        signer: {
          ...fixture.signer,
          sign(message: Uint8Array) {
            message[0] = message[0]! ^ 1;
            return new Uint8Array(signEd25519(null, Buffer.from(message), fixture.privateKey));
          },
        },
      }),
    ).rejects.toMatchObject({ code: "SIGNATURE_INVALID" });
  });

  it("rejects symlinks, persistent hardlinks, directories, FIFOs, and occupied destinations", async () => {
    const fixture = makeFixture(join(root, "safe.rsi-release"));
    const receipt = await createSignedReleaseBundle(fixture.options);
    const trusted = trust(receipt, fixture.publicKeySpkiDer);

    const symlinkPath = join(root, "archive-link.rsi-release");
    await symlink(fixture.options.destinationPath, symlinkPath);
    await expect(
      verifySignedReleaseBundle({ archivePath: symlinkPath, trust: trusted }),
    ).rejects.toMatchObject({ code: "ARCHIVE_UNSAFE" });

    const hardlinkPath = join(root, "archive-hardlink.rsi-release");
    await link(fixture.options.destinationPath, hardlinkPath);
    await expect(
      verifySignedReleaseBundle({ archivePath: hardlinkPath, trust: trusted }),
    ).rejects.toMatchObject({ code: "ARCHIVE_UNSAFE" });
    await unlink(hardlinkPath);

    const directoryPath = join(root, "archive-directory.rsi-release");
    await mkdir(directoryPath, { mode: 0o700 });
    await expect(
      verifySignedReleaseBundle({ archivePath: directoryPath, trust: trusted }),
    ).rejects.toMatchObject({ code: "ARCHIVE_UNSAFE" });

    const fifoPath = join(root, "archive-fifo.rsi-release");
    const fifo = spawnSync("mkfifo", [fifoPath], { shell: false });
    expect(fifo.status).toBe(0);
    await chmod(fifoPath, 0o600);
    await expect(
      verifySignedReleaseBundle({ archivePath: fifoPath, trust: trusted }),
    ).rejects.toMatchObject({ code: "ARCHIVE_UNSAFE" });

    const occupiedPath = join(root, "occupied.rsi-release");
    await symlink(fixture.options.destinationPath, occupiedPath);
    const occupiedFixture = makeFixture(occupiedPath);
    await expect(createSignedReleaseBundle(occupiedFixture.options)).rejects.toMatchObject({
      code: "DESTINATION_EXISTS",
    });
  });

  it("allows exactly one concurrent create-only publication", async () => {
    const destinationPath = join(root, "concurrent.rsi-release");
    const fixture = makeFixture(destinationPath);
    const results = await Promise.allSettled([
      createSignedReleaseBundle(fixture.options),
      createSignedReleaseBundle(fixture.options),
    ]);
    expect(results.filter(({ status }) => status === "fulfilled")).toHaveLength(1);
    expect(results.filter(({ status }) => status === "rejected")).toHaveLength(1);
    const fulfilled = results.find(
      (result): result is PromiseFulfilledResult<ReleaseBundleReceiptV1> =>
        result.status === "fulfilled",
    );
    expect(fulfilled).toBeDefined();
    await expect(
      verifySignedReleaseBundle({
        archivePath: destinationPath,
        trust: trust(fulfilled!.value, fixture.publicKeySpkiDer),
      }),
    ).resolves.toMatchObject({ status: "verified-restorable-release-component" });
    expect((await readdir(root)).some((name) => name.startsWith(".rsi-release-partial-"))).toBe(
      false,
    );
  });

  it("fully verifies before restore and never overwrites a restore destination", async () => {
    const fixture = makeFixture(join(root, "restore-source.rsi-release"));
    const receipt = await createSignedReleaseBundle(fixture.options);
    const trusted = trust(receipt, fixture.publicKeySpkiDer);
    const destination = join(root, "restored");
    const report = await restoreSignedReleaseBundle({
      archivePath: fixture.options.destinationPath,
      destinationDirectory: destination,
      trust: trusted,
    });
    expect(report.restoredFileCount).toBe(fixture.artifacts.length + 1);
    expect(await readFile(join(destination, "source/packages/observer/src/index.ts"), "utf8")).toBe(
      "export const observer = true;\n",
    );
    expect((await lstat(destination)).mode & 0o777).toBe(0o700);
    expect((await lstat(join(destination, "source/package.json"))).mode & 0o777).toBe(0o600);
    expect(
      await readFile(join(destination, "release/signed-release-manifest.v1.json"), "utf8"),
    ).toContain('"signature"');

    await expect(
      restoreSignedReleaseBundle({
        archivePath: fixture.options.destinationPath,
        destinationDirectory: destination,
        trust: trusted,
      }),
    ).rejects.toMatchObject({ code: "DESTINATION_EXISTS" });

    const badArchive = join(root, "restore-tampered.rsi-release");
    const bytes = await readFile(fixture.options.destinationPath);
    bytes[bytes.length - 1] = bytes[bytes.length - 1]! ^ 1;
    await writePrivate(badArchive, bytes);
    const untouchedDestination = join(root, "must-not-exist");
    await expect(
      restoreSignedReleaseBundle({
        archivePath: badArchive,
        destinationDirectory: untouchedDestination,
        trust: trusted,
      }),
    ).rejects.toMatchObject({ code: "TRUST_MISMATCH" });
    await expect(lstat(untouchedDestination)).rejects.toBeDefined();
  });
});

function makeFixture(
  destinationPath: string,
  overrides: {
    readonly artifacts?: readonly ReleaseArtifactInputV1[];
    readonly commitSha?: string;
    readonly predecessorManifestSha256?: string | null;
    readonly releaseVersion?: string;
  } = {},
): Fixture {
  const releaseVersion = overrides.releaseVersion ?? RELEASE_VERSION;
  const commitSha = overrides.commitSha ?? COMMIT;
  const artifacts = overrides.artifacts ?? makeArtifacts(releaseVersion, commitSha);
  const bindings = deriveReleaseArtifactBindings(artifacts);
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeySpkiDer = new Uint8Array(publicKey.export({ format: "der", type: "spki" }));
  const signer: ReleaseBundleSignerV1 = Object.freeze({
    keyId: "release-key-1",
    publicKeySpkiDer,
    sign(message: Uint8Array) {
      return new Uint8Array(signEd25519(null, Buffer.from(message), privateKey));
    },
  });
  const options: CreateSignedReleaseBundleOptions = {
    artifacts,
    destinationPath,
    release: {
      ...bindings,
      commitSha,
      createdAt: CREATED_AT,
      gitTreeSha: TREE,
      nodeVersion: "24.19.0",
      pnpmVersion: "11.20.0",
      predecessorManifestSha256: overrides.predecessorManifestSha256 ?? null,
      releaseVersion,
    },
    signer,
  };
  return Object.freeze({ artifacts, options, privateKey, publicKeySpkiDer, signer });
}

function makeArtifacts(
  releaseVersion = RELEASE_VERSION,
  commitSha = COMMIT,
): readonly ReleaseArtifactInputV1[] {
  const artifacts: ReleaseArtifactInputV1[] = [
    artifact(
      "source/package.json",
      "source",
      "application/json",
      canonicalJson({
        engines: { node: "24.19.0", pnpm: "11.20.0" },
        name: "rsi",
        packageManager: "pnpm@11.20.0",
        private: true,
        type: "module",
        version: releaseVersion,
      }),
    ),
    artifact(
      "source/pnpm-workspace.yaml",
      "source",
      "application/yaml",
      "packages:\n  - packages/*\n",
    ),
    artifact(
      "source/tsconfig.json",
      "source",
      "application/json",
      canonicalJson({ compilerOptions: { strict: true } }),
    ),
    artifact(
      "source/packages/observer/src/index.ts",
      "source",
      "text/typescript",
      "export const observer = true;\n",
    ),
    artifact("source/pnpm-lock.yaml", "lockfile", "application/yaml", "lockfileVersion: '9.0'\n"),
  ];
  for (const name of REQUIRED_CONFIG_SCHEMA_NAMES) {
    artifacts.push(
      artifact(
        `config-schemas/${name}.schema.json`,
        "config-schema",
        "application/json",
        canonicalJson({
          name,
          schema: { additionalProperties: false, type: "object" },
          schemaType: "rsi.versioned-config-schema",
          schemaVersion: 1,
        }),
      ),
    );
  }
  artifacts.push(
    artifact(
      "runbooks/README.md",
      "runbook",
      "text/markdown",
      `# Observer runbooks\n\n${Array.from({ length: 19 }, (_, index) => `RB-${String(index + 1).padStart(2, "0")}: sanitized procedure`).join("\n")}\n`,
    ),
    artifact(
      "recovery/observer-restore.md",
      "recovery-procedure",
      "text/markdown",
      "# Observer restore\n\nRSI-RECOVERY-PROCEDURE-V1\nVERIFY-BEFORE-RESTORE\nNO-SECRET-RESTORE\nNEW-LINEAGE-REQUIRED\n",
    ),
    artifact(
      "release/sbom.cdx.json",
      "sbom",
      "application/json",
      canonicalJson({
        bomFormat: "CycloneDX",
        metadata: {
          component: { name: "rsi", type: "application", version: releaseVersion },
        },
        specVersion: "1.6",
        version: 1,
      }),
    ),
    artifact(
      "release/test-summary.v1.json",
      "test-summary",
      "application/json",
      canonicalJson({
        commitSha,
        completedAt: TEST_COMPLETED_AT,
        requiredChecks: REQUIRED_TEST_CHECKS.map((name) => ({
          name,
          outcome: "passed",
          resultSha256: sha256(`result:${name}`),
        })),
        summaryType: "rsi.release.test-summary",
        version: 1,
      }),
    ),
  );
  return Object.freeze(artifacts);
}

function artifact(
  path: string,
  role: ReleaseArtifactInputV1["role"],
  mediaType: ReleaseArtifactInputV1["mediaType"],
  text: string,
): ReleaseArtifactInputV1 {
  return Object.freeze({ bytes: utf8(text), mediaType, path, role });
}

function utf8(text: string): Uint8Array {
  return encoder.encode(text);
}

function trust(receipt: ReleaseBundleReceiptV1, releasePublicKeySpkiDer: Uint8Array) {
  return { receipt, releasePublicKeySpkiDer };
}

async function writePrivate(path: string, bytes: Uint8Array): Promise<void> {
  await writeFile(path, bytes, { flag: "wx", mode: 0o600 });
  await chmod(path, 0o600);
}

function forgeArchive(
  original: Buffer,
  privateKey: KeyObject,
  mutate: (manifest: ReleaseBundleManifestV1) => void,
): { readonly bytes: Buffer; readonly envelope: ManifestEnvelopeV1 } {
  const parsed = readEnvelopeAndTail(original);
  mutate(parsed.envelope.manifest);
  parsed.envelope.signature = signEd25519(
    null,
    manifestSignatureMessage(parsed.envelope.manifest),
    privateKey,
  ).toString("base64url");
  return rewriteFromParts(parsed.envelope, parsed.tail);
}

function rewriteEnvelope(
  original: Buffer,
  mutate: (envelope: { manifest: ReleaseBundleManifestV1; signature: string }) => void,
): { readonly bytes: Buffer; readonly envelope: ManifestEnvelopeV1 } {
  const parsed = readEnvelopeAndTail(original);
  mutate(parsed.envelope);
  return rewriteFromParts(parsed.envelope, parsed.tail);
}

function readEnvelopeAndTail(original: Buffer): {
  readonly envelope: { manifest: ReleaseBundleManifestV1; signature: string };
  readonly tail: Buffer;
} {
  const minimum = ARCHIVE_MAGIC.length + 4;
  const envelopeLength = original.readUInt32BE(ARCHIVE_MAGIC.length);
  const envelope = JSON.parse(
    original.subarray(minimum, minimum + envelopeLength).toString("utf8"),
  ) as { manifest: ReleaseBundleManifestV1; signature: string };
  return { envelope, tail: Buffer.from(original.subarray(minimum + envelopeLength)) };
}

function rewriteFromParts(
  envelope: { manifest: ReleaseBundleManifestV1; signature: string },
  tail: Buffer,
): { readonly bytes: Buffer; readonly envelope: ManifestEnvelopeV1 } {
  const envelopeBytes = Buffer.from(canonicalJson(envelope), "utf8");
  const header = Buffer.alloc(ARCHIVE_MAGIC.length + 4);
  ARCHIVE_MAGIC.copy(header);
  header.writeUInt32BE(envelopeBytes.length, ARCHIVE_MAGIC.length);
  return {
    bytes: Buffer.concat([header, envelopeBytes, tail]),
    envelope: envelope as ManifestEnvelopeV1,
  };
}
