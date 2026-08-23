import { spawnSync } from "node:child_process";
import {
  createPublicKey,
  generateKeyPairSync,
  sign as signEd25519,
  verify as verifyEd25519,
  type KeyObject,
} from "node:crypto";
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rename,
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
  decodeEnvelopeForTest,
  manifestSignatureMessage,
  verifyReleaseArchiveBytes,
  type ManifestEnvelopeV1,
  type ReleaseBundleManifestV1,
} from "../src/archive.js";
import { REQUIRED_CONFIG_SCHEMA_NAMES, REQUIRED_TEST_CHECKS } from "../src/artifacts.js";
import { canonicalJson, sha256 } from "../src/canonical.js";
import { publishBundleCreateOnly, restoreVerifiedReleaseArchive } from "../src/filesystem.js";

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
      createdAt: CREATED_AT,
      gitTreeSha: TREE,
      nodeVersion: "24.19.0",
      pnpmVersion: "11.20.0",
      predecessorManifestSha256: null,
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

  it("does not request a signature when the destination parent is invalid", async () => {
    const fixture = makeFixture(join(root, "missing-parent", "release.rsi-release"));
    let signatureCount = 0;

    await expect(
      createSignedReleaseBundle({
        ...fixture.options,
        signer: countingSigner(fixture, () => {
          signatureCount += 1;
        }),
      }),
    ).rejects.toMatchObject({ code: "DESTINATION_UNSAFE" });

    expect(signatureCount).toBe(0);
    expect(await retainedPartialPaths(root)).toEqual([]);
  });

  it("does not request a signature when the destination is already occupied", async () => {
    const destinationPath = join(root, "preflight-occupied.rsi-release");
    await writeFile(destinationPath, "existing", { mode: 0o600 });
    const fixture = makeFixture(destinationPath);
    let signatureCount = 0;

    await expect(
      createSignedReleaseBundle({
        ...fixture.options,
        signer: countingSigner(fixture, () => {
          signatureCount += 1;
        }),
      }),
    ).rejects.toMatchObject({ code: "DESTINATION_EXISTS" });

    expect(signatureCount).toBe(0);
    expect(await readFile(destinationPath, "utf8")).toBe("existing");
    expect(await retainedPartialPaths(root)).toEqual([]);
  });

  it("does not request a signature when the owner-only reservation cannot be opened", async () => {
    const lockedParent = join(root, "locked-parent");
    await mkdir(lockedParent, { mode: 0o500 });
    await chmod(lockedParent, 0o500);
    const fixture = makeFixture(join(lockedParent, "release.rsi-release"));
    let signatureCount = 0;
    try {
      await expect(
        createSignedReleaseBundle({
          ...fixture.options,
          signer: countingSigner(fixture, () => {
            signatureCount += 1;
          }),
        }),
      ).rejects.toMatchObject({ code: "DESTINATION_UNSAFE" });
    } finally {
      await chmod(lockedParent, 0o700);
    }

    expect(signatureCount).toBe(0);
    expect(await retainedPartialPaths(lockedParent)).toEqual([]);
  });

  it("retains the durable reservation when signing fails", async () => {
    const fixture = makeFixture(join(root, "signer-failure.rsi-release"));
    let signatureCount = 0;

    await expect(
      createSignedReleaseBundle({
        ...fixture.options,
        signer: {
          ...fixture.signer,
          sign() {
            signatureCount += 1;
            throw new Error("synthetic signer failure");
          },
        },
      }),
    ).rejects.toMatchObject({ code: "SIGNER_FAILED" });

    expect(signatureCount).toBe(1);
    const [partialPath] = await retainedPartialPaths(root);
    expect(partialPath).toBeDefined();
    const partialStat = await lstat(partialPath!);
    expect(partialStat.mode & 0o777).toBe(0o600);
    expect(partialStat.nlink).toBe(1);
    expect(partialStat.size).toBe(0);

    await expect(
      createSignedReleaseBundle({
        ...fixture.options,
        signer: countingSigner(fixture, () => {
          signatureCount += 1;
        }),
      }),
    ).rejects.toMatchObject({ code: "DESTINATION_EXISTS" });
    expect(signatureCount).toBe(1);
    expect(await retainedPartialPaths(root)).toEqual([partialPath]);
  });

  it("retains the complete signed archive when publication loses a post-signature race", async () => {
    const destinationPath = join(root, "post-signature-race.rsi-release");
    const fixture = makeFixture(destinationPath);
    let signatureCount = 0;

    await expect(
      createSignedReleaseBundle({
        ...fixture.options,
        signer: {
          ...fixture.signer,
          async sign(message) {
            signatureCount += 1;
            const signature = await fixture.signer.sign(message);
            await writeFile(destinationPath, "competing output", { mode: 0o600 });
            return signature;
          },
        },
      }),
    ).rejects.toMatchObject({ code: "DESTINATION_EXISTS" });

    expect(signatureCount).toBe(1);
    expect(await readFile(destinationPath, "utf8")).toBe("competing output");
    const [partialPath] = await retainedPartialPaths(root);
    expect(partialPath).toBeDefined();
    const partialStat = await lstat(partialPath!);
    expect(partialStat.mode & 0o777).toBe(0o600);
    expect(partialStat.nlink).toBe(1);
    expect(partialStat.size).toBeGreaterThan(0);
    expectValidArchiveSignature(await readFile(partialPath!), fixture.publicKeySpkiDer);
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
        archivePath: second.options.destinationPath,
        trust: trust(secondReceipt, second.publicKeySpkiDer),
      }),
    ).resolves.toMatchObject({
      createdAt: CREATED_AT,
      nodeVersion: "24.19.0",
      pnpmVersion: "11.20.0",
      predecessorManifestSha256: firstReceipt.manifestSha256,
    });

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

    const normalizedTextArtifact: ReleaseArtifactInputV1 = {
      bytes: utf8("24.19.0\n"),
      mediaType: "text/plain",
      path: "source/scripts/node-version.txt",
      role: "source",
    };
    expect(() =>
      deriveReleaseArtifactBindings([...artifacts, normalizedTextArtifact]),
    ).not.toThrow();
    const swiftArtifact: ReleaseArtifactInputV1 = {
      bytes: utf8("import Foundation\n\nprivate let fixedHelper = true\n"),
      mediaType: "text/x-swift",
      path: "source/packages/release-key-provisioning/native/keychain-helper.swift",
      role: "source",
    };
    expect(() => deriveReleaseArtifactBindings([...artifacts, swiftArtifact])).not.toThrow();
    for (const path of [
      "source/config/foundation-independent-reviewer-identity.v1.json",
      "source/config/foundation-release-identity.v1.json",
      "source/config/foundation-release-key-helper-compatibility.v1.json",
      "source/config/foundation-release-key-provisioning-receipt.v1.json",
    ]) {
      expect(() =>
        deriveReleaseArtifactBindings([
          ...artifacts,
          {
            bytes: utf8('{"status":"public-evidence-fixture"}\n'),
            mediaType: "application/json",
            path,
            role: "source",
          },
        ]),
      ).not.toThrow();
    }
    expect(() =>
      deriveReleaseArtifactBindings([
        ...artifacts,
        {
          bytes: utf8('{"status":"not-allowlisted"}\n'),
          mediaType: "application/json",
          path: "source/config/unreviewed.json",
          role: "source",
        },
      ]),
    ).toThrowError(ReleaseBundleError);
    expect(() =>
      deriveReleaseArtifactBindings([...artifacts, { ...swiftArtifact, mediaType: "text/plain" }]),
    ).toThrowError(ReleaseBundleError);
    expect(() =>
      deriveReleaseArtifactBindings([
        ...artifacts,
        { ...normalizedTextArtifact, path: "source/scripts/.node-version" },
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
    let signatureCount = 0;
    await expect(
      createSignedReleaseBundle({
        ...occupiedFixture.options,
        signer: countingSigner(occupiedFixture, () => {
          signatureCount += 1;
        }),
      }),
    ).rejects.toMatchObject({ code: "DESTINATION_EXISTS" });
    expect(signatureCount).toBe(0);
  });

  it("retains an owner-only signed partial when publication fails before linking", async () => {
    const source = makeFixture(join(root, "before-link-source.rsi-release"));
    const receipt = await createSignedReleaseBundle(source.options);
    const signedArchive = await readFile(source.options.destinationPath);
    await unlink(source.options.destinationPath);
    const destinationPath = join(root, "before-link.rsi-release");

    await expect(
      publishBundleCreateOnly(destinationPath, signedArchive, {
        beforeLink() {
          throw new Error("synthetic before-link failure");
        },
      }),
    ).rejects.toMatchObject({ code: "DESTINATION_UNSAFE" });

    await expect(lstat(destinationPath)).rejects.toMatchObject({ code: "ENOENT" });
    const [partialPath] = await retainedPartialPaths(root);
    expect(partialPath).toBeDefined();
    const partialStat = await lstat(partialPath!);
    expect(partialStat.mode & 0o777).toBe(0o600);
    expect(partialStat.nlink).toBe(1);
    await expect(
      verifySignedReleaseBundle({
        archivePath: partialPath!,
        trust: trust(receipt, source.publicKeySpkiDer),
      }),
    ).resolves.toMatchObject({ status: "verified-restorable-release-component" });
  });

  it("retains the signed partial when the create-only link loses a race", async () => {
    const source = makeFixture(join(root, "link-race-source.rsi-release"));
    const receipt = await createSignedReleaseBundle(source.options);
    const signedArchive = await readFile(source.options.destinationPath);
    await unlink(source.options.destinationPath);
    const destinationPath = join(root, "link-race.rsi-release");

    await expect(
      publishBundleCreateOnly(destinationPath, signedArchive, {
        beforeLink: () => writeFile(destinationPath, "competing output", { mode: 0o600 }),
      }),
    ).rejects.toMatchObject({ code: "DESTINATION_EXISTS" });

    expect(await readFile(destinationPath, "utf8")).toBe("competing output");
    const [partialPath] = await retainedPartialPaths(root);
    expect(partialPath).toBeDefined();
    const partialStat = await lstat(partialPath!);
    expect(partialStat.mode & 0o777).toBe(0o600);
    expect(partialStat.nlink).toBe(1);
    await expect(
      verifySignedReleaseBundle({
        archivePath: partialPath!,
        trust: trust(receipt, source.publicKeySpkiDer),
      }),
    ).resolves.toMatchObject({ status: "verified-restorable-release-component" });
  });

  it("keeps both signed names when publication fails before destination-link fsync", async () => {
    const source = makeFixture(join(root, "after-link-source.rsi-release"));
    await createSignedReleaseBundle(source.options);
    const signedArchive = await readFile(source.options.destinationPath);
    await unlink(source.options.destinationPath);
    const destinationPath = join(root, "after-link.rsi-release");

    await expect(
      publishBundleCreateOnly(destinationPath, signedArchive, {
        afterLink() {
          throw new Error("synthetic after-link failure");
        },
      }),
    ).rejects.toMatchObject({ code: "DESTINATION_UNSAFE" });

    const destinationStat = await lstat(destinationPath);
    expect(destinationStat.mode & 0o777).toBe(0o600);
    expect(destinationStat.nlink).toBe(2);
    const [partialPath] = await retainedPartialPaths(root);
    expect(partialPath).toBeDefined();
    const partialStat = await lstat(partialPath!);
    expect(partialStat.nlink).toBe(2);
    expect(partialStat.dev).toBe(destinationStat.dev);
    expect(partialStat.ino).toBe(destinationStat.ino);
    expectValidArchiveSignature(await readFile(destinationPath), source.publicKeySpkiDer);
    expectValidArchiveSignature(await readFile(partialPath!), source.publicKeySpkiDer);
  });

  it("cannot report success when the guarded parent is replaced at final cleanup sync", async () => {
    const source = makeFixture(join(root, "cleanup-parent-source.rsi-release"));
    await createSignedReleaseBundle(source.options);
    const signedArchive = await readFile(source.options.destinationPath);
    await unlink(source.options.destinationPath);
    const publicationParent = join(root, "cleanup-parent");
    const displacedParent = join(root, "cleanup-parent-displaced");
    await mkdir(publicationParent, { mode: 0o700 });
    const destinationPath = join(publicationParent, "release.rsi-release");

    await expect(
      publishBundleCreateOnly(destinationPath, signedArchive, {
        async beforeFinalCleanupSync() {
          await rename(publicationParent, displacedParent);
          await mkdir(publicationParent, { mode: 0o700 });
        },
      }),
    ).rejects.toMatchObject({ code: "DESTINATION_UNSAFE" });

    await expect(lstat(destinationPath)).rejects.toMatchObject({ code: "ENOENT" });
    const retainedDestination = join(displacedParent, "release.rsi-release");
    expect(await readFile(retainedDestination)).toEqual(signedArchive);
    expect((await lstat(retainedDestination)).nlink).toBe(1);
    expect(await retainedPartialPaths(displacedParent)).toEqual([]);
  });

  it("allows exactly one concurrent create-only publication", async () => {
    const destinationPath = join(root, "concurrent.rsi-release");
    const fixture = makeFixture(destinationPath);
    let signatureCount = 0;
    const options: CreateSignedReleaseBundleOptions = {
      ...fixture.options,
      signer: {
        ...fixture.signer,
        sign(message) {
          signatureCount += 1;
          return fixture.signer.sign(message);
        },
      },
    };
    const results = await Promise.allSettled([
      createSignedReleaseBundle(options),
      createSignedReleaseBundle(options),
    ]);
    expect(signatureCount).toBe(1);
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
    expect(await retainedPartialPaths(root)).toEqual([]);
  });

  it("fails closed before writing restore contents when root-link durability cannot proceed", async () => {
    const fixture = makeFixture(join(root, "restore-root-sync-source.rsi-release"));
    const receipt = await createSignedReleaseBundle(fixture.options);
    const trusted = trust(receipt, fixture.publicKeySpkiDer);
    const archiveBytes = await readFile(fixture.options.destinationPath);
    const verified = verifyReleaseArchiveBytes(archiveBytes, trusted);
    const destination = join(root, "restore-root-sync-failure");

    await expect(
      restoreVerifiedReleaseArchive(destination, verified, {
        beforeOuterParentSync() {
          throw new Error("synthetic outer-parent sync failure");
        },
      }),
    ).rejects.toMatchObject({ code: "DESTINATION_UNSAFE" });

    const destinationStat = await lstat(destination);
    expect(destinationStat.isDirectory()).toBe(true);
    expect(destinationStat.mode & 0o777).toBe(0o700);
    expect(await readdir(destination)).toEqual([]);
  });

  it("durably restores artifacts before exposing the signed manifest name", async () => {
    const fixture = makeFixture(join(root, "restore-manifest-prelink-source.rsi-release"));
    const receipt = await createSignedReleaseBundle(fixture.options);
    const trusted = trust(receipt, fixture.publicKeySpkiDer);
    const verified = verifyReleaseArchiveBytes(
      await readFile(fixture.options.destinationPath),
      trusted,
    );
    const destination = join(root, "restore-manifest-prelink-failure");

    await expect(
      restoreVerifiedReleaseArchive(destination, verified, {
        beforeManifestLink() {
          throw new Error("synthetic manifest-link failure");
        },
      }),
    ).rejects.toMatchObject({ code: "DESTINATION_UNSAFE" });

    const manifest = join(destination, "release", "signed-release-manifest.v1.json");
    await expect(lstat(manifest)).rejects.toMatchObject({ code: "ENOENT" });
    expect(await readFile(join(destination, "source/package.json"), "utf8")).toContain(
      '"name":"rsi"',
    );
    const partials = await retainedPartialPaths(join(destination, "release"));
    expect(partials).toHaveLength(1);
    expect(await readFile(partials[0]!, "utf8")).toBe(canonicalJson(verified.envelope));
  });

  it("retains both complete manifest names when final-link durability is interrupted", async () => {
    const fixture = makeFixture(join(root, "restore-manifest-postlink-source.rsi-release"));
    const receipt = await createSignedReleaseBundle(fixture.options);
    const trusted = trust(receipt, fixture.publicKeySpkiDer);
    const verified = verifyReleaseArchiveBytes(
      await readFile(fixture.options.destinationPath),
      trusted,
    );
    const destination = join(root, "restore-manifest-postlink-failure");

    await expect(
      restoreVerifiedReleaseArchive(destination, verified, {
        afterManifestLink() {
          throw new Error("synthetic post-manifest-link failure");
        },
      }),
    ).rejects.toMatchObject({ code: "DESTINATION_UNSAFE" });

    const manifest = join(destination, "release", "signed-release-manifest.v1.json");
    const [partial] = await retainedPartialPaths(join(destination, "release"));
    expect(partial).toBeDefined();
    const [manifestStat, partialStat] = await Promise.all([lstat(manifest), lstat(partial!)]);
    expect(manifestStat.nlink).toBe(2);
    expect(partialStat.nlink).toBe(2);
    expect(manifestStat.ino).toBe(partialStat.ino);
    expect(await readFile(manifest, "utf8")).toBe(canonicalJson(verified.envelope));
  });

  it("refuses restore success when an artifact changes while the manifest is finalized", async () => {
    const fixture = makeFixture(join(root, "restore-artifact-race-source.rsi-release"));
    const receipt = await createSignedReleaseBundle(fixture.options);
    const verified = verifyReleaseArchiveBytes(
      await readFile(fixture.options.destinationPath),
      trust(receipt, fixture.publicKeySpkiDer),
    );
    const destination = join(root, "restore-artifact-race");
    const artifactPath = join(destination, "source/package.json");

    await expect(
      restoreVerifiedReleaseArchive(destination, verified, {
        async afterManifestLink() {
          const bytes = await readFile(artifactPath);
          bytes[0] = bytes[0]! ^ 1;
          await writeFile(artifactPath, bytes);
        },
      }),
    ).rejects.toMatchObject({ code: "DESTINATION_UNSAFE" });
  });

  it("refuses restore success when a restored subtree changes during manifest publication", async () => {
    const fixture = makeFixture(join(root, "restore-directory-race-source.rsi-release"));
    const receipt = await createSignedReleaseBundle(fixture.options);
    const verified = verifyReleaseArchiveBytes(
      await readFile(fixture.options.destinationPath),
      trust(receipt, fixture.publicKeySpkiDer),
    );
    const destination = join(root, "restore-directory-race");

    await expect(
      restoreVerifiedReleaseArchive(destination, verified, {
        async afterManifestLink() {
          await chmod(join(destination, "source"), 0o755);
        },
      }),
    ).rejects.toMatchObject({ code: "DESTINATION_UNSAFE" });
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
    expect(await retainedPartialPaths(join(destination, "release"))).toEqual([]);

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

async function retainedPartialPaths(directory: string): Promise<string[]> {
  return (await readdir(directory))
    .filter((name) => name.startsWith(".rsi-release-partial-"))
    .map((name) => join(directory, name));
}

function expectValidArchiveSignature(bytes: Buffer, publicKeySpkiDer: Uint8Array): void {
  const envelope = decodeEnvelopeForTest(bytes);
  expect(
    verifyEd25519(
      null,
      manifestSignatureMessage(envelope.manifest),
      createPublicKey({ format: "der", key: Buffer.from(publicKeySpkiDer), type: "spki" }),
      Buffer.from(envelope.signature, "base64url"),
    ),
  ).toBe(true);
}

function countingSigner(fixture: Fixture, onSign: () => void): ReleaseBundleSignerV1 {
  return {
    ...fixture.signer,
    sign(message) {
      onSign();
      return fixture.signer.sign(message);
    },
  };
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
