import { execFileSync } from "node:child_process";
import { generateKeyPairSync, sign as signEd25519, createHash, type KeyObject } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  createFoundationSignedTagArtifact,
  encodeFoundationOpenSshPublicKey,
  verifyFoundationSignedTagArtifact,
  type CreateFoundationSignedTagOptionsV1,
  type FoundationSignedTagArtifactV1,
  type VerifyFoundationSignedTagOptionsV1,
} from "../src/foundation-tag.js";

const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);
const HASH_C = "c".repeat(64);
const HASH_D = "d".repeat(64);
const TARGET = "d3f1e81183cc13fe51ea85ad21bcc71d31866dee";
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((path) => rm(path, { force: true, recursive: true })),
  );
});

describe("foundation signed-tag artifact", () => {
  it("creates deterministic, strictly verified bytes with exactly one signature callback", async () => {
    const keys = generateKeyPairSync("ed25519");
    let calls = 0;
    const options = createOptions(keys.privateKey, keys.publicKey, () => {
      calls += 1;
    });

    const first = await createFoundationSignedTagArtifact(options);
    expect(calls).toBe(1);
    const second = await createFoundationSignedTagArtifact(options);
    expect(calls).toBe(2);
    expect(first.tagObjectBytes).toEqual(second.tagObjectBytes);
    expect(first.verification).toEqual(second.verification);
    expect(first.verification).toMatchObject({
      archiveSha256: HASH_A,
      ciEvidenceSha256: HASH_B,
      manifestSha256: HASH_C,
      readinessConclusionSha256: HASH_D,
      objectiveEvidenceState: "FOUNDATION_BUILT",
      releaseVersion: "0.1.0-foundation.1",
      signatureAlgorithm: "ssh-ed25519",
      signatureHash: "sha512",
      signatureNamespace: "git",
      tagName: "foundation-v1",
      targetCommit: TARGET,
    });
    expect(first.verification.gitObjectSha1).toMatch(/^[0-9a-f]{40}$/u);
    expect(first.verification.gitObjectSha256).toMatch(/^[0-9a-f]{64}$/u);
    expect(first.verification.tagObjectSha256).toMatch(/^[0-9a-f]{64}$/u);
    expect(first.verification.gitObjectSha1).toBe(
      expectedGitObjectHash("sha1", first.tagObjectBytes),
    );
    expect(first.verification.gitObjectSha256).toBe(
      expectedGitObjectHash("sha256", first.tagObjectBytes),
    );
    expect(first.verification.tagObjectSha256).toBe(
      createHash("sha256").update(first.tagObjectBytes).digest("hex"),
    );
    expect(Buffer.from(first.tagObjectBytes).toString("utf8")).toContain(
      "objective-evidence-state: FOUNDATION_BUILT\n",
    );
    expect(Buffer.from(first.tagObjectBytes).toString("utf8")).toContain(
      `readiness-conclusion-sha256: ${HASH_D}\n`,
    );

    const report = verifyFoundationSignedTagArtifact(
      first.tagObjectBytes,
      verificationOptions(keys.publicKey),
    );
    expect(report).toEqual(first.verification);
  });

  it("fails closed for tamper, a wrong target, an unknown field, and a different public key", async () => {
    const keys = generateKeyPairSync("ed25519");
    const otherKeys = generateKeyPairSync("ed25519");
    const artifact = await createFoundationSignedTagArtifact(
      createOptions(keys.privateKey, keys.publicKey),
    );
    const expected = verificationOptions(keys.publicKey);

    const tampered = replaceBytes(
      artifact,
      `archive-sha256: ${HASH_A}`,
      `archive-sha256: ${"d".repeat(64)}`,
    );
    expect(() => verifyFoundationSignedTagArtifact(tampered, expected)).toThrow();
    expect(() =>
      verifyFoundationSignedTagArtifact(tampered, {
        ...expected,
        archiveSha256: "d".repeat(64),
      }),
    ).toThrow(/SSH signature is invalid/u);
    expect(() =>
      verifyFoundationSignedTagArtifact(artifact.tagObjectBytes, {
        ...expected,
        targetCommit: "1".repeat(40),
      }),
    ).toThrow(/target commit binding/u);
    const unknownField = replaceBytes(
      artifact,
      "manifest-sha256: ",
      "unknown-field: rejected\nmanifest-sha256: ",
    );
    expect(() => verifyFoundationSignedTagArtifact(unknownField, expected)).toThrow(
      /payload structure/u,
    );
    expect(() =>
      verifyFoundationSignedTagArtifact(artifact.tagObjectBytes, {
        ...expected,
        publicKeySpkiDer: exportSpki(otherKeys.publicKey),
      }),
    ).toThrow(/trusted key/u);
  });

  it("does not retry an invalid signer and rejects unknown option fields", async () => {
    const keys = generateKeyPairSync("ed25519");
    let calls = 0;
    const invalid = createOptions(keys.privateKey, keys.publicKey, () => {
      calls += 1;
    });
    const invalidSigner = {
      ...invalid,
      signer: {
        ...invalid.signer,
        sign: (): Uint8Array => {
          calls += 1;
          return new Uint8Array(64);
        },
      },
    };
    await expect(createFoundationSignedTagArtifact(invalidSigner)).rejects.toThrow(
      /invalid signature/u,
    );
    expect(calls).toBe(1);

    await expect(
      createFoundationSignedTagArtifact({
        ...invalid,
        surprise: true,
      } as CreateFoundationSignedTagOptionsV1),
    ).rejects.toThrow(/unsupported fields/u);
  });

  it("is accepted by native git verify-tag with an isolated allowed-signers file", async () => {
    const root = await mkdtemp(join(tmpdir(), "rsi-foundation-tag-"));
    temporaryDirectories.push(root);
    const repository = join(root, "repository");
    git(root, ["init", "-q", repository]);
    git(repository, ["config", "user.name", "RSI Test"]);
    git(repository, ["config", "user.email", "release@rsi.local"]);
    await writeFile(join(repository, "README"), "isolated native verification fixture\n", {
      encoding: "utf8",
      mode: 0o600,
    });
    git(repository, ["add", "README"]);
    git(repository, ["commit", "-q", "-m", "fixture"]);
    const targetCommit = git(repository, ["rev-parse", "HEAD"]).trim();
    const keys = generateKeyPairSync("ed25519");
    const artifact = await createFoundationSignedTagArtifact(
      createOptions(keys.privateKey, keys.publicKey, undefined, targetCommit),
    );
    const objectId = git(
      repository,
      ["hash-object", "-t", "tag", "-w", "--stdin"],
      artifact.tagObjectBytes,
    ).trim();
    expect(objectId).toBe(artifact.verification.gitObjectSha1);
    git(repository, ["update-ref", "refs/tags/foundation-v1", objectId]);

    const allowedSignersPath = join(root, "allowed_signers");
    await writeFile(
      allowedSignersPath,
      `release@rsi.local ${encodeFoundationOpenSshPublicKey(exportSpki(keys.publicKey))}\n`,
      { encoding: "utf8", mode: 0o600 },
    );
    git(repository, ["config", "gpg.format", "ssh"]);
    git(repository, ["config", "gpg.ssh.allowedSignersFile", allowedSignersPath]);
    expect(() => git(repository, ["verify-tag", "foundation-v1"])).not.toThrow();
    expect(git(repository, ["rev-parse", "foundation-v1^{commit}"]).trim()).toBe(targetCommit);
  });
});

function createOptions(
  privateKey: KeyObject,
  publicKey: KeyObject,
  onSign?: () => void,
  targetCommit = TARGET,
): CreateFoundationSignedTagOptionsV1 {
  const spki = exportSpki(publicKey);
  const fingerprint = createHash("sha256").update(spki).digest("hex");
  return {
    archiveSha256: HASH_A,
    ciEvidenceSha256: HASH_B,
    manifestSha256: HASH_C,
    readinessConclusionSha256: HASH_D,
    signer: {
      keyId: `rsi-release-${fingerprint.slice(0, 16)}`,
      publicKeySpkiDer: spki,
      sign: (message): Uint8Array => {
        onSign?.();
        return Uint8Array.from(signEd25519(null, message, privateKey));
      },
    },
    targetCommit,
  };
}

function verificationOptions(
  publicKey: KeyObject,
  targetCommit = TARGET,
): VerifyFoundationSignedTagOptionsV1 {
  const spki = exportSpki(publicKey);
  const fingerprint = createHash("sha256").update(spki).digest("hex");
  return {
    archiveSha256: HASH_A,
    ciEvidenceSha256: HASH_B,
    manifestSha256: HASH_C,
    readinessConclusionSha256: HASH_D,
    publicKeySpkiDer: spki,
    signerFingerprintSha256: fingerprint,
    signerKeyId: `rsi-release-${fingerprint.slice(0, 16)}`,
    targetCommit,
  };
}

function exportSpki(publicKey: KeyObject): Buffer {
  return publicKey.export({ format: "der", type: "spki" });
}

function replaceBytes(
  artifact: FoundationSignedTagArtifactV1,
  search: string,
  replacement: string,
): Uint8Array {
  const text = Buffer.from(artifact.tagObjectBytes).toString("utf8");
  expect(text).toContain(search);
  return Buffer.from(text.replace(search, replacement), "utf8");
}

function git(directory: string, args: readonly string[], input?: Uint8Array): string {
  return execFileSync("git", args, {
    cwd: directory,
    encoding: "utf8",
    env: {
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      LANG: "C",
      LC_ALL: "C",
      PATH: process.env.PATH,
      XDG_CONFIG_HOME: directory,
    },
    input,
    maxBuffer: 1024 * 1024,
    stdio: ["pipe", "pipe", "pipe"],
  });
}

function expectedGitObjectHash(algorithm: "sha1" | "sha256", bytes: Uint8Array): string {
  return createHash(algorithm)
    .update(`tag ${bytes.byteLength}\0`, "ascii")
    .update(bytes)
    .digest("hex");
}
