import { generateKeyPairSync } from "node:crypto";
import { chmod, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import type { ReleaseBundleSignerV1 } from "@rsi/release-bundle";
import { afterEach, describe, expect, it } from "vitest";

import { canonicalJson } from "../src/canonical.js";
import { createKeychainCustody, readFoundationCiEvidenceFile } from "../src/host.js";
import { makeCiEvidence } from "./helpers.js";

const repositoryRoot = fileURLToPath(new URL("../../../", import.meta.url));
const cleanup: string[] = [];

afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((path) => rm(path, { force: true, recursive: true })));
});

describe("MacBook release-key custody", () => {
  it("permits exactly one in-scope signature and disables escaped capabilities", async () => {
    const { privateKey } = generateKeyPairSync("ed25519");
    const material = Buffer.from(privateKey.export({ format: "der", type: "pkcs8" }));
    let escaped: ReleaseBundleSignerV1 | undefined;
    const custody = createKeychainCustody(() => material);

    await custody.withSigner(async (signer) => {
      escaped = signer;
      expect(signer.sign(new Uint8Array([1, 2, 3]))).toHaveLength(64);
      expect(() => signer.sign(new Uint8Array([4, 5, 6]))).toThrowError(
        expect.objectContaining({ code: "CUSTODY_FAILED" }),
      );
    });

    expect(material.every((byte) => byte === 0)).toBe(true);
    expect(escaped).toBeDefined();
    expect(() => escaped!.sign(new Uint8Array([7, 8, 9]))).toThrowError(
      expect.objectContaining({ code: "CUSTODY_FAILED" }),
    );
    expect(escaped!.publicKeySpkiDer.every((byte) => byte === 0)).toBe(true);
  });
});

describe("retained foundation CI evidence", () => {
  it("accepts only canonical owner-only evidence outside the repository", async () => {
    const directory = await realpath(await mkdtemp(join(tmpdir(), "rsi-ci-evidence-")));
    cleanup.push(directory);
    await chmod(directory, 0o700);
    const path = join(directory, "foundation-ci.json");
    const evidence = makeCiEvidence();
    await writeFile(path, canonicalJson(evidence), { mode: 0o600 });

    await expect(readFoundationCiEvidenceFile(path, repositoryRoot)).resolves.toMatchObject({
      evidence,
      sha256: expect.stringMatching(/^[0-9a-f]{64}$/u),
    });

    await chmod(path, 0o644);
    await expect(readFoundationCiEvidenceFile(path, repositoryRoot)).rejects.toMatchObject({
      code: "INPUT_INVALID",
    });
    await chmod(path, 0o600);
    await writeFile(path, `${canonicalJson(evidence)}\n`, { mode: 0o600 });
    await expect(readFoundationCiEvidenceFile(path, repositoryRoot)).rejects.toMatchObject({
      code: "CI_EVIDENCE_INVALID",
    });
  });
});
