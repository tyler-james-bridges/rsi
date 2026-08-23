import { createHash, generateKeyPairSync, sign as signEd25519, type KeyObject } from "node:crypto";
import { chmod, mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

import { afterEach, describe, expect, it } from "vitest";

import {
  createFoundationAuthenticatedIndependentReview,
  foundationAuthenticatedIndependentReviewSha256,
  type FoundationAuthenticatedIndependentReviewV1,
} from "../src/authenticated-review.js";
import { canonicalJson } from "../src/canonical.js";
import { readFoundationIndependentReviewEvidenceFile } from "../src/host.js";
import type { FoundationIndependentReviewerIdentityV1 } from "../src/reviewer-identity.js";
import { makeReviewEvidence } from "./helpers.js";

interface ReviewerFixture {
  readonly identity: FoundationIndependentReviewerIdentityV1;
  readonly privateKey: KeyObject;
  readonly publicKeySpkiDer: Buffer;
}

interface RepositoryFixture {
  readonly envelope: FoundationAuthenticatedIndependentReviewV1;
  readonly evidencePath: string;
  readonly parentCommit: string;
  readonly repositoryRoot: string;
  readonly reviewer: ReviewerFixture;
  readonly root: string;
  readonly targetCommit: string;
}

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
});

describe("foundation authenticated-review Git trust lineage", () => {
  it("accepts an ephemeral reviewer key pinned unchanged before the reviewed commit", async () => {
    const fixture = await createRepositoryFixture();

    await expect(
      readFoundationIndependentReviewEvidenceFile(
        fixture.evidencePath,
        fixture.repositoryRoot,
        fixture.targetCommit,
      ),
    ).resolves.toEqual({
      evidence: fixture.envelope.evidence,
      sha256: foundationAuthenticatedIndependentReviewSha256(fixture.envelope),
    });
  });

  it("refuses a reviewer identity first pinned by the reviewed commit", async () => {
    const fixture = await createRepositoryFixture({ pinMode: "same-commit" });

    await expect(readFixture(fixture)).rejects.toThrow(/identity trust file|strict-ancestor/u);
  });

  it("refuses a reviewer identity changed by the reviewed commit", async () => {
    const fixture = await createRepositoryFixture({ pinMode: "changed" });

    await expect(readFixture(fixture)).rejects.toThrow(/added or changed/u);
  });

  it("refuses reuse of the reviewer key by the release signer or reviewer ID by the operator", async () => {
    const selfSigner = await createRepositoryFixture({ selfReleaseSigner: true });
    await expect(readFixture(selfSigner)).rejects.toThrow(/not independent/u);

    const sameOperator = await createRepositoryFixture({ sameOperator: true });
    await expect(readFixture(sameOperator)).rejects.toThrow(/not independent/u);
  });

  it("refuses wrong-key, wrong-signature, and changed-body envelopes", async () => {
    const fixture = await createRepositoryFixture();
    const other = makeReviewer(fixture.reviewer.identity.reviewerId);
    const wrongKeyEnvelope = await signEnvelope(
      other,
      fixture.targetCommit,
      git(fixture.repositoryRoot, ["rev-parse", `${fixture.targetCommit}^{tree}`]).trim(),
    );
    await writeEnvelope(fixture.evidencePath, wrongKeyEnvelope);
    await expect(readFixture(fixture)).rejects.toThrow(/does not bind/u);

    const badSignature = Buffer.from(fixture.envelope.signatureBase64url, "base64url");
    badSignature[0] = badSignature[0]! ^ 1;
    await writeEnvelope(fixture.evidencePath, {
      ...fixture.envelope,
      signatureBase64url: badSignature.toString("base64url"),
    });
    await expect(readFixture(fixture)).rejects.toThrow(/signature did not verify/u);

    await writeEnvelope(fixture.evidencePath, {
      ...fixture.envelope,
      evidence: {
        ...fixture.envelope.evidence,
        reviewedAt: "2026-08-18T00:30:01.000Z",
      },
    });
    await expect(readFixture(fixture)).rejects.toThrow(/signature did not verify/u);
  });

  it("refuses noncanonical and extra-field external envelopes", async () => {
    const fixture = await createRepositoryFixture();
    await writeFile(
      fixture.evidencePath,
      Buffer.from(`${canonicalJson(fixture.envelope)}\n`, "utf8"),
      { mode: 0o600 },
    );
    await expect(readFixture(fixture)).rejects.toThrow(/not canonical/u);

    await writeFile(
      fixture.evidencePath,
      Buffer.from(canonicalJson({ ...fixture.envelope, unsupported: true }), "utf8"),
      { mode: 0o600 },
    );
    await expect(readFixture(fixture)).rejects.toThrow(/unsupported fields/u);
  });

  it("requires an owner-only external file with the dedicated suffix", async () => {
    const fixture = await createRepositoryFixture();
    await chmod(fixture.evidencePath, 0o644);
    await expect(readFixture(fixture)).rejects.toMatchObject({ code: "INPUT_INVALID" });

    await chmod(fixture.evidencePath, 0o600);
    const wrongSuffix = join(fixture.root, "foundation.review.json");
    await writeFile(wrongSuffix, Buffer.from(canonicalJson(fixture.envelope), "utf8"), {
      mode: 0o600,
    });
    await expect(
      readFoundationIndependentReviewEvidenceFile(
        wrongSuffix,
        fixture.repositoryRoot,
        fixture.targetCommit,
      ),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });
  });

  it("refuses replace refs, grafts, and shallow history", async () => {
    const replaced = await createRepositoryFixture();
    git(replaced.repositoryRoot, ["replace", replaced.targetCommit, replaced.parentCommit]);
    await expect(readFixture(replaced)).rejects.toThrow(/history is ambiguous/u);

    const grafted = await createRepositoryFixture();
    await mkdir(join(grafted.repositoryRoot, ".git", "info"), { recursive: true });
    await writeFile(
      join(grafted.repositoryRoot, ".git", "info", "grafts"),
      `${grafted.targetCommit} ${grafted.parentCommit}\n`,
    );
    await expect(readFixture(grafted)).rejects.toThrow(/history is ambiguous/u);

    const source = await createRepositoryFixture();
    const shallowRoot = await ownerOnlyTempRoot();
    const shallowRepository = join(shallowRoot, "shallow");
    git(shallowRoot, ["clone", "--depth=1", `file://${source.repositoryRoot}`, shallowRepository]);
    await expect(
      readFoundationIndependentReviewEvidenceFile(
        source.evidencePath,
        shallowRepository,
        source.targetCommit,
      ),
    ).rejects.toThrow(/history is ambiguous/u);
  });
});

async function createRepositoryFixture(
  options: {
    readonly pinMode?: "ancestor" | "changed" | "same-commit";
    readonly sameOperator?: boolean;
    readonly selfReleaseSigner?: boolean;
  } = {},
): Promise<RepositoryFixture> {
  const root = await ownerOnlyTempRoot();
  const repositoryRoot = join(root, "repo");
  await mkdir(repositoryRoot, { mode: 0o700 });
  git(repositoryRoot, ["init", "-b", "main"]);
  git(repositoryRoot, ["config", "user.name", "RSI Test"]);
  git(repositoryRoot, ["config", "user.email", "rsi-test@example.invalid"]);

  const reviewer = makeReviewer();
  const ancestorReviewer = options.pinMode === "changed" ? makeReviewer() : reviewer;
  await mkdir(join(repositoryRoot, "config"), { recursive: true });
  if (options.pinMode !== "same-commit") {
    await writeCanonical(
      join(repositoryRoot, "config", "foundation-independent-reviewer-identity.v1.json"),
      ancestorReviewer.identity,
    );
  }
  if (options.selfReleaseSigner === true) {
    await writeCanonical(join(repositoryRoot, "config", "foundation-release-identity.v1.json"), {
      keyId: `rsi-release-${reviewer.identity.reviewerFingerprintSha256.slice(0, 16)}`,
      publicKeySpkiDerBase64url: reviewer.identity.publicKeySpkiDerBase64url,
      signerFingerprintSha256: reviewer.identity.reviewerFingerprintSha256,
    });
  }
  if (options.sameOperator === true) {
    await writeCanonical(
      join(repositoryRoot, "config", "foundation-release-key-helper-compatibility.v1.json"),
      { drillOperatorId: reviewer.identity.reviewerId },
    );
  }
  await writeFile(join(repositoryRoot, "baseline.txt"), "review trust baseline\n", "utf8");
  git(repositoryRoot, ["add", "."]);
  git(repositoryRoot, ["commit", "-m", "pin reviewer trust before review target"]);
  const parentCommit = git(repositoryRoot, ["rev-parse", "HEAD"]).trim();

  if (options.pinMode === "same-commit" || options.pinMode === "changed") {
    await writeCanonical(
      join(repositoryRoot, "config", "foundation-independent-reviewer-identity.v1.json"),
      reviewer.identity,
    );
  }
  await writeFile(join(repositoryRoot, "target.txt"), "reviewed target\n", "utf8");
  git(repositoryRoot, ["add", "."]);
  git(repositoryRoot, ["commit", "-m", "reviewed target"]);
  const targetCommit = git(repositoryRoot, ["rev-parse", "HEAD"]).trim();
  const gitTreeSha = git(repositoryRoot, ["rev-parse", `${targetCommit}^{tree}`]).trim();
  const envelope = await signEnvelope(reviewer, targetCommit, gitTreeSha);
  const evidencePath = join(root, "foundation.review-evidence.json");
  await writeEnvelope(evidencePath, envelope);
  return { envelope, evidencePath, parentCommit, repositoryRoot, reviewer, root, targetCommit };
}

function makeReviewer(reviewerId = "rsi-independent-review-agent"): ReviewerFixture {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeySpkiDer = publicKey.export({ format: "der", type: "spki" });
  const reviewerFingerprintSha256 = createHash("sha256").update(publicKeySpkiDer).digest("hex");
  return {
    identity: {
      algorithm: "Ed25519",
      identityType: "rsi.foundation-independent-reviewer-identity",
      keyId: `rsi-reviewer-${reviewerFingerprintSha256.slice(0, 16)}`,
      publicKeySpkiDerBase64url: publicKeySpkiDer.toString("base64url"),
      reviewerFingerprintSha256,
      reviewerId,
      reviewerRole: "independent-non-authoring-agent",
      version: 1,
    },
    privateKey,
    publicKeySpkiDer,
  };
}

async function signEnvelope(
  reviewer: ReviewerFixture,
  commitSha: string,
  gitTreeSha: string,
): Promise<FoundationAuthenticatedIndependentReviewV1> {
  return createFoundationAuthenticatedIndependentReview(
    makeReviewEvidence({ commitSha, gitTreeSha, reviewerId: reviewer.identity.reviewerId }),
    reviewer.identity,
    {
      keyId: reviewer.identity.keyId,
      publicKeySpkiDer: reviewer.publicKeySpkiDer,
      sign: (message) => Uint8Array.from(signEd25519(null, message, reviewer.privateKey)),
    },
  );
}

async function writeEnvelope(
  path: string,
  envelope: FoundationAuthenticatedIndependentReviewV1,
): Promise<void> {
  await writeFile(path, Buffer.from(canonicalJson(envelope), "utf8"), { mode: 0o600 });
  await chmod(path, 0o600);
}

async function writeCanonical(path: string, value: unknown): Promise<void> {
  await writeFile(path, Buffer.from(canonicalJson(value), "utf8"), { mode: 0o644 });
}

async function ownerOnlyTempRoot(): Promise<string> {
  const root = await realpath(await mkdtemp(join(tmpdir(), "rsi-review-trust-")));
  roots.push(root);
  await chmod(root, 0o700);
  return root;
}

function readFixture(fixture: RepositoryFixture) {
  return readFoundationIndependentReviewEvidenceFile(
    fixture.evidencePath,
    fixture.repositoryRoot,
    fixture.targetCommit,
  );
}

function git(cwd: string, args: readonly string[]): string {
  const result = spawnSync("/usr/bin/git", args, {
    cwd,
    encoding: "utf8",
    env: {
      ...process.env,
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_NO_REPLACE_OBJECTS: "1",
      GIT_OPTIONAL_LOCKS: "0",
    },
    shell: false,
    timeout: 20_000,
  });
  if (result.status !== 0 || result.signal !== null) {
    throw new Error(`git failed: ${args.join(" ")}: ${result.stderr}`);
  }
  return result.stdout;
}
