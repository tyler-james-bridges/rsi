import {
  chmod,
  link,
  mkdtemp,
  readFile,
  realpath,
  rename,
  rm,
  stat,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import { canonicalJson } from "../src/canonical.js";
import {
  hasActiveNonLoopbackInterface,
  readFoundationCiEvidenceFile,
  reserveFoundationTagObject,
  validateFoundationConclusionDestination,
  validateFoundationDestination,
  validateFoundationReceiptDestination,
  validateFoundationReportDestination,
  validateFoundationTagObjectDestination,
  writeFoundationEvidence,
} from "../src/host.js";
import { makeCiEvidence } from "./helpers.js";

const repositoryRoot = fileURLToPath(new URL("../../../", import.meta.url));
const cleanup: string[] = [];

afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((path) => rm(path, { force: true, recursive: true })));
});

describe("ceremony offline evidence", () => {
  it("fails closed for active IPv4, IPv6, and status-only non-loopback interfaces", () => {
    expect(
      hasActiveNonLoopbackInterface(
        "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST>\n\tstatus: active\n",
      ),
    ).toBe(true);
    expect(
      hasActiveNonLoopbackInterface(
        "en0: flags=8863<UP,BROADCAST>\n\tinet 192.0.2.10 netmask 0xffffff00\n\tstatus: inactive\n",
      ),
    ).toBe(true);
    expect(
      hasActiveNonLoopbackInterface(
        "en0: flags=8863<UP,BROADCAST>\n\tinet6 fe80::1234%en0 prefixlen 64\n\tstatus: inactive\n",
      ),
    ).toBe(true);
  });

  it("allows only loopback or address-free inactive interfaces and rejects missing evidence", () => {
    expect(
      hasActiveNonLoopbackInterface(
        [
          "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST>",
          "\tinet 127.0.0.1 netmask 0xff000000",
          "\tinet6 ::1 prefixlen 128",
          "en0: flags=8822<BROADCAST,SMART,SIMPLEX,MULTICAST>",
          "\tstatus: inactive",
          "",
        ].join("\n"),
      ),
    ).toBe(false);
    expect(hasActiveNonLoopbackInterface("")).toBe(true);
  });
});

describe("retained foundation CI evidence", () => {
  it("accepts only canonical owner-only evidence outside the repository", async () => {
    const directory = await ownerOnlyTemporaryDirectory("rsi-ci-evidence-");
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

    await writeFile(path, canonicalJson(evidence), { mode: 0o600 });
    const hardlink = join(directory, "foundation-ci-hardlink.json");
    await link(path, hardlink);
    await expect(readFoundationCiEvidenceFile(path, repositoryRoot)).rejects.toMatchObject({
      code: "INPUT_INVALID",
    });
    await unlink(hardlink);
  });

  it("rejects same-size mutation and path replacement during evidence reads", async () => {
    const directory = await ownerOnlyTemporaryDirectory("rsi-ci-evidence-race-");
    const path = join(directory, "foundation-ci.json");
    const evidence = makeCiEvidence();
    const changed = makeCiEvidence({
      runId: "32034831277",
      runUrl: "https://github.com/tyler-james-bridges/rsi/actions/runs/32034831277",
    });
    expect(canonicalJson(changed)).toHaveLength(canonicalJson(evidence).length);
    await writeFile(path, canonicalJson(evidence), { mode: 0o600 });

    await expect(
      readFoundationCiEvidenceFile(path, repositoryRoot, {
        afterOpen: () => writeFile(path, canonicalJson(changed), { mode: 0o600 }),
      }),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });

    await writeFile(path, canonicalJson(evidence), { mode: 0o600 });
    const replacement = join(directory, "replacement.json");
    const displaced = join(directory, "displaced.json");
    await writeFile(replacement, canonicalJson(evidence), { mode: 0o600 });
    await expect(
      readFoundationCiEvidenceFile(path, repositoryRoot, {
        afterOpen: async () => {
          await rename(path, displaced);
          await rename(replacement, path);
        },
      }),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });
  });
});

describe("create-only ceremony destinations", () => {
  it("validates every v2 output suffix outside the repository", async () => {
    const directory = await ownerOnlyTemporaryDirectory("rsi-ceremony-destinations-");
    const cases = [
      [validateFoundationDestination, join(directory, "release.rsi-release")],
      [validateFoundationReceiptDestination, join(directory, "release.receipt.json")],
      [
        validateFoundationConclusionDestination,
        join(directory, "release.readiness-conclusion.json"),
      ],
      [validateFoundationTagObjectDestination, join(directory, "release.foundation-tag")],
      [validateFoundationReportDestination, join(directory, "release.ceremony-report.json")],
    ] as const;

    for (const [validate, path] of cases) {
      await expect(validate(path, repositoryRoot)).resolves.toBe(path);
    }
  });

  it("never overwrites an existing retained evidence file", async () => {
    const directory = await ownerOnlyTemporaryDirectory("rsi-create-only-");
    const path = join(directory, "release.foundation-tag");
    await writeFile(path, "preexisting", { mode: 0o600 });

    await expect(
      writeFoundationEvidence(
        path,
        repositoryRoot,
        ".foundation-tag",
        new TextEncoder().encode("replacement"),
      ),
    ).rejects.toBeInstanceOf(Error);
    expect(await readFile(path, "utf8")).toBe("preexisting");
  });

  it("durably reserves the tag path and preserves it when custody never begins", async () => {
    const directory = await ownerOnlyTemporaryDirectory("rsi-tag-reservation-");
    const path = join(directory, "release.foundation-tag");
    const reservation = await reserveFoundationTagObject(path, repositoryRoot);

    expect((await stat(path)).mode & 0o777).toBe(0o600);
    expect((await stat(path)).size).toBe(0);
    await reservation.preserve();
    expect((await stat(path)).size).toBe(0);
    await expect(reserveFoundationTagObject(path, repositoryRoot)).rejects.toMatchObject({
      code: "OUTPUT_FAILED",
    });
  });

  it("never deletes fully written tag bytes after an ambiguous publication failure", async () => {
    const directory = await ownerOnlyTemporaryDirectory("rsi-tag-partial-");
    const path = join(directory, "release.foundation-tag");
    const bytes = new TextEncoder().encode("signed-detached-tag-evidence");
    const reservation = await reserveFoundationTagObject(path, repositoryRoot, {
      afterWrite: () => {
        throw new Error("simulated post-write failure");
      },
    });

    await expect(reservation.publish(bytes)).rejects.toMatchObject({ code: "OUTPUT_FAILED" });
    expect(await readFile(path, "utf8")).toBe("signed-detached-tag-evidence");
    expect((await stat(path)).mode & 0o777).toBe(0o600);
  });

  it("keeps private-key export paths out of the Node ceremony host", async () => {
    const source = await readFile(
      fileURLToPath(new URL("../src/host.ts", import.meta.url)),
      "utf8",
    );
    expect(source).not.toContain("find-generic-password");
    expect(source).not.toContain("createPrivateKey");
    expect(source).not.toContain('"-w"');
    expect(source).not.toContain("pkcs8");
  });
});

async function ownerOnlyTemporaryDirectory(prefix: string): Promise<string> {
  const directory = await realpath(await mkdtemp(join(tmpdir(), prefix)));
  cleanup.push(directory);
  await chmod(directory, 0o700);
  return directory;
}
