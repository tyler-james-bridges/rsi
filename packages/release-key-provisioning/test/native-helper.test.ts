import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFile, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

describe("fixed native Keychain helper", () => {
  const sourcePath = new URL("../native/keychain-helper.swift", import.meta.url).pathname;

  it.skipIf(process.platform !== "darwin")(
    "typechecks without accessing Keychain or reading secret input",
    () => {
      const result = spawnSync("/usr/bin/xcrun", ["swiftc", "-typecheck", sourcePath], {
        encoding: "utf8",
        env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
        maxBuffer: 64 * 1024,
        shell: false,
        timeout: 30_000,
      });
      expect({ signal: result.signal, status: result.status, stderr: result.stderr }).toEqual({
        signal: null,
        status: 0,
        stderr: "",
      });
    },
  );

  it.skipIf(process.platform !== "darwin")(
    "builds a deterministic attested executable without touching Keychain",
    async () => {
      const directories: string[] = [];
      try {
        const hashes: string[] = [];
        for (const _copy of [1, 2] as const) {
          const directory = await mkdtemp(join(tmpdir(), "rsi-helper-test-"));
          directories.push(directory);
          const snapshot = join(directory, "keychain-helper.swift");
          const output = join(directory, "rsi-release-key-helper");
          await copyFile(sourcePath, snapshot);
          const compile = spawnSync(
            "/usr/bin/xcrun",
            [
              "swiftc",
              "-O",
              "-module-name",
              "RSIReleaseKeyHelper",
              "-file-prefix-map",
              `${directory}=/rsi/foundation-helper-build`,
              "-Xlinker",
              "-no_uuid",
              snapshot,
              "-o",
              output,
            ],
            {
              encoding: "utf8",
              env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
              maxBuffer: 128 * 1024,
              shell: false,
              timeout: 60_000,
            },
          );
          expect({ signal: compile.signal, status: compile.status }).toEqual({
            signal: null,
            status: 0,
          });
          const signed = spawnSync(
            "/usr/bin/codesign",
            ["--force", "--sign", "-", "--timestamp=none", output],
            {
              encoding: "utf8",
              env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
              maxBuffer: 64 * 1024,
              shell: false,
              timeout: 30_000,
            },
          );
          expect({ signal: signed.signal, status: signed.status }).toEqual({
            signal: null,
            status: 0,
          });
          hashes.push(
            createHash("sha256")
              .update(await readFile(output))
              .digest("hex"),
          );
        }
        expect(hashes[0]).toBe(hashes[1]);
      } finally {
        await Promise.all(
          directories.map((directory) => rm(directory, { force: true, recursive: true })),
        );
      }
    },
    120_000,
  );

  it("keeps secret bytes inside the fixed-domain helper and unwinds before process exit", async () => {
    const source = await readFile(sourcePath, "utf8");
    expect(source.match(/Foundation\.exit\(/gu)).toHaveLength(1);
    expect(source).toContain("kSecAttrSynchronizableAny");
    expect(source).toContain("kSecMatchLimitAll");
    expect(source).toContain('case "sign-release"');
    expect(source).toContain('case "sign-tag"');
    expect(source).not.toContain("find-generic-password");
    expect(source).not.toContain("print(keyData");
  });
});
