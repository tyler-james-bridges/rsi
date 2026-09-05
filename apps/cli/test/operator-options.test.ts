import { chmod, lstat, mkdir, mkdtemp, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  assertStage0StorageIsolation,
  operatorUsage,
  parseOperatorOptions,
  resolveProspectiveStoragePath,
} from "../src/operator-options.js";

let directory: string | undefined;

afterEach(async () => {
  if (directory !== undefined) await rm(directory, { force: true, recursive: true });
  directory = undefined;
});

describe("operator command options", () => {
  it("accepts pnpm separators and explicit safe options", () => {
    expect(
      parseOperatorOptions([
        "--",
        "--db",
        ":memory:",
        "--research-db",
        "research.sqlite",
        "--",
        "--port",
        "0",
      ]),
    ).toEqual({ databasePath: ":memory:", port: 0, researchDatabasePath: "research.sqlite" });
  });

  it("uses loopback-service defaults", () => {
    expect(parseOperatorOptions([])).toEqual({
      databasePath: ".local/stage0/rsi-runtime.sqlite",
      port: 8_787,
      researchDatabasePath: ".local/stage0/rsi-research.sqlite",
    });
  });

  it("returns help without starting a service", () => {
    expect(parseOperatorOptions(["--help"])).toBeNull();
    expect(operatorUsage()).toContain("signer-blind Stage 0 runtime");
    expect(operatorUsage()).toContain("begins in STOPPED");
  });

  it("allows only the dedicated Stage 0 subtree inside the production data directory", () => {
    const production = "/private/rsi/production";
    expect(() =>
      assertStage0StorageIsolation(
        `${production}/rsi-runtime.sqlite`,
        "/private/rsi/stage0/research.sqlite",
        production,
      ),
    ).toThrow("cannot open Stage 1 production storage");
    expect(() =>
      assertStage0StorageIsolation(
        "/private/rsi/stage0/runtime.sqlite",
        `${production}/alternate.sqlite`,
        production,
      ),
    ).toThrow("cannot open Stage 1 production storage");
    expect(() =>
      assertStage0StorageIsolation(
        `${production}/vault/nested/runtime.sqlite`,
        "/private/rsi/stage0/research.sqlite",
        production,
      ),
    ).toThrow("cannot open Stage 1 production storage");
    expect(() =>
      assertStage0StorageIsolation(
        `${production}/stage0/runtime.sqlite`,
        `${production}/stage0/nested/research.sqlite`,
        production,
      ),
    ).not.toThrow();
    expect(() =>
      assertStage0StorageIsolation(
        "/private/rsi/stage0/runtime.sqlite",
        "/private/rsi/stage0/research.sqlite",
        production,
      ),
    ).not.toThrow();
  });

  it("resolves a symlinked existing ancestor without creating a nested Stage 1 path", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-stage0-prospective-"));
    await chmod(directory, 0o700);
    const production = join(directory, "production");
    const vault = join(production, "rsi-x-canary-vault");
    const alias = join(directory, "outside-alias");
    const requestedParent = join(alias, "unexpected");
    await mkdir(vault, { mode: 0o700, recursive: true });
    await symlink(vault, alias);

    const candidate = await resolveProspectiveStoragePath(join(requestedParent, "runtime.sqlite"));
    const canonicalProduction = await resolveProspectiveStoragePath(production);
    expect(() => assertStage0StorageIsolation(candidate, ":memory:", canonicalProduction)).toThrow(
      "cannot open Stage 1 production storage",
    );
    await expect(lstat(requestedParent)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it.each<[string, string[]]>([
    ["unknown argument", ["--public"]],
    ["retired fixture seed", ["--seed"]],
    ["missing database path", ["--db"]],
    ["missing research database path", ["--research-db"]],
    ["shared database", ["--db", "same.sqlite", "--research-db", "same.sqlite"]],
    ["non-integer port", ["--port", "12.5"]],
    ["out-of-range port", ["--port", "65536"]],
  ])("rejects %s", (_label, args) => {
    expect(() => parseOperatorOptions(args)).toThrow();
  });
});
