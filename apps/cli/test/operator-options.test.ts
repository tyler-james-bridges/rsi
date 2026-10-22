import { chmod, lstat, mkdir, mkdtemp, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  assertDistinctStage0DatabasePaths,
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
    ).toEqual({
      attentionDatabasePath: "rsi-attention.sqlite",
      databasePath: ":memory:",
      port: 0,
      researchDatabasePath: "research.sqlite",
      watchlistDatabasePath: "rsi-watchlist.sqlite",
    });
  });

  it("uses loopback-service defaults", () => {
    expect(parseOperatorOptions([])).toEqual({
      attentionDatabasePath: ".local/stage0/rsi-attention.sqlite",
      databasePath: ".local/stage0/rsi-runtime.sqlite",
      port: 8_787,
      researchDatabasePath: ".local/stage0/rsi-research.sqlite",
      watchlistDatabasePath: ".local/stage0/rsi-watchlist.sqlite",
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
        "/private/rsi/runtime.sqlite",
        "/private/rsi/research.sqlite",
        production,
        `${production}/watchlist.sqlite`,
        "/private/rsi/stage0/attention.sqlite",
      ),
    ).toThrow("cannot open Stage 1 production storage");
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
        `${production}/stage0/watchlist.sqlite`,
        `${production}/stage0/attention.sqlite`,
      ),
    ).not.toThrow();
    expect(() =>
      assertStage0StorageIsolation(
        "/private/rsi/stage0/runtime.sqlite",
        "/private/rsi/stage0/research.sqlite",
        production,
        "/private/rsi/stage0/watchlist.sqlite",
        `${production}/attention.sqlite`,
      ),
    ).toThrow("cannot open Stage 1 production storage");
    expect(() =>
      assertStage0StorageIsolation(
        "/private/rsi/stage0/runtime.sqlite",
        "/private/rsi/stage0/research.sqlite",
        production,
      ),
    ).not.toThrow();
  });

  it("rejects a case alias of an absent production root", () => {
    const production = join(tmpdir(), "rsi-absent-production-root", ".local");
    expect(() =>
      assertStage0StorageIsolation(
        join(tmpdir(), "rsi-stage0-runtime.sqlite"),
        join(tmpdir(), "rsi-stage0-research.sqlite"),
        production,
        join(tmpdir(), "rsi-stage0-watchlist.sqlite"),
        join(tmpdir(), "rsi-absent-production-root", ".LOCAL", "attention.sqlite"),
      ),
    ).toThrow("cannot open Stage 1 production storage");
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
    ["missing watchlist database path", ["--watchlist-db"]],
    ["missing attention database path", ["--attention-db"]],
    [
      "watchlist aliases research",
      ["--watchlist-db", "same.sqlite", "--research-db", "same.sqlite"],
    ],
    ["shared database", ["--db", "same.sqlite", "--research-db", "same.sqlite"]],
    ["attention aliases runtime", ["--attention-db", "same.sqlite", "--db", "same.sqlite"]],
    [
      "attention aliases watchlist",
      ["--attention-db", "collection.sqlite", "--watchlist-db", "collection.sqlite"],
    ],
    ["non-integer port", ["--port", "12.5"]],
    ["out-of-range port", ["--port", "65536"]],
  ])("rejects %s", (_label, args) => {
    expect(() => parseOperatorOptions(args)).toThrow();
  });

  it("rejects Unicode-normalized aliases across every Stage 0 database role", () => {
    expect(() =>
      assertDistinctStage0DatabasePaths([
        "/tmp/caf\u00e9.sqlite",
        "/tmp/research.sqlite",
        "/tmp/watchlist.sqlite",
        "/tmp/cafe\u0301.sqlite",
      ]),
    ).toThrow("separate SQLite files");
  });
});
