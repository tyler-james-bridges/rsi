import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import * as recoveryEntry from "../src/base-rpc-recovery.js";

const REPOSITORY_ROOT = fileURLToPath(new URL("../../..", import.meta.url));

async function workspaceTarget(specifier: string): Promise<string | null> {
  if (!specifier.startsWith("@rsi/")) return null;
  const parts = specifier.split("/");
  const packageName = parts[1];
  if (packageName === undefined) return null;
  const packageRoot = join(REPOSITORY_ROOT, "packages", packageName);
  const manifest = JSON.parse(await readFile(join(packageRoot, "package.json"), "utf8")) as {
    exports?: Record<string, string> | string;
  };
  const key = parts.length === 2 ? "." : `./${parts.slice(2).join("/")}`;
  const target = typeof manifest.exports === "string" ? manifest.exports : manifest.exports?.[key];
  if (typeof target !== "string") throw new Error(`unresolved workspace import: ${specifier}`);
  return resolve(packageRoot, target.replace(/\.js$/u, ".ts"));
}

async function recoveryGraph(entry: string): Promise<
  Readonly<{
    externals: ReadonlySet<string>;
    sources: ReadonlyMap<string, string>;
  }>
> {
  const sources = new Map<string, string>();
  const externals = new Set<string>();
  const visit = async (path: string): Promise<void> => {
    if (sources.has(path)) return;
    const source = await readFile(path, "utf8");
    sources.set(path, source);
    const specifiers = [
      ...source.matchAll(/\bfrom\s+["']([^"']+)["']/gu),
      ...source.matchAll(/\bimport\s*\(\s*["']([^"']+)["']/gu),
      ...source.matchAll(/\bimport\s+["']([^"']+)["']/gu),
    ].map((match) => match[1]!);
    for (const specifier of specifiers) {
      if (specifier.startsWith(".")) {
        await visit(resolve(dirname(path), specifier.replace(/\.js$/u, ".ts")));
        continue;
      }
      const workspace = await workspaceTarget(specifier);
      if (workspace !== null) {
        await visit(workspace);
        continue;
      }
      externals.add(specifier);
    }
  };
  await visit(entry);
  return Object.freeze({ externals, sources });
}

describe("Base RPC read-canary recovery import graph", () => {
  it("is statically collectorless, credentialless, and egress-free", async () => {
    const entry = fileURLToPath(new URL("../src/base-rpc-recovery.ts", import.meta.url));
    const graph = await recoveryGraph(entry);
    const paths = [...graph.sources.keys()].join("\n");
    const imports = [...graph.externals].join("\n");
    const source = [...graph.sources.values()].join("\n");

    expect(recoveryEntry).toHaveProperty("recoverBaseRpcReadCanary");
    expect(recoveryEntry).not.toHaveProperty("BaseRpcReadCanaryController");
    expect(paths).not.toMatch(/base-rpc-read-canary-controller|base-rpc-collector/u);
    expect(imports).not.toMatch(
      /@rsi\/base-rpc-collector|@rsi\/credential-host|node:http|node:https|node:net|node:tls|undici|ws/u,
    );
    expect(source).not.toMatch(/\bfetch\s*\(|\bXMLHttpRequest\b|\bWebSocket\b/u);
    expect(graph.sources.has(entry)).toBe(true);
  });
});
