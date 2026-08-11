import { createHash } from "node:crypto";

import type { RecordedLink, XPostFixture } from "./schemas.js";

export type InstructionFlag =
  | "prompt:financial-action"
  | "prompt:instruction-override"
  | "prompt:policy-disable"
  | "prompt:role-spoofing"
  | "prompt:secret-exfiltration"
  | "prompt:tool-invocation";

export type IdentityFlag =
  "identity:declared-address-conflict" | "identity:multiple-contract-addresses";

export type UrlFlag =
  | "url:cross-origin-redirect"
  | "url:embedded-userinfo"
  | "url:http-scheme"
  | "url:https-downgrade"
  | "url:mixed-script-label"
  | "url:punycode-hostname"
  | "url:redirect-loop"
  | "url:unicode-hostname";

export interface NormalizedUrlEndpoint {
  normalizedUrl: string;
  origin: string;
  hostname: string;
}

export interface NormalizedRedirectHop extends NormalizedUrlEndpoint {
  statusCode: number;
}

export interface NormalizedUrlTrace {
  initial: NormalizedUrlEndpoint;
  redirects: readonly NormalizedRedirectHop[];
  final: NormalizedUrlEndpoint;
  flags: readonly UrlFlag[];
}

const INSTRUCTION_PATTERNS: readonly [InstructionFlag, RegExp][] = [
  [
    "prompt:instruction-override",
    /\b(?:ignore|disregard|forget|override)\b.{0,80}\b(?:previous|prior|system|developer|safety|instructions?|rules?|policy)\b/i,
  ],
  ["prompt:role-spoofing", /(?:^|[\n\r])\s*(?:system|developer|assistant)\s*:/im],
  [
    "prompt:secret-exfiltration",
    /\b(?:reveal|print|return|upload|expose|send)\b.{0,80}\b(?:private key|seed phrase|mnemonic|secret|credentials?|api key|card number)\b/i,
  ],
  [
    "prompt:tool-invocation",
    /\b(?:call|invoke|run|execute|use)\b.{0,60}\b(?:tool|function|shell|terminal|wallet|api|mcp)\b/i,
  ],
  [
    "prompt:financial-action",
    /\b(?:sign|approve|send|transfer|withdraw|bridge|swap|buy)\b.{0,60}\b(?:transaction|funds?|tokens?|nfts?|wallet|balance|everything|now)\b/i,
  ],
  [
    "prompt:policy-disable",
    /\b(?:disable|bypass|remove|skip|turn off)\b.{0,60}\b(?:guard|limit|policy|approval|verification|safety|simulation)\b/i,
  ],
];

const SCRIPT_TESTS: readonly [string, RegExp][] = [
  ["latin", /\p{Script=Latin}/u],
  ["cyrillic", /\p{Script=Cyrillic}/u],
  ["greek", /\p{Script=Greek}/u],
  ["arabic", /\p{Script=Arabic}/u],
  ["hebrew", /\p{Script=Hebrew}/u],
  ["han", /\p{Script=Han}/u],
  ["hiragana", /\p{Script=Hiragana}/u],
  ["katakana", /\p{Script=Katakana}/u],
  ["devanagari", /\p{Script=Devanagari}/u],
];

function uniqueSorted<T extends string>(values: readonly T[]): T[] {
  return [...new Set(values)].sort() as T[];
}

function normalizedHostInput(rawUrl: string): string {
  const authority = rawUrl.match(/^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/iu)?.[1] ?? "";
  const withoutUserInfo = authority.slice(authority.lastIndexOf("@") + 1);
  if (withoutUserInfo.startsWith("[")) {
    return withoutUserInfo.slice(0, withoutUserInfo.indexOf("]") + 1);
  }

  const colon = withoutUserInfo.lastIndexOf(":");
  const possiblePort = colon >= 0 ? withoutUserInfo.slice(colon + 1) : "";
  const hostname = /^\d+$/.test(possiblePort) ? withoutUserInfo.slice(0, colon) : withoutUserInfo;
  try {
    return decodeURIComponent(hostname);
  } catch {
    return hostname;
  }
}

function endpoint(rawUrl: string): { endpoint: NormalizedUrlEndpoint; flags: UrlFlag[] } {
  const parsed = new URL(rawUrl);
  const flags: UrlFlag[] = [];
  const inputHostname = normalizedHostInput(rawUrl);

  if (parsed.username.length > 0 || parsed.password.length > 0) {
    flags.push("url:embedded-userinfo");
    parsed.username = "";
    parsed.password = "";
  }
  if (parsed.protocol === "http:") {
    flags.push("url:http-scheme");
  }
  if (/[^\x00-\x7f]/u.test(inputHostname)) {
    flags.push("url:unicode-hostname");
  }
  if (parsed.hostname.split(".").some((label) => label.toLowerCase().startsWith("xn--"))) {
    flags.push("url:punycode-hostname");
  }

  const hasMixedScriptLabel = inputHostname.split(".").some((label) => {
    const scripts = SCRIPT_TESTS.filter(([, matcher]) => matcher.test(label)).map(([name]) => name);
    return scripts.length > 1;
  });
  if (hasMixedScriptLabel) {
    flags.push("url:mixed-script-label");
  }

  parsed.hash = "";
  parsed.searchParams.sort();

  return {
    endpoint: {
      normalizedUrl: parsed.toString(),
      origin: parsed.origin,
      hostname: parsed.hostname.toLowerCase(),
    },
    flags,
  };
}

export function analyzeRecordedLink(link: RecordedLink): NormalizedUrlTrace {
  const first = endpoint(link.observedUrl);
  const flags: UrlFlag[] = [...first.flags];
  const redirects: NormalizedRedirectHop[] = [];
  const visited = new Set([first.endpoint.normalizedUrl]);
  let previous = first.endpoint;

  for (const redirect of link.redirects) {
    const next = endpoint(redirect.location);
    flags.push(...next.flags);
    if (next.endpoint.origin !== previous.origin) {
      flags.push("url:cross-origin-redirect");
    }
    if (
      previous.normalizedUrl.startsWith("https:") &&
      next.endpoint.normalizedUrl.startsWith("http:")
    ) {
      flags.push("url:https-downgrade");
    }
    if (visited.has(next.endpoint.normalizedUrl)) {
      flags.push("url:redirect-loop");
    }
    visited.add(next.endpoint.normalizedUrl);
    redirects.push({ ...next.endpoint, statusCode: redirect.statusCode });
    previous = next.endpoint;
  }

  return {
    initial: first.endpoint,
    redirects,
    final: previous,
    flags: uniqueSorted(flags),
  };
}

function normalizeUntrustedText(text: string): string {
  return text
    .normalize("NFKC")
    .replace(/[\u200B-\u200D\u2060\uFEFF]/gu, "")
    .toLowerCase();
}

export function flagUntrustedInstructions(text: string): InstructionFlag[] {
  const normalized = normalizeUntrustedText(text);
  return uniqueSorted(
    INSTRUCTION_PATTERNS.filter(([, pattern]) => pattern.test(normalized)).map(([flag]) => flag),
  );
}

export function flagAssetIdentityConflicts(text: string, declaredAddress: string): IdentityFlag[] {
  const addresses = uniqueSorted(
    [...normalizeUntrustedText(text).matchAll(/\b0x[0-9a-f]{40}\b/gu)].map(([address]) =>
      address.toLowerCase(),
    ),
  );
  const flags: IdentityFlag[] = [];

  if (addresses.length > 1) {
    flags.push("identity:multiple-contract-addresses");
  }
  if (addresses.some((address) => address !== declaredAddress.toLowerCase())) {
    flags.push("identity:declared-address-conflict");
  }
  return uniqueSorted(flags);
}

export function socialContentFingerprint(fixture: XPostFixture): string {
  const normalized = normalizeUntrustedText(fixture.post.text)
    .replace(/https?:\/\/\S+/gu, "<url>")
    .replace(/\b0x[0-9a-f]{40}\b/gu, "<address>")
    .replace(/\s+/gu, " ")
    .trim();
  return createHash("sha256").update(normalized).digest("hex");
}
