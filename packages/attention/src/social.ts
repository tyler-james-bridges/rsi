import {
  ContentClusterIdSchema,
  HARD_REASONS,
  PostIdHashSchema,
  RecordedSocialPostSchema,
  WATCH_REASONS,
  AttentionInputError,
  assertPlainAttentionData,
  type HardReason,
  type WatchReason,
} from "./schemas.js";
import { hashText } from "./hash.js";

const INSTRUCTION_PATTERNS = [
  /\b(?:ignore|disregard|forget|override)\b.{0,80}\b(?:previous|prior|system|developer|safety|instructions?|rules?|policy)\b/iu,
  /\b(?:system|developer|assistant)\s*:/iu,
  /\b(?:reveal|print|return|upload|expose|send)\b.{0,80}\b(?:private key|seed phrase|mnemonic|secret|credentials?|api key|card number)\b/iu,
  /\b(?:call|invoke|run|execute|use)\b.{0,60}\b(?:tool|function|shell|terminal|wallet|api|mcp)\b/iu,
  /\b(?:sign|approve|send|transfer|withdraw|bridge|swap|buy)\b.{0,60}\b(?:transaction|funds?|tokens?|nfts?|wallet|balance|everything|now)\b/iu,
  /\b(?:disable|bypass|remove|skip|turn off)\b.{0,60}\b(?:guard|limit|policy|approval|verification|safety|simulation)\b/iu,
] as const;

const SCRIPT_PATTERNS = [
  /\p{Script=Latin}/u,
  /\p{Script=Cyrillic}/u,
  /\p{Script=Greek}/u,
  /\p{Script=Arabic}/u,
  /\p{Script=Hebrew}/u,
  /\p{Script=Han}/u,
  /\p{Script=Hiragana}/u,
  /\p{Script=Katakana}/u,
  /\p{Script=Devanagari}/u,
] as const;

const WALLET_DEMAND = /\b(?:connect|link|verify|authenticate)\b.{0,24}\b(?:your\s+)?wallet\b/giu;
const CLAIM_CONTEXT = /\b(?:claim|airdrop|mint)\b/giu;
const APPROVAL_DEMAND = /\b(?:approve|approval|authorize|allow)\b/giu;
const UNLIMITED_CONTEXT = /\b(?:unlimited|all\s+tokens|all\s+assets)\b/giu;
const GUARANTEED_CONTEXT = /\bguaranteed\b/giu;
const RETURN_CONTEXT = /\b(?:returns?|profits?|risk[ -]?free)\b/giu;
const EXACT_ADDRESS_PATTERN =
  /(?<![\p{ID_Continue}\p{L}\p{N}\p{M}\p{Cf}\p{Pc}])0x[0-9a-fA-F]{40}(?![\p{ID_Continue}\p{L}\p{N}\p{M}\p{Cf}\p{Pc}])/gu;

export interface SanitizedSocialPostFacts {
  readonly postIdHash: ReturnType<typeof PostIdHashSchema.parse>;
  readonly contentClusterId: ReturnType<typeof ContentClusterIdSchema.parse>;
  readonly mentionedAddresses: readonly string[];
  readonly detectedHardReasons: readonly HardReason[];
  readonly detectedWatchReasons: readonly WatchReason[];
}

export function normalizeSocialText(text: string): string {
  if (typeof text !== "string" || text.length < 1 || text.length > 4_096) {
    throw new AttentionInputError();
  }
  return text.normalize("NFKC").toLowerCase().replace(/\s+/gu, " ").trim();
}

export function sanitizeSocialPost(input: unknown): SanitizedSocialPostFacts {
  assertPlainAttentionData(input);
  const parsed = RecordedSocialPostSchema.safeParse(input);
  if (!parsed.success) throw new AttentionInputError();
  const post = parsed.data;
  const normalized = normalizeSocialText(post.text);
  const mentionedAddresses = uniqueSorted(
    [...post.text.matchAll(EXACT_ADDRESS_PATTERN)].map((match) => match[0].toLowerCase()),
  );
  const detectedHardReasons: HardReason[] = [];
  const detectedWatchReasons: WatchReason[] = [];

  if (INSTRUCTION_PATTERNS.some((pattern) => pattern.test(normalized))) {
    detectedHardReasons.push("INSTRUCTION_CONTENT");
  }
  if (patternsAreNear(normalized, WALLET_DEMAND, CLAIM_CONTEXT, 80)) {
    detectedHardReasons.push("WALLET_CONNECTION_SOLICITATION");
  }
  if (patternsAreNear(normalized, APPROVAL_DEMAND, UNLIMITED_CONTEXT, 80)) {
    detectedHardReasons.push("UNLIMITED_APPROVAL_SOLICITATION");
  }
  if (patternsAreNear(normalized, GUARANTEED_CONTEXT, RETURN_CONTEXT, 80)) {
    detectedHardReasons.push("GUARANTEED_RETURN_CLAIM");
  }

  const urls = uniqueSorted([...extractUrls(post.text), ...extractUrls(normalized)]);
  if (urls.some(isDeceptiveUrl) || claimsHttpsDowngrade(normalized)) {
    detectedHardReasons.push("DECEPTIVE_LINK_INDICATOR");
  } else if (urls.length > 0) {
    detectedWatchReasons.push("LINKS_UNCHECKED");
  }

  return Object.freeze({
    postIdHash: PostIdHashSchema.parse(hashText("rsi-attention-x-id-v1\0", post.id)),
    contentClusterId: ContentClusterIdSchema.parse(
      hashText("rsi-attention-x-copy-v1\0", normalized),
    ),
    mentionedAddresses: Object.freeze(mentionedAddresses),
    detectedHardReasons: Object.freeze(ordered(detectedHardReasons, HARD_REASONS)),
    detectedWatchReasons: Object.freeze(ordered(detectedWatchReasons, WATCH_REASONS)),
  });
}

function patternsAreNear(
  text: string,
  firstPattern: RegExp,
  secondPattern: RegExp,
  maximumDistance: number,
): boolean {
  const first = matchRanges(text, firstPattern);
  const second = matchRanges(text, secondPattern);
  return first.some((left) =>
    second.some(
      (right) =>
        Math.min(Math.abs(left.start - right.end), Math.abs(right.start - left.end)) <=
        maximumDistance,
    ),
  );
}

function matchRanges(text: string, pattern: RegExp): readonly { start: number; end: number }[] {
  return [...text.matchAll(pattern)].map((match) => ({
    start: match.index,
    end: match.index + match[0].length,
  }));
}

function extractUrls(text: string): readonly string[] {
  return [...text.matchAll(/(?<![\p{L}\p{N}])(\p{L}{4,5})[:：][\/／]{2}[^\s<>"'`]+/giu)]
    .map((match) => {
      const scheme = match[1]?.normalize("NFKC").toLowerCase();
      if (scheme !== "http" && scheme !== "https") return null;
      const separator = match[0].match(/[:：][\/／]{2}/u);
      if (separator?.index === undefined) return null;
      const authorityAndPath = match[0].slice(separator.index + separator[0].length);
      return `${scheme}://${authorityAndPath}`.replace(/[.,!?;:}\])]+$/u, "");
    })
    .filter((url): url is string => url !== null);
}

function isDeceptiveUrl(rawUrl: string): boolean {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.username.length > 0 || parsed.password.length > 0) return true;
    const inputHostname = rawHostname(rawUrl);
    if (/[^\x00-\x7f]/u.test(inputHostname)) return true;
    if (parsed.hostname.split(".").some((label) => label.toLowerCase().startsWith("xn--"))) {
      return true;
    }
    return inputHostname
      .split(".")
      .some((label) => SCRIPT_PATTERNS.filter((pattern) => pattern.test(label)).length > 1);
  } catch {
    return false;
  }
}

function rawHostname(rawUrl: string): string {
  const authority = rawUrl.match(/^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/iu)?.[1] ?? "";
  const withoutUserInfo = authority.slice(authority.lastIndexOf("@") + 1);
  if (withoutUserInfo.startsWith("[")) {
    return withoutUserInfo.slice(0, withoutUserInfo.indexOf("]") + 1);
  }
  const separator = withoutUserInfo.lastIndexOf(":");
  const port = separator >= 0 ? withoutUserInfo.slice(separator + 1) : "";
  const hostname = /^\d+$/.test(port) ? withoutUserInfo.slice(0, separator) : withoutUserInfo;
  try {
    return decodeURIComponent(hostname);
  } catch {
    return hostname;
  }
}

function claimsHttpsDowngrade(text: string): boolean {
  return /https:\/\/\S{1,240}.{0,80}(?:redirects?|sends?|leads?|[-=]>)\s*.{0,20}http:\/\//iu.test(
    text,
  );
}

function ordered<T extends string>(values: readonly T[], order: readonly T[]): T[] {
  const unique = new Set(values);
  return order.filter((value) => unique.has(value));
}

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values)].sort();
}
