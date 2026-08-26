import { XCollectorError } from "./errors.js";

export type XRateLimitReceipt = Readonly<{
  limit: number;
  remaining: number;
  resetAtUnixSeconds: number;
}>;

const RATE_LIMIT_KEYS = ["limit", "remaining", "resetAtUnixSeconds"] as const;
const RATE_LIMIT_HEADERS = [
  "x-rate-limit-limit",
  "x-rate-limit-remaining",
  "x-rate-limit-reset",
] as const;
const DECIMAL_INTEGER_PATTERN = /^(?:0|[1-9][0-9]*)$/;

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function invalidRateLimitMetadata(): never {
  throw new XCollectorError(
    "INVALID_RATE_LIMIT_METADATA",
    "The X rate-limit receipt metadata is incomplete or invalid.",
  );
}

function parseHeaderInteger(value: string): number {
  if (!DECIMAL_INTEGER_PATTERN.test(value)) invalidRateLimitMetadata();
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) invalidRateLimitMetadata();
  return parsed;
}

function readReceiptObject(value: unknown): XRateLimitReceipt {
  if (!isPlainRecord(value)) invalidRateLimitMetadata();
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== RATE_LIMIT_KEYS.length ||
    ownKeys.some(
      (key) => typeof key !== "string" || !(RATE_LIMIT_KEYS as readonly string[]).includes(key),
    )
  ) {
    invalidRateLimitMetadata();
  }

  const numbers = Object.create(null) as Record<(typeof RATE_LIMIT_KEYS)[number], number>;
  for (const key of RATE_LIMIT_KEYS) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      !descriptor.enumerable ||
      typeof descriptor.value !== "number" ||
      !Number.isSafeInteger(descriptor.value)
    ) {
      invalidRateLimitMetadata();
    }
    numbers[key] = descriptor.value;
  }
  if (
    numbers.limit < 1 ||
    numbers.remaining < 0 ||
    numbers.remaining > numbers.limit ||
    numbers.resetAtUnixSeconds < 0
  ) {
    invalidRateLimitMetadata();
  }
  return Object.freeze({
    limit: numbers.limit,
    remaining: numbers.remaining,
    resetAtUnixSeconds: numbers.resetAtUnixSeconds,
  });
}

/** Parses only the three documented X rate-limit headers and never retains raw header values. */
export function readXRateLimitReceipt(headers: Headers): XRateLimitReceipt | undefined {
  const values = RATE_LIMIT_HEADERS.map((header) => headers.get(header));
  if (values.every((value) => value === null)) return undefined;
  if (values.some((value) => value === null)) invalidRateLimitMetadata();

  const [limitText, remainingText, resetText] = values as [string, string, string];
  return readReceiptObject({
    limit: parseHeaderInteger(limitText),
    remaining: parseHeaderInteger(remainingText),
    resetAtUnixSeconds: parseHeaderInteger(resetText),
  });
}

export function validateXRateLimitReceipt(value: unknown): XRateLimitReceipt {
  return readReceiptObject(value);
}

export function isXRateLimitReceipt(value: unknown): value is XRateLimitReceipt {
  try {
    readReceiptObject(value);
    return true;
  } catch {
    return false;
  }
}

export function copyXRateLimitReceipt(
  value: XRateLimitReceipt | undefined,
): XRateLimitReceipt | undefined {
  return value === undefined ? undefined : readReceiptObject(value);
}
