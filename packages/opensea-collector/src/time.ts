import { OpenSeaCollectorError } from "./errors.js";

export type OpenSeaCollectorClock = () => Date;

const MIN_ACQUIRED_AT_MS = Date.parse("2020-01-01T00:00:00.000Z");
const MAX_ACQUIRED_AT_MS = Date.parse("2100-01-01T00:00:00.000Z");
const CANONICAL_UTC_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

export function isCanonicalOpenSeaAcquiredAt(value: unknown): value is string {
  if (typeof value !== "string" || !CANONICAL_UTC_PATTERN.test(value)) return false;
  const milliseconds = Date.parse(value);
  return (
    Number.isFinite(milliseconds) &&
    milliseconds >= MIN_ACQUIRED_AT_MS &&
    milliseconds <= MAX_ACQUIRED_AT_MS &&
    new Date(milliseconds).toISOString() === value
  );
}

export function readOpenSeaAcquiredAt(clock: OpenSeaCollectorClock): string {
  try {
    const value = clock();
    if (!(value instanceof Date)) throw new Error("invalid clock");
    const acquiredAt = value.toISOString();
    if (!isCanonicalOpenSeaAcquiredAt(acquiredAt)) throw new Error("invalid clock");
    return acquiredAt;
  } catch {
    throw new OpenSeaCollectorError(
      "INVALID_CONFIGURATION",
      "The collector clock returned an invalid acquisition time.",
    );
  }
}
