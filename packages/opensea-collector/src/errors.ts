import type { OpenSeaRateLimitReceipt } from "./rate-limit.js";

export type OpenSeaCollectorErrorCode =
  | "INVALID_CONFIGURATION"
  | "INVALID_CREDENTIAL"
  | "RUNTIME_AUTHORIZATION_FAILED"
  | "ATTEMPT_AUTHORIZATION_FAILED"
  | "CLOCK_REGRESSION"
  | "ABORTED"
  | "TIMEOUT"
  | "TRANSPORT_FAILURE"
  | "REDIRECT_REFUSED"
  | "PAYMENT_REQUIRED"
  | "HTTP_STATUS"
  | "UNSUPPORTED_CONTENT_ENCODING"
  | "UNSUPPORTED_CONTENT_TYPE"
  | "INVALID_RATE_LIMIT_METADATA"
  | "RESPONSE_TOO_LARGE"
  | "CONTENT_LENGTH_MISMATCH"
  | "CREDENTIAL_IN_REQUEST"
  | "CREDENTIAL_IN_RESPONSE"
  | "INVALID_RESPONSE_SCHEMA";

export type OpenSeaCollectorSafeDetails = Readonly<{
  status?: number;
  limitBytes?: number;
  receivedBytes?: number;
  rateLimit?: OpenSeaRateLimitReceipt;
}>;

/** A closed error surface that never retains response bodies, headers, or transport errors. */
export class OpenSeaCollectorError extends Error {
  readonly code: OpenSeaCollectorErrorCode;
  readonly details: OpenSeaCollectorSafeDetails | undefined;

  constructor(
    code: OpenSeaCollectorErrorCode,
    message: string,
    details?: OpenSeaCollectorSafeDetails,
  ) {
    super(message);
    this.name = "OpenSeaCollectorError";
    this.code = code;
    this.details = details === undefined ? undefined : Object.freeze({ ...details });
  }

  toJSON(): Readonly<{
    name: "OpenSeaCollectorError";
    code: OpenSeaCollectorErrorCode;
    message: string;
    details?: OpenSeaCollectorSafeDetails;
  }> {
    return this.details === undefined
      ? { name: "OpenSeaCollectorError", code: this.code, message: this.message }
      : {
          name: "OpenSeaCollectorError",
          code: this.code,
          message: this.message,
          details: this.details,
        };
  }
}

export function isOpenSeaCollectorError(value: unknown): value is OpenSeaCollectorError {
  return value instanceof OpenSeaCollectorError;
}
