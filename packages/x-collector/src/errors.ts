export type XCollectorErrorCode =
  | "INVALID_CONFIGURATION"
  | "INVALID_CREDENTIAL"
  | "INVALID_QUERY"
  | "ABORTED"
  | "TIMEOUT"
  | "TRANSPORT_FAILURE"
  | "REDIRECT_REFUSED"
  | "HTTP_STATUS"
  | "UNSUPPORTED_CONTENT_TYPE"
  | "RESPONSE_TOO_LARGE"
  | "CONTENT_LENGTH_MISMATCH"
  | "CREDENTIAL_IN_REQUEST"
  | "CREDENTIAL_IN_RESPONSE"
  | "MALFORMED_JSON"
  | "INVALID_RESPONSE_SCHEMA"
  | "CASSETTE_MISS"
  | "INVALID_CASSETTE"
  | "CASSETTE_STORAGE_FAILURE";

export type XCollectorSafeDetails = Readonly<{
  status?: number;
  limitBytes?: number;
  receivedBytes?: number;
  path?: string;
}>;

/** An intentionally small error surface that never retains transport errors or response bodies. */
export class XCollectorError extends Error {
  readonly code: XCollectorErrorCode;
  readonly details: XCollectorSafeDetails | undefined;

  constructor(code: XCollectorErrorCode, message: string, details?: XCollectorSafeDetails) {
    super(message);
    this.name = "XCollectorError";
    this.code = code;
    this.details = details === undefined ? undefined : Object.freeze({ ...details });
  }

  toJSON(): Readonly<{
    name: "XCollectorError";
    code: XCollectorErrorCode;
    message: string;
    details?: XCollectorSafeDetails;
  }> {
    return this.details === undefined
      ? { name: "XCollectorError", code: this.code, message: this.message }
      : { name: "XCollectorError", code: this.code, message: this.message, details: this.details };
  }
}

export function isXCollectorError(value: unknown): value is XCollectorError {
  return value instanceof XCollectorError;
}
