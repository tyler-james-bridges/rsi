export type BaseRpcCollectorErrorCode =
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
  | "RATE_LIMITED"
  | "HTTP_STATUS"
  | "UNSUPPORTED_CONTENT_ENCODING"
  | "UNSUPPORTED_CONTENT_TYPE"
  | "RESPONSE_TOO_LARGE"
  | "CONTENT_LENGTH_MISMATCH"
  | "CREDENTIAL_IN_REQUEST"
  | "CREDENTIAL_IN_RESPONSE"
  | "INVALID_RESPONSE_SCHEMA";

export type BaseRpcCollectorSafeDetails = Readonly<{
  status?: number;
  limitBytes?: number;
  receivedBytes?: number;
}>;

/** A closed error surface that never retains bodies, headers, credentials, or transport errors. */
export class BaseRpcCollectorError extends Error {
  readonly code: BaseRpcCollectorErrorCode;
  readonly details: BaseRpcCollectorSafeDetails | undefined;

  constructor(
    code: BaseRpcCollectorErrorCode,
    message: string,
    details?: BaseRpcCollectorSafeDetails,
  ) {
    super(message);
    this.name = "BaseRpcCollectorError";
    this.code = code;
    this.details = details === undefined ? undefined : Object.freeze({ ...details });
  }

  toJSON(): Readonly<{
    name: "BaseRpcCollectorError";
    code: BaseRpcCollectorErrorCode;
    message: string;
    details?: BaseRpcCollectorSafeDetails;
  }> {
    return this.details === undefined
      ? { name: "BaseRpcCollectorError", code: this.code, message: this.message }
      : {
          name: "BaseRpcCollectorError",
          code: this.code,
          message: this.message,
          details: this.details,
        };
  }
}

export function isBaseRpcCollectorError(value: unknown): value is BaseRpcCollectorError {
  return value instanceof BaseRpcCollectorError;
}
