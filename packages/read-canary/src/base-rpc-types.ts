import type { z } from "zod";

import type {
  BaseRpcReadCanaryDurableReceiptSchema,
  BaseRpcReadCanaryFailureEventPayloadSchema,
  BaseRpcReadCanaryPlanSchema,
  BaseRpcReadCanaryProjectionSchema,
  BaseRpcReadCanaryReceiptSchema,
  BaseRpcReadCanaryResultEventPayloadSchema,
  BaseRpcReadCanaryRunCommandSchema,
} from "./base-rpc-schemas.js";

export type BaseRpcReadCanaryPlanV1 = z.infer<typeof BaseRpcReadCanaryPlanSchema>;
export type BaseRpcReadCanaryFailureEventPayloadV1 = z.infer<
  typeof BaseRpcReadCanaryFailureEventPayloadSchema
>;
export type BaseRpcReadCanaryRunCommand = z.infer<typeof BaseRpcReadCanaryRunCommandSchema>;
/** Sanitized public receipt. */
export type BaseRpcReadCanaryReceiptV1 = z.infer<typeof BaseRpcReadCanaryReceiptSchema>;
/** Internal authenticated event payload; never return this from the public API. */
export type BaseRpcReadCanaryDurableReceiptV1 = z.infer<
  typeof BaseRpcReadCanaryDurableReceiptSchema
>;
export type BaseRpcReadCanaryResultEventPayloadV1 = z.infer<
  typeof BaseRpcReadCanaryResultEventPayloadSchema
>;
export type BaseRpcReadCanaryProjectionV1 = z.infer<typeof BaseRpcReadCanaryProjectionSchema>;

export type BaseRpcReadCanaryFailureCode =
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
  | "INVALID_RESPONSE_SCHEMA"
  | "CAPTURE_REJECTED"
  | "CREDENTIAL_UNAVAILABLE"
  | "DURABLE_STATE_FAILURE"
  | "INTERRUPTED"
  | "RUNTIME_DENIED"
  | "UNKNOWN_FAILURE";
