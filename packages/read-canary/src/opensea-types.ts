import type { OpenSeaCollectorErrorCode, OpenSeaRateLimitReceipt } from "@rsi/opensea-collector";

import type {
  OpenSeaReadCanaryPlanSchema,
  OpenSeaReadCanaryFailureEventPayloadSchema,
  OpenSeaReadCanaryProjectionSchema,
  OpenSeaReadCanaryReceiptSchema,
  OpenSeaReadCanaryResultEventPayloadSchema,
  OpenSeaReadCanaryRunCommandSchema,
} from "./opensea-schemas.js";
import type { z } from "zod";

export type OpenSeaReadCanaryPlanV1 = z.infer<typeof OpenSeaReadCanaryPlanSchema>;
export type OpenSeaReadCanaryFailureEventPayloadV1 = z.infer<
  typeof OpenSeaReadCanaryFailureEventPayloadSchema
>;
export type OpenSeaReadCanaryRunCommand = z.infer<typeof OpenSeaReadCanaryRunCommandSchema>;
export type OpenSeaReadCanaryReceiptV1 = z.infer<typeof OpenSeaReadCanaryReceiptSchema>;
export type OpenSeaReadCanaryResultEventPayloadV1 = z.infer<
  typeof OpenSeaReadCanaryResultEventPayloadSchema
>;
export type OpenSeaReadCanaryProjectionV1 = z.infer<typeof OpenSeaReadCanaryProjectionSchema>;

export type OpenSeaReadCanaryFailureCode =
  | OpenSeaCollectorErrorCode
  | "CAPTURE_REJECTED"
  | "CREDENTIAL_UNAVAILABLE"
  | "DURABLE_STATE_FAILURE"
  | "INTERRUPTED"
  | "RUNTIME_DENIED"
  | "UNKNOWN_FAILURE";

export interface OpenSeaReadCanaryTransportFacts {
  readonly hasNextPage: boolean;
  readonly rateLimit: OpenSeaRateLimitReceipt | null;
}
