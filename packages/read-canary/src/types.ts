import type { XCollectorErrorCode, XRateLimitReceipt } from "@rsi/x-collector";

import type {
  XReadCanaryPlanSchema,
  XReadCanaryProjectionSchema,
  XReadCanaryReceiptSchema,
  XReadCanaryResultEventPayloadSchema,
  XReadCanaryRunCommandSchema,
} from "./schemas.js";
import type { z } from "zod";

export type XReadCanaryPlanV1 = z.infer<typeof XReadCanaryPlanSchema>;
export type XReadCanaryRunCommand = z.infer<typeof XReadCanaryRunCommandSchema>;
export type XReadCanaryReceiptV1 = z.infer<typeof XReadCanaryReceiptSchema>;
export type XReadCanaryResultEventPayloadV1 = z.infer<typeof XReadCanaryResultEventPayloadSchema>;
export type XReadCanaryProjectionV1 = z.infer<typeof XReadCanaryProjectionSchema>;

export type XReadCanaryFailureCode =
  | XCollectorErrorCode
  | "CAPTURE_REJECTED"
  | "CREDENTIAL_UNAVAILABLE"
  | "DURABLE_STATE_FAILURE"
  | "INTERRUPTED"
  | "RUNTIME_DENIED"
  | "UNKNOWN_FAILURE";

export interface XReadCanaryTransportFacts {
  readonly hasNextPage: boolean;
  readonly rateLimit: XRateLimitReceipt | null;
}
