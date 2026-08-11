export type JsonPrimitive = boolean | null | number | string;

export type JsonValue =
  JsonPrimitive | { readonly [key: string]: JsonValue } | readonly JsonValue[];

export interface AppendEventInput {
  readonly aggregateId: string;
  readonly eventId?: string;
  readonly idempotencyKey?: string;
  readonly occurredAt?: string;
  readonly payload: JsonValue;
  readonly type: string;
}

export interface StoredEvent {
  readonly aggregateId: string;
  readonly eventHash: string;
  readonly eventId: string;
  readonly idempotencyKey: string | null;
  readonly occurredAt: string;
  readonly payload: JsonValue;
  readonly previousHash: string;
  readonly sequence: number;
  readonly type: string;
}

export interface EventListFilters {
  /** Only events strictly after this sequence. */
  readonly afterSequence?: number;
  readonly aggregateId?: string;
  /** Only events strictly before this sequence. */
  readonly beforeSequence?: number;
  readonly limit?: number;
  readonly order?: "asc" | "desc";
  readonly type?: string;
}

export type IntegrityIssueCode =
  | "DATABASE_ERROR"
  | "HEAD_HASH_MISMATCH"
  | "HEAD_SEQUENCE_MISMATCH"
  | "INVALID_EVENT_HASH"
  | "INVALID_METADATA"
  | "INVALID_PAYLOAD_JSON"
  | "INVALID_PREVIOUS_HASH"
  | "INVALID_ROW"
  | "NON_CANONICAL_PAYLOAD"
  | "NON_CANONICAL_TIMESTAMP"
  | "PREVIOUS_HASH_MISMATCH"
  | "SEQUENCE_GAP"
  | "UNSUPPORTED_SCHEMA_VERSION";

export interface IntegrityIssue {
  readonly code: IntegrityIssueCode;
  readonly message: string;
  readonly sequence: number | null;
}

export interface IntegrityReport {
  readonly errors: readonly IntegrityIssue[];
  readonly eventCount: number;
  readonly headHash: string;
  readonly headSequence: number;
  readonly valid: boolean;
}
