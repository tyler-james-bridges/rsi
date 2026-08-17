export type AlertProfile = "dev" | "canary" | "production-observer";

export type AlertPlane = "healthchecks" | "resend";

export type IncidentCode =
  | "ALERT_DELIVERY_FAILURE"
  | "ALERT_PATH_CANARY"
  | "ANCHOR_FAILURE"
  | "BACKUP_FAILURE"
  | "CLOCK_FAILURE"
  | "CONFIGURATION_DRIFT"
  | "COST_ANOMALY"
  | "CREDENTIAL_COMPROMISE"
  | "CROSS_PROFILE_CONTAMINATION"
  | "CURSOR_FAILURE"
  | "DATA_LEAK"
  | "FINANCIAL_ADAPTER_REACHABLE"
  | "HOST_SECURITY_FAILURE"
  | "INCIDENT_LATCH_BYPASS"
  | "INTEGRITY_MISMATCH"
  | "NETWORK_BOUNDARY_ESCAPE"
  | "POLICY_BOUNDARY_ESCAPE"
  | "PREFLIGHT_FAILURE"
  | "PROVIDER_OUTAGE"
  | "PROVIDER_SCHEMA_DRIFT"
  | "PUBLICATION_FAILURE"
  | "PURGE_FAILURE"
  | "RELEASE_FAILURE"
  | "RESOURCE_BOUND_EXCEEDED"
  | "RUNTIME_CRASH"
  | "SECOND_WRITER"
  | "SESSION_SUPERVISION_FAILURE"
  | "SIGNING_KEY_COMPROMISE"
  | "TERMS_OR_PRICE_DRIFT";

export interface IncidentAlertV1 {
  readonly schemaVersion: "incident-alert.v1";
  readonly incidentId: string;
  readonly incidentCode: IncidentCode;
  readonly severity: "critical";
  readonly occurredAt: string;
  readonly profile: AlertProfile;
  readonly sessionId: string;
  readonly templateRevision: 1;
  readonly instruction: "OPEN_LOCAL_RSI_CONSOLE";
}

export type DeliveryState = "delivered" | "exhausted" | "in_flight" | "pending";

export interface EnqueueAlertInput {
  readonly alert: IncidentAlertV1;
  readonly plane: AlertPlane;
  readonly queuedAt: string;
}

export interface ClaimDeliveryInput {
  readonly claimedAt: string;
  readonly plane: AlertPlane;
}

export interface AlertDeliveryClaim {
  readonly alert: IncidentAlertV1;
  readonly attempt: 1 | 2;
  readonly claimedAt: string;
  readonly deliveryId: string;
  readonly idempotencyKey: string;
  readonly plane: AlertPlane;
}

export interface CompleteDeliveryInput {
  readonly attempt: 1 | 2;
  readonly completedAt: string;
  readonly deliveryId: string;
  readonly providerMessageId?: string;
}

export interface FailDeliveryInput {
  readonly attempt: 1 | 2;
  readonly deliveryId: string;
  readonly failedAt: string;
  readonly retryable: boolean;
}

export interface RecoverDeliveriesInput {
  readonly recoveredAt: string;
}

export interface AlertDeliveryReceipt {
  readonly attempts: 0 | 1 | 2;
  readonly deliveryId: string;
  readonly plane: AlertPlane;
  readonly profile: AlertProfile;
  readonly queuedAt: string;
  readonly state: DeliveryState;
  readonly updatedAt: string;
}

export interface AlertRecoveryReceipt {
  readonly exhausted: number;
  readonly recoveredAt: string;
  readonly retryReady: number;
}

export interface AlertIntegrityReport {
  readonly auditEvents: number;
  readonly attempts: number;
  readonly deliveries: number;
  readonly errors: readonly string[];
  readonly valid: boolean;
}

/** Aggregate-only per-session alert state. Incident and delivery identifiers never escape. */
export interface AlertSessionSummaryV1 {
  readonly schemaVersion: 1;
  readonly profile: AlertProfile;
  readonly sessionId: string;
  readonly incidentCount: number;
  readonly deliveryCount: number;
  readonly states: Readonly<Record<DeliveryState, number>>;
}

/**
 * Content-free authenticated audit-prefix pin. Retain it outside the SQLite file and provide it
 * on reopen so state older than that proven prefix cannot be substituted. A valid newer suffix is
 * accepted so a commit remains recoverable if the process crashed before retaining a newer pin.
 */
export interface AlertTrustedHeadV1 {
  readonly schemaVersion: "alert-trusted-head.v1";
  readonly profile: AlertProfile;
  readonly auditSequence: number;
  readonly auditMac: string;
  readonly schemaMac: string;
  readonly headMac: string;
}

export interface OpenAlertOutboxOptions {
  readonly databasePath: string;
  readonly profile: AlertProfile;
  readonly stateKey: Uint8Array;
  readonly trustedHead?: AlertTrustedHeadV1 | undefined;
}
