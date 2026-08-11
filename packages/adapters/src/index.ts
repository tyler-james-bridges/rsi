import { z } from "zod";

import type { Observation } from "@rsi/domain";
import type { PolicyApproval } from "@rsi/policy";

export const AdapterCapabilitySchema = z.enum([
  "read_only",
  "paid_read",
  "state_changing",
  "forbidden",
]);

export const AdapterManifestSchema = z
  .object({
    id: z.string().regex(/^[a-z0-9._-]+$/),
    label: z.string().min(1),
    capability: AdapterCapabilitySchema,
    status: z.enum(["disabled", "quarantined", "approved"]),
    credentialBoundary: z.string().min(1),
    notes: z.string().min(1),
  })
  .strict();

export type AdapterManifest = z.infer<typeof AdapterManifestSchema>;

export interface QuarantinedPayload {
  adapterId: string;
  acquiredAt: string;
  contentType: string;
  bytes: Uint8Array;
}

export interface ResearchAdapter {
  readonly manifest: AdapterManifest;
  collect(query: Readonly<Record<string, unknown>>): Promise<QuarantinedPayload[]>;
}

export interface EvidenceAdapter {
  readonly manifest: AdapterManifest;
  extract(payload: QuarantinedPayload): Promise<Observation[]>;
}

export interface ExecutionReceipt {
  adapterId: string;
  intentId: string;
  submittedAt: string;
  externalReference: string;
  requestHash: string;
  responseHash: string;
}

export interface ExecutionAdapter {
  readonly manifest: AdapterManifest;
  execute(approval: PolicyApproval): Promise<ExecutionReceipt>;
}

export const RSI_ADAPTER_CATALOG = Object.freeze(
  [
    {
      id: "x.research",
      label: "X research collector",
      capability: "read_only",
      status: "disabled",
      credentialBoundary: "quarantine-worker",
      notes: "Collects hypotheses only; never supplies transaction authority.",
    },
    {
      id: "agentcash.x402",
      label: "AgentCash x402 research buyer",
      capability: "paid_read",
      status: "disabled",
      credentialBoundary: "research-budget-wallet",
      notes: "Every provider, manifest, payee, asset, and price must be pinned and capped.",
    },
    {
      id: "opensea.read",
      label: "OpenSea market evidence",
      capability: "read_only",
      status: "disabled",
      credentialBoundary: "market-data-worker",
      notes: "Produces canonical collection, listing, ownership, and bid evidence.",
    },
    {
      id: "opensea.seaport",
      label: "OpenSea Seaport executor",
      capability: "state_changing",
      status: "disabled",
      credentialBoundary: "exclusive-onchain-executor",
      notes: "Accepts PolicyApproval only; reconstructs and simulates calldata independently.",
    },
    {
      id: "robinhood.trading",
      label: "Robinhood Agentic Trading MCP",
      capability: "state_changing",
      status: "disabled",
      credentialBoundary: "exclusive-brokerage-executor",
      notes: "Dedicated Agentic account only; account data stays outside shared model memory.",
    },
    {
      id: "robinhood.banking",
      label: "Robinhood Banking MCP",
      capability: "state_changing",
      status: "disabled",
      credentialBoundary: "approved-checkout-worker",
      notes: "Legacy-card fallback with per-purchase approval; never an x402 replacement.",
    },
    {
      id: "robinhood.chain",
      label: "Robinhood Chain ERC-4337 wallet",
      capability: "state_changing",
      status: "disabled",
      credentialBoundary: "exclusive-onchain-executor",
      notes: "Fresh smart account with an expiring, selector-scoped session key.",
    },
  ].map((manifest) => AdapterManifestSchema.parse(manifest)),
);
