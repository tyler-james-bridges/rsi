import { z } from "zod";

import {
  AtomicSchema,
  Bytes32Schema,
  EvmAddressSchema,
  TimestampSchema,
  canonicalTimestamp,
  deepFreeze,
  fail,
  parseJsonBytes,
  parsePlain,
} from "./common.js";

export const OPENSEA_CONTRACT_REVIEW_DATE = "2026-08-15";
export const OPENSEA_REST_MAXIMUM_BYTES = 2 * 1_024 * 1_024;
export const OPENSEA_STREAM_MAXIMUM_EVENT_BYTES = 256 * 1_024;

const ChainSchema = z.literal("base");
const TokenIdSchema = AtomicSchema;
const CollectionSlugSchema = z.string().regex(/^[a-z0-9][a-z0-9-]{0,127}$/);
const Rfc3339Schema = z
  .string()
  .max(24)
  .refine((value) => {
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) return false;
    const time = Date.parse(value);
    const normalized = value.length === 20 ? value.replace("Z", ".000Z") : value;
    return Number.isFinite(time) && new Date(time).toISOString() === normalized;
  });

const AssetSchema = z.strictObject({
  chain: ChainSchema,
  contract: EvmAddressSchema,
  tokenId: TokenIdSchema,
});

const RestRequestInputSchema = z.strictObject({
  asset: AssetSchema,
  orderHash: Bytes32Schema,
  protocolAddress: EvmAddressSchema,
});

const StreamRequestInputSchema = z.strictObject({ collectionSlug: CollectionSlugSchema });

const PriceSchema = z.strictObject({
  currencyAddress: EvmAddressSchema,
  decimals: z.number().int().min(0).max(36),
  value: AtomicSchema,
});

const RestResponseSchema = z.strictObject({
  asset: z.strictObject({ contract: EvmAddressSchema, identifier: TokenIdSchema }),
  chain: ChainSchema,
  order_created_at: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
  order_hash: Bytes32Schema,
  price: PriceSchema,
  protocol_address: EvmAddressSchema,
  protocol_data: z.strictObject({
    parameters: z.strictObject({ endTime: AtomicSchema, startTime: AtomicSchema }),
  }),
  remaining_quantity: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  status: z.literal("ACTIVE"),
});

const StreamResponseSchema = z.strictObject({
  event_type: z.literal("item_listed"),
  payload: z.strictObject({
    base_price: AtomicSchema,
    collection: z.strictObject({ slug: CollectionSlugSchema }),
    event_timestamp: Rfc3339Schema,
    item: z.strictObject({
      chain: z.strictObject({ name: ChainSchema }),
      nft_id: z.string().max(256),
    }),
    payment_token: z.strictObject({
      address: EvmAddressSchema,
      decimals: z.number().int().min(0).max(36),
      symbol: z.string().regex(/^[A-Za-z0-9._-]{1,24}$/),
    }),
  }),
  sent_at: Rfc3339Schema,
});

const restEvidenceInstances = new WeakSet<object>();
const streamTriggerInstances = new WeakSet<object>();
const corroboratedListingInstances = new WeakSet<object>();

export interface OpenSeaAssetV1 {
  readonly chain: "base";
  readonly contract: string;
  readonly tokenId: string;
}

export interface OpenSeaRestRequestV1 {
  readonly accept: "application/json";
  readonly contractReviewDate: typeof OPENSEA_CONTRACT_REVIEW_DATE;
  readonly credentialHeader: "x-api-key";
  readonly maximumResponseBytes: typeof OPENSEA_REST_MAXIMUM_BYTES;
  readonly method: "GET";
  readonly operation: "opensea.rest.v1";
  readonly origin: "https://api.opensea.io";
  readonly path: string;
  readonly redirect: "reject";
  readonly timeoutMs: 10_000;
}

export interface OpenSeaStreamSubscriptionV1 {
  readonly contractReviewDate: typeof OPENSEA_CONTRACT_REVIEW_DATE;
  readonly credentialPlacement: "query-token";
  readonly heartbeatMs: 30_000;
  readonly maximumEventBytes: typeof OPENSEA_STREAM_MAXIMUM_EVENT_BYTES;
  readonly operation: "opensea.stream.v1";
  readonly origin: "wss://stream-api.opensea.io";
  readonly path: "/socket/websocket";
  readonly reconnectAttempts: 1;
  readonly reconnectTimeoutMs: 15_000;
  readonly topic: string;
}

export interface OpenSeaRestEvidenceV1 {
  readonly acquiredAt: string;
  readonly asset: Readonly<OpenSeaAssetV1>;
  readonly orderCreatedAt: string;
  readonly orderHash: string;
  readonly payment: Readonly<{ currencyAddress: string; decimals: number; value: string }>;
  readonly protocolAddress: string;
  readonly validUntil: string;
}

export interface OpenSeaStreamTriggerV1 {
  readonly acquiredAt: string;
  readonly asset: Readonly<OpenSeaAssetV1>;
  readonly collectionSlug: string;
  readonly eventObservedAt: string;
  readonly payment: Readonly<{ currencyAddress: string; decimals: number; value: string }>;
  readonly validUntil: string;
}

export interface OpenSeaCorroboratedListingV1 extends OpenSeaRestEvidenceV1 {
  readonly collectionSlug: string;
  readonly streamObservedAt: string;
}

export function prepareOpenSeaRestRequest(value: unknown): Readonly<OpenSeaRestRequestV1> {
  const input = parsePlain(RestRequestInputSchema, value);
  const chain = input.asset.chain;
  return Object.freeze({
    accept: "application/json",
    contractReviewDate: OPENSEA_CONTRACT_REVIEW_DATE,
    credentialHeader: "x-api-key",
    maximumResponseBytes: OPENSEA_REST_MAXIMUM_BYTES,
    method: "GET",
    operation: "opensea.rest.v1",
    origin: "https://api.opensea.io",
    path: `/api/v2/orders/chain/${chain}/protocol/${input.protocolAddress.toLowerCase()}/${input.orderHash.toLowerCase()}`,
    redirect: "reject",
    timeoutMs: 10_000,
  });
}

export function prepareOpenSeaStreamSubscription(
  value: unknown,
): Readonly<OpenSeaStreamSubscriptionV1> {
  const input = parsePlain(StreamRequestInputSchema, value);
  return Object.freeze({
    contractReviewDate: OPENSEA_CONTRACT_REVIEW_DATE,
    credentialPlacement: "query-token",
    heartbeatMs: 30_000,
    maximumEventBytes: OPENSEA_STREAM_MAXIMUM_EVENT_BYTES,
    operation: "opensea.stream.v1",
    origin: "wss://stream-api.opensea.io",
    path: "/socket/websocket",
    reconnectAttempts: 1,
    reconnectTimeoutMs: 15_000,
    topic: `collection:${input.collectionSlug}`,
  });
}

export function parseOpenSeaRestFixture(
  bytes: unknown,
  expectedValue: unknown,
  acquiredAtValue: unknown,
): Readonly<OpenSeaRestEvidenceV1> {
  const expected = parsePlain(RestRequestInputSchema, expectedValue);
  const acquiredAt = parsePlain(TimestampSchema, acquiredAtValue);
  const response = parseJsonBytes(RestResponseSchema, bytes, OPENSEA_REST_MAXIMUM_BYTES);
  if (
    response.chain !== expected.asset.chain ||
    response.asset.contract.toLowerCase() !== expected.asset.contract.toLowerCase() ||
    response.asset.identifier !== expected.asset.tokenId ||
    response.order_hash.toLowerCase() !== expected.orderHash.toLowerCase() ||
    response.protocol_address.toLowerCase() !== expected.protocolAddress.toLowerCase()
  ) {
    fail("ASSET_MISMATCH");
  }
  const acquired = Date.parse(acquiredAt);
  const created = response.order_created_at * 1_000;
  const starts = Number(BigInt(response.protocol_data.parameters.startTime) * 1_000n);
  const ends = Number(BigInt(response.protocol_data.parameters.endTime) * 1_000n);
  if (
    !Number.isSafeInteger(starts) ||
    !Number.isSafeInteger(ends) ||
    created > acquired ||
    starts > acquired ||
    ends <= acquired
  ) {
    fail("STALE_RESPONSE");
  }
  const evidence = deepFreeze({
    acquiredAt,
    asset: {
      chain: response.chain,
      contract: response.asset.contract.toLowerCase(),
      tokenId: response.asset.identifier,
    },
    orderCreatedAt: new Date(created).toISOString(),
    orderHash: response.order_hash.toLowerCase(),
    payment: {
      currencyAddress: response.price.currencyAddress.toLowerCase(),
      decimals: response.price.decimals,
      value: response.price.value,
    },
    protocolAddress: response.protocol_address.toLowerCase(),
    validUntil: new Date(Math.min(acquired + 120_000, ends)).toISOString(),
  });
  restEvidenceInstances.add(evidence);
  return evidence;
}

export function parseOpenSeaStreamFixture(
  bytes: unknown,
  expectedCollectionValue: unknown,
  acquiredAtValue: unknown,
): Readonly<OpenSeaStreamTriggerV1> {
  const expected = parsePlain(StreamRequestInputSchema, expectedCollectionValue);
  const acquiredAt = parsePlain(TimestampSchema, acquiredAtValue);
  const response = parseJsonBytes(StreamResponseSchema, bytes, OPENSEA_STREAM_MAXIMUM_EVENT_BYTES);
  if (response.payload.collection.slug !== expected.collectionSlug) fail("ASSET_MISMATCH");
  const [chain, contract, tokenId, ...extra] = response.payload.item.nft_id.split("/");
  const parsedAsset = AssetSchema.safeParse({ chain, contract, tokenId });
  if (!parsedAsset.success || extra.length !== 0) fail("RESPONSE_INVALID");
  const eventObservedAt = canonicalTimestamp(response.payload.event_timestamp);
  const sentAt = Date.parse(response.sent_at);
  const observedAt = Date.parse(eventObservedAt);
  const acquired = Date.parse(acquiredAt);
  if (observedAt > sentAt || sentAt > acquired || acquired - observedAt > 120_000) {
    fail("STALE_RESPONSE");
  }
  const trigger = deepFreeze({
    acquiredAt,
    asset: {
      chain: parsedAsset.data.chain,
      contract: parsedAsset.data.contract.toLowerCase(),
      tokenId: parsedAsset.data.tokenId,
    },
    collectionSlug: response.payload.collection.slug,
    eventObservedAt,
    payment: {
      currencyAddress: response.payload.payment_token.address.toLowerCase(),
      decimals: response.payload.payment_token.decimals,
      value: response.payload.base_price,
    },
    validUntil: new Date(observedAt + 120_000).toISOString(),
  });
  streamTriggerInstances.add(trigger);
  return trigger;
}

export function corroborateOpenSeaListing(
  streamValue: unknown,
  restValue: unknown,
  atValue: unknown,
): Readonly<OpenSeaCorroboratedListingV1> {
  if (
    typeof streamValue !== "object" ||
    streamValue === null ||
    !streamTriggerInstances.has(streamValue) ||
    typeof restValue !== "object" ||
    restValue === null ||
    !restEvidenceInstances.has(restValue)
  ) {
    fail("INPUT_INVALID");
  }
  const stream = parsePlain(
    z.strictObject({
      acquiredAt: TimestampSchema,
      asset: AssetSchema,
      collectionSlug: CollectionSlugSchema,
      eventObservedAt: TimestampSchema,
      payment: PriceSchema,
      validUntil: TimestampSchema,
    }),
    streamValue,
  );
  const rest = parsePlain(
    z.strictObject({
      acquiredAt: TimestampSchema,
      asset: AssetSchema,
      orderCreatedAt: TimestampSchema,
      orderHash: Bytes32Schema,
      payment: PriceSchema,
      protocolAddress: EvmAddressSchema,
      validUntil: TimestampSchema,
    }),
    restValue,
  );
  const at = parsePlain(TimestampSchema, atValue);
  if (
    stream.asset.chain !== rest.asset.chain ||
    stream.asset.contract.toLowerCase() !== rest.asset.contract.toLowerCase() ||
    stream.asset.tokenId !== rest.asset.tokenId ||
    stream.payment.currencyAddress.toLowerCase() !== rest.payment.currencyAddress.toLowerCase() ||
    stream.payment.decimals !== rest.payment.decimals ||
    stream.payment.value !== rest.payment.value
  ) {
    fail("ASSET_MISMATCH");
  }
  if (Date.parse(at) >= Math.min(Date.parse(stream.validUntil), Date.parse(rest.validUntil))) {
    fail("STALE_RESPONSE");
  }
  if (
    Date.parse(stream.eventObservedAt) > Date.parse(stream.acquiredAt) ||
    Date.parse(stream.acquiredAt) > Date.parse(rest.acquiredAt) ||
    Date.parse(rest.orderCreatedAt) > Date.parse(rest.acquiredAt) ||
    Date.parse(rest.acquiredAt) > Date.parse(at)
  ) {
    fail("STALE_RESPONSE");
  }
  const listing = deepFreeze({
    ...rest,
    collectionSlug: stream.collectionSlug,
    streamObservedAt: stream.eventObservedAt,
    validUntil: new Date(
      Math.min(Date.parse(stream.validUntil), Date.parse(rest.validUntil)),
    ).toISOString(),
  });
  corroboratedListingInstances.add(listing);
  return listing;
}

export function isOpenSeaCorroboratedListing(
  value: unknown,
): value is Readonly<OpenSeaCorroboratedListingV1> {
  return typeof value === "object" && value !== null && corroboratedListingInstances.has(value);
}
