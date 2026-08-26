import { z } from "zod";

import {
  EvmAddressSchema,
  TimestampSchema,
  deepFreeze,
  fail,
  parseJsonBytes,
  parsePlain,
} from "./common.js";

/**
 * Contract reviewed against the official OpenSea API v2 OpenAPI description on 2026-08-25.
 * Bump this version only after a deliberate review of an upstream contract change.
 */
export const OPENSEA_TRENDING_CONTRACT_VERSION =
  "opensea-api-v2-collections-trending.2026-08-25.one-day-base-ten-v1" as const;
export const OPENSEA_TRENDING_CONTRACT_REVIEW_DATE = "2026-08-25" as const;
export const OPENSEA_TRENDING_ORIGIN = "https://api.opensea.io" as const;
export const OPENSEA_TRENDING_PATH = "/api/v2/collections/trending" as const;
export const OPENSEA_TRENDING_QUERY = "timeframe=one_day&chains=base&limit=10" as const;
export const OPENSEA_TRENDING_URL =
  `${OPENSEA_TRENDING_ORIGIN}${OPENSEA_TRENDING_PATH}?${OPENSEA_TRENDING_QUERY}` as const;
export const OPENSEA_TRENDING_MAXIMUM_RESULTS = 10 as const;
export const OPENSEA_TRENDING_MAXIMUM_BYTES = 2 * 1_024 * 1_024;
export const OPENSEA_TRENDING_TIMEOUT_MS = 10_000 as const;
export const OPENSEA_TRENDING_VALIDITY_MS = 120_000 as const;

const OPENSEA_TRENDING_MAXIMUM_CONTRACTS_PER_COLLECTION = 16;
const OPENSEA_TRENDING_MAXIMUM_CURSOR_CHARACTERS = 2_048;

const CollectionSlugSchema = z.string().regex(/^[a-z0-9][a-z0-9-]{0,127}$/);
const RequiredNameSchema = z.string().max(512);
const DiscardedCategorySchema = z.string().max(256);
const DiscardedDescriptionSchema = z.string().max(25_000);
const DiscardedOwnerSchema = z.string().max(256);
const DiscardedUrlSchema = z.string().max(4_096);
const DiscardedUsernameSchema = z.string().max(256);
const NextCursorSchema = z
  .string()
  .min(1)
  .max(OPENSEA_TRENDING_MAXIMUM_CURSOR_CHARACTERS)
  .regex(/^[\x21-\x7e]+$/);

const ContractSchema = z.strictObject({
  address: EvmAddressSchema,
  chain: z.literal("base"),
});

/**
 * Exact documented CollectionResponse wire shape. Text, URLs, usernames, feature flags, and the
 * pagination cursor are admitted only so the provider response can be validated; none cross the
 * trusted projection boundary.
 */
const CollectionResponseSchema = z.strictObject({
  banner_image_url: DiscardedUrlSchema.optional(),
  category: DiscardedCategorySchema.optional(),
  collection: CollectionSlugSchema,
  collection_offers_enabled: z.boolean(),
  contracts: z.array(ContractSchema).min(1).max(OPENSEA_TRENDING_MAXIMUM_CONTRACTS_PER_COLLECTION),
  description: DiscardedDescriptionSchema.optional(),
  discord_url: DiscardedUrlSchema.optional(),
  image_url: DiscardedUrlSchema.optional(),
  instagram_username: DiscardedUsernameSchema.optional(),
  is_disabled: z.literal(false),
  is_nsfw: z.literal(false),
  name: RequiredNameSchema,
  opensea_url: DiscardedUrlSchema,
  owner: DiscardedOwnerSchema.optional(),
  project_url: DiscardedUrlSchema.optional(),
  safelist_status: z.literal("verified"),
  telegram_url: DiscardedUrlSchema.optional(),
  trait_offers_enabled: z.boolean(),
  twitter_username: DiscardedUsernameSchema.optional(),
  wiki_url: DiscardedUrlSchema.optional(),
});

const TrendingResponseSchema = z.strictObject({
  collections: z.array(CollectionResponseSchema).max(OPENSEA_TRENDING_MAXIMUM_RESULTS),
  next: NextCursorSchema.optional(),
});

export interface OpenSeaTrendingRequestV1 {
  readonly accept: "application/json";
  readonly contractReviewDate: typeof OPENSEA_TRENDING_CONTRACT_REVIEW_DATE;
  readonly contractVersion: typeof OPENSEA_TRENDING_CONTRACT_VERSION;
  readonly credentialHeader: "x-api-key";
  readonly maximumResponseBytes: typeof OPENSEA_TRENDING_MAXIMUM_BYTES;
  readonly maximumResults: typeof OPENSEA_TRENDING_MAXIMUM_RESULTS;
  readonly method: "GET";
  readonly operation: "opensea.trending-collections.v1";
  readonly origin: typeof OPENSEA_TRENDING_ORIGIN;
  readonly path: typeof OPENSEA_TRENDING_PATH;
  readonly query: typeof OPENSEA_TRENDING_QUERY;
  readonly redirect: "reject";
  readonly retryAttempts: 0;
  readonly timeoutMs: typeof OPENSEA_TRENDING_TIMEOUT_MS;
  readonly url: typeof OPENSEA_TRENDING_URL;
}

export interface OpenSeaTrendingCollectionV1 {
  readonly baseAddresses: readonly string[];
  readonly rank: number;
  readonly slug: string;
}

export interface OpenSeaTrendingEvidenceV1 {
  readonly acquiredAt: string;
  readonly collections: readonly Readonly<OpenSeaTrendingCollectionV1>[];
  readonly hasNextPage: boolean;
  readonly validUntil: string;
}

/** Prepare the one fixed, read-only request. There is deliberately no cursor or request input. */
export function prepareOpenSeaTrendingRequest(): Readonly<OpenSeaTrendingRequestV1> {
  if (arguments.length !== 0) fail("INPUT_INVALID");
  return Object.freeze({
    accept: "application/json",
    contractReviewDate: OPENSEA_TRENDING_CONTRACT_REVIEW_DATE,
    contractVersion: OPENSEA_TRENDING_CONTRACT_VERSION,
    credentialHeader: "x-api-key",
    maximumResponseBytes: OPENSEA_TRENDING_MAXIMUM_BYTES,
    maximumResults: OPENSEA_TRENDING_MAXIMUM_RESULTS,
    method: "GET",
    operation: "opensea.trending-collections.v1",
    origin: OPENSEA_TRENDING_ORIGIN,
    path: OPENSEA_TRENDING_PATH,
    query: OPENSEA_TRENDING_QUERY,
    redirect: "reject",
    retryAttempts: 0,
    timeoutMs: OPENSEA_TRENDING_TIMEOUT_MS,
    url: OPENSEA_TRENDING_URL,
  });
}

/**
 * Validate the exact reviewed wire response and return only collection identity. Provider text,
 * URLs, flags, and pagination material remain quarantined and are never included in the result.
 */
export function parseOpenSeaTrendingResponse(
  bytes: unknown,
  acquiredAtValue: unknown,
): Readonly<OpenSeaTrendingEvidenceV1> {
  const acquiredAt = parsePlain(TimestampSchema, acquiredAtValue);
  const response = parseJsonBytes(TrendingResponseSchema, bytes, OPENSEA_TRENDING_MAXIMUM_BYTES);
  const slugs = response.collections.map((collection) => collection.collection);
  if (new Set(slugs).size !== slugs.length) fail("RESPONSE_INVALID");

  const acquiredTime = Date.parse(acquiredAt);
  const validUntilTime = acquiredTime + OPENSEA_TRENDING_VALIDITY_MS;
  if (!Number.isFinite(validUntilTime)) fail("INPUT_INVALID");

  return deepFreeze({
    acquiredAt,
    collections: response.collections.map((collection, index) => {
      const baseAddresses = collection.contracts.map((contract) => contract.address.toLowerCase());
      if (new Set(baseAddresses).size !== baseAddresses.length) fail("RESPONSE_INVALID");
      return {
        baseAddresses,
        rank: index + 1,
        slug: collection.collection,
      };
    }),
    hasNextPage: response.next !== undefined,
    validUntil: new Date(validUntilTime).toISOString(),
  });
}
