import {
  AtomicAmountSchema,
  Bytes32Schema,
  EvmAddressSchema,
  NftAssetSchema,
  TimestampSchema,
  XStableIdSchema,
} from "@rsi/domain";
import { z } from "zod";

const HttpUrlSchema = z
  .string()
  .min(1)
  .max(2_048)
  .url()
  .refine((value) => {
    const protocol = new URL(value).protocol;
    return protocol === "http:" || protocol === "https:";
  }, "only HTTP(S) URLs are accepted");

const ProviderOriginSchema = HttpUrlSchema.refine((value) => {
  const url = new URL(value);
  return (
    url.protocol === "https:" &&
    url.username.length === 0 &&
    url.password.length === 0 &&
    url.pathname === "/" &&
    url.search.length === 0 &&
    url.hash.length === 0
  );
}, "providerOrigin must be an HTTPS origin without credentials, path, query, or fragment");

const ProviderIdSchema = z.string().regex(/^[a-zA-Z0-9._-]{1,128}$/);

export const RedirectHopSchema = z
  .object({
    statusCode: z.number().int().min(300).max(399),
    location: HttpUrlSchema,
  })
  .strict();

export const RecordedLinkSchema = z
  .object({
    observedUrl: HttpUrlSchema,
    redirects: z.array(RedirectHopSchema).max(10).default([]),
  })
  .strict();

export const XAuthorSnapshotSchema = z
  .object({
    authorId: XStableIdSchema,
    handle: z.string().regex(/^[A-Za-z0-9_]{1,15}$/),
    accountCreatedAt: TimestampSchema,
    followersCount: z.number().int().nonnegative().max(1_000_000_000).nullable(),
    followingCount: z.number().int().nonnegative().max(1_000_000_000).nullable(),
    postsCount: z.number().int().nonnegative().max(10_000_000_000).nullable(),
    verified: z.boolean(),
    previousHandles: z
      .array(z.string().regex(/^[A-Za-z0-9_]{1,15}$/))
      .max(20)
      .default([]),
  })
  .strict();

const XSourceSchema = z
  .object({
    kind: z.literal("x"),
    providerId: ProviderIdSchema,
    providerOrigin: ProviderOriginSchema.optional(),
  })
  .strict();

const OpenSeaSourceSchema = z
  .object({
    kind: z.literal("opensea"),
    providerId: ProviderIdSchema,
    providerOrigin: ProviderOriginSchema.optional(),
  })
  .strict();

const OnchainSourceSchema = z
  .object({
    kind: z.literal("onchain"),
    providerId: ProviderIdSchema,
    providerOrigin: ProviderOriginSchema.optional(),
  })
  .strict();

const SocialClaimSchema = z
  .object({
    type: z.enum(["market_momentum", "risk_indicator"]),
    asset: NftAssetSchema,
    confidence: z.number().min(0).max(1),
  })
  .strict();

const CanonicalClaimSchema = z
  .object({
    type: z.enum(["collection_identity", "ownership", "listing", "executable_bid"]),
    asset: NftAssetSchema,
    confidence: z.number().min(0).max(1),
  })
  .strict();

function addTemporalChecks<T extends z.ZodTypeAny>(schema: T): T {
  return schema.superRefine((value, context) => {
    const candidate = value as {
      acquiredAt?: string;
      validUntil?: string;
    };
    if (
      candidate.acquiredAt !== undefined &&
      candidate.validUntil !== undefined &&
      Date.parse(candidate.validUntil) <= Date.parse(candidate.acquiredAt)
    ) {
      context.addIssue({
        code: "custom",
        message: "validUntil must be later than acquiredAt",
        path: ["validUntil"],
      });
    }
  }) as T;
}

export const XPostFixtureSchema = addTemporalChecks(
  z
    .object({
      fixtureVersion: z.literal("rsi.fixture.v1"),
      fixtureType: z.literal("x-post"),
      source: XSourceSchema,
      acquiredAt: TimestampSchema,
      validUntil: TimestampSchema,
      post: z
        .object({
          postId: XStableIdSchema,
          author: XAuthorSnapshotSchema,
          createdAt: TimestampSchema,
          editHistoryIds: z.array(XStableIdSchema).max(100).default([]),
          text: z.string().min(1).max(16_000),
          links: z.array(RecordedLinkSchema).max(25).default([]),
        })
        .strict(),
      claim: SocialClaimSchema,
    })
    .strict(),
).superRefine((fixture, context) => {
  if (Date.parse(fixture.post.createdAt) > Date.parse(fixture.acquiredAt)) {
    context.addIssue({
      code: "custom",
      message: "post.createdAt must not be later than acquiredAt",
      path: ["post", "createdAt"],
    });
  }
});

export const OpenSeaFixtureSchema = addTemporalChecks(
  z
    .object({
      fixtureVersion: z.literal("rsi.fixture.v1"),
      fixtureType: z.literal("opensea-record"),
      source: OpenSeaSourceSchema,
      acquiredAt: TimestampSchema,
      validUntil: TimestampSchema,
      record: z
        .object({
          recordId: z.string().min(1).max(256),
          observedAt: TimestampSchema,
          marketplace: z.literal("opensea"),
          claim: CanonicalClaimSchema,
          orderHash: Bytes32Schema.optional(),
          maker: EvmAddressSchema.optional(),
          links: z.array(RecordedLinkSchema).max(25).default([]),
        })
        .strict(),
    })
    .strict(),
).superRefine((fixture, context) => {
  if (Date.parse(fixture.record.observedAt) > Date.parse(fixture.acquiredAt)) {
    context.addIssue({
      code: "custom",
      message: "record.observedAt must not be later than acquiredAt",
      path: ["record", "observedAt"],
    });
  }
});

export const OnchainFixtureSchema = addTemporalChecks(
  z
    .object({
      fixtureVersion: z.literal("rsi.fixture.v1"),
      fixtureType: z.literal("onchain-record"),
      source: OnchainSourceSchema,
      acquiredAt: TimestampSchema,
      validUntil: TimestampSchema,
      record: z
        .object({
          chainId: z.number().int().positive(),
          blockNumber: AtomicAmountSchema,
          blockHash: Bytes32Schema,
          blockTimestamp: TimestampSchema,
          transactionHash: Bytes32Schema.optional(),
          logIndex: z.number().int().nonnegative().optional(),
          claim: CanonicalClaimSchema,
        })
        .strict()
        .superRefine((record, context) => {
          if (record.chainId !== record.claim.asset.chainId) {
            context.addIssue({
              code: "custom",
              message: "record chainId must match claim asset chainId",
              path: ["claim", "asset", "chainId"],
            });
          }
        }),
    })
    .strict(),
).superRefine((fixture, context) => {
  if (Date.parse(fixture.record.blockTimestamp) > Date.parse(fixture.acquiredAt)) {
    context.addIssue({
      code: "custom",
      message: "record.blockTimestamp must not be later than acquiredAt",
      path: ["record", "blockTimestamp"],
    });
  }
});

export const ResearchFixtureSchema = z.union([
  XPostFixtureSchema,
  OpenSeaFixtureSchema,
  OnchainFixtureSchema,
]);

export type RecordedLink = z.infer<typeof RecordedLinkSchema>;
export type XPostFixture = z.infer<typeof XPostFixtureSchema>;
export type OpenSeaFixture = z.infer<typeof OpenSeaFixtureSchema>;
export type OnchainFixture = z.infer<typeof OnchainFixtureSchema>;
export type ResearchFixture = z.infer<typeof ResearchFixtureSchema>;
