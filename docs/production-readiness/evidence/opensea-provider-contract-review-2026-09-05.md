# OpenSea provider-contract review — 2026-09-05

## Scope and outcome

This was a read-only review of current first-party OpenSea documentation and OpenSea's published
OpenAPI mirror. It did not create, access, reveal, rotate, or use an OpenSea API key and did not
send a request to an OpenSea API endpoint. It did not commission RSI's OpenSea canary or grant any
continuing provider authority.

The reviewed endpoint remains available, and RSI's fixed request still matches its documented
method, origin, path, and parameters:

```text
GET https://api.opensea.io/api/v2/collections/trending?timeframe=one_day&chains=base&limit=10
```

## Reviewed provider facts

- `one_day` is a supported timeframe, `chains` is a comma-separated chain filter, `base` is a
  supported chain identifier, and `limit=10` is inside the documented `1` to `100` range. OpenSea
  promises composite-score ordering specifically for `one_day` without a chain filter; RSI does
  not claim composite-score ordering for this Base-filtered request.
- Public marketplace reads require `x-api-key`. They do not require a wallet bearer token. OpenSea
  documents an unauthenticated instant-key creation endpoint whose free-tier keys expire after
  seven days, plus a Developer-settings flow for full API keys. Neither flow was used in this
  review.
- OpenSea publishes no per-request monetary price, billing header, x402 requirement, or HTTP `402`
  behavior for this REST read. Its instant key is described as free-tier and quota-limited. RSI's
  one-USD-micro ledger reserve is therefore a local nonzero accounting slot, not an OpenSea price;
  the provider charge remains unreported.
- OpenSea documents token-bucket rate limiting shared by all API keys on one account. Authenticated
  responses include `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset`, with the
  reset expressed as Unix seconds. A `429` response also includes `Retry-After`. Published example
  limits may change, so RSI does not hardcode them.
- A successful response contains a required `collections` array and optional string `next`. Each
  collection requires `collection`, `name`, `safelist_status`, `is_disabled`, `is_nsfw`,
  `trait_offers_enabled`, `collection_offers_enabled`, `opensea_url`, and `contracts`. Each contract
  requires string `address` and `chain`. The other eleven documented collection-metadata fields are
  optional and accept either a string or `null`. The response does not include sales-volume or
  trending-score metrics.
- OpenSea announced the trending-collections endpoint on 2026-05-13. The 2026-05-07 removal notice
  concerns legacy order endpoints and collection-stat fields, not this endpoint. No current
  deprecation or migration notice was found for the trending-collections endpoint.

## Public-documentation recheck — 2026-09-07

Status: **no public-documentation blocker found**. This was another unauthenticated, read-only
review; it did not access an OpenSea account, credential, Keychain item, or API endpoint.

The endpoint, parameters, Base chain identifier, `x-api-key` authentication, and documented
response shape remain compatible with RSI's fixed one-request contract. The relevant subset of
OpenSea's current published OpenAPI at commit
[`14a6bb3`](https://github.com/ProjectOpenSea/api-types/blob/14a6bb34f24dc0cdc50c09b4901e9c87aea4d66a/opensea-api.json)
is semantically unchanged from the pinned 2026-09-05 review. Public quota examples remain advisory,
and the actual account limit and provider charge remain unknown until separately authorized account
review. This recheck does not commission the canary or grant credential or provider access.

## Deliberate RSI narrowings

RSI's parser is an intentionally stricter local acceptance policy, not a verbatim model of every
payload permitted by OpenSea's machine schema. It additionally:

- rejects unknown object properties and applies local length and character bounds;
- limits the response to ten unique collection slugs;
- requires one to sixteen unique, valid EVM addresses per collection and requires every returned
  contract entry to name Base;
- requires `safelist_status = "verified"`, `is_disabled = false`, and `is_nsfw = false`;
- bounds the optional cursor and discards its value;
- accepts only its reviewed JSON content types even though OpenSea's success media type is
  published as `*/*` and JSON is documented as the default; and
- applies local response-size, timeout, no-redirect, no-retry, no-pagination, identity-encoding,
  and freshness rules that OpenSea does not guarantee.

These restrictions remain fail-closed. This review changed their provenance date and description,
not their runtime behavior.

## Official sources

- <https://docs.opensea.io/reference/get_trending_collections>
- <https://docs.opensea.io/reference/api-overview>
- <https://docs.opensea.io/reference/api-keys>
- <https://docs.opensea.io/reference/llms-agent-discovery>
- <https://docs.opensea.io/changelog/new-api-endpoints>
- <https://docs.opensea.io/changelog/removing-deprecated-rest-api-endpoints-and-response-fields>
- <https://github.com/ProjectOpenSea/api-types/blob/359960022b293c4375e33f9962eea9a5802e5dfe/opensea-api.json>
