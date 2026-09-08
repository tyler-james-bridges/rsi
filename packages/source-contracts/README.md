# RSI marketplace and chain source contracts

`@rsi/source-contracts` is an offline-only safety package. It contains no `fetch`, WebSocket,
credential, environment-variable, retry, provider SDK, or filesystem implementation. It prepares
credential-free request descriptors and validates bounded response bytes or synthetic fixtures so
later commissioning has an exact contract to test before any transport can be enabled.

## OpenSea trending collections

`@rsi/source-contracts/opensea-trending` is the live-wire, read-only request and acceptance
contract reviewed against the official OpenSea API v2 OpenAPI description on 2026-09-05. The
[public provider-contract review](../../docs/production-readiness/evidence/opensea-provider-contract-review-2026-09-05.md)
records the official sources and the distinction between OpenSea's schema and RSI's local policy.
The contract can prepare exactly one request:

```text
GET https://api.opensea.io/api/v2/collections/trending?timeframe=one_day&chains=base&limit=10
```

The origin, path, and fixed ordered query are exported separately; the URL is composed from those
three constants so no caller can confuse query parameters with a path or supply its own query.
The descriptor names `x-api-key` as the credential header but never accepts or contains a
credential. It has no request input, cursor input, retry, pagination, order, token-ID, wallet,
payment, or execution capability. The strict response parser applies RSI's intentionally narrower
acceptance policy over the documented `CollectionResponse` field set. OpenSea does not publish
RSI's extra string bounds, exact-property rule, uniqueness requirements, contract-count limit, or
Base-only contract-array guarantee. RSI deliberately fails closed outside those local bounds,
requires at most ten unique collection slugs, one to sixteen valid Base contract addresses per
collection, and requires every collection to be verified, enabled, and non-NSFW. Provider text,
metadata, media, URLs, feature flags, and the optional cursor are discarded. The trusted result
contains only rank, slug, normalized Base addresses, acquisition and expiry timestamps, and
whether a valid cursor was present.

## Base Mainnet finalized anchor

`@rsi/source-contracts/base-rpc-anchor` is a separate live-wire request and acceptance contract for
one signer-blind Base Mainnet check. It owns one exact JSON-RPC batch:

```text
POST https://base-mainnet.g.alchemy.com/v2
eth_chainId([])
eth_getBlockByNumber(["finalized", false])
```

The descriptor contains no credential and accepts no URL, method, parameter, block-tag, provider,
retry, fallback, payment, wallet, or transaction input. Its strict parser accepts both expected
response IDs exactly once, verifies chain ID `8453`, rejects JSON-RPC errors and unknown block
fields, and applies a two-hour local freshness limit. Private block number and hash access is
available only through an authentic branded anchor; generic serialization projects only a
content-free `providerReportedFinalized` claim. That label records one provider's response to the
`finalized` tag and is not independent finality proof. The dated
[provider-contract review](../../docs/production-readiness/evidence/base-rpc-provider-contract-review-2026-09-05.md)
records the upstream facts and deliberate local narrowings.

## Legacy OpenSea fixtures

`@rsi/source-contracts/legacy-opensea-fixtures` contains the old synthetic, normalized Get Order
and Stream fixtures reviewed on 2026-08-15. They are **legacy synthetic/non-live** schemas: they do
not describe live OpenSea wire responses and are intentionally absent from the package root and
the trending contract. They exclude metadata, media, URLs, makers, signatures, free-form text, and
write/trading endpoints. Nothing may use them as a parser for trending-collections responses.

The canonical-chain contract prepares `eth_getBlockByNumber("finalized", false)` and a second
block-number-pinned batch containing only block-hash revalidation, `eth_getCode`, ERC-165, and
ERC-721 `ownerOf` or ERC-1155 `balanceOf`. It binds runtime bytecode to an approved SHA-256 and
proves the EIP-1967 implementation slot is either empty or equals an explicitly approved
implementation with its own approved bytecode hash. An empty EIP-1967 slot is not represented as a
general “non-proxy” claim; other proxy patterns stay unavailable until an explicit resolver exists.
It never calls `tokenURI`, metadata, media, transactions, wallets, or state-changing methods. Base
is bound to chain ID 8453 and Robinhood Chain to 4663. Because the identity reads are pinned to the
finalized historical block rather than current state, the request descriptor requires
archive-capable access; it never silently falls back to `latest`.
Provider support and the meaning/timing of `finalized` must still be proven during a separately
approved canary; fixture success is not that proof.

Official references:

- <https://docs.opensea.io/reference/get_trending_collections>
- <https://docs.opensea.io/reference/get_order>
- <https://docs.opensea.io/docs/stream-real-time-events>
- <https://www.alchemy.com/docs/reference/node-supported-chains>
- <https://docs.base.org/base-chain/api-reference/rpc-overview>
- <https://docs.robinhood.com/chain/connecting/>
