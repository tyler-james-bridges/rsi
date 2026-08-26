# `@rsi/opensea-collector`

A one-shot, read-only collector for OpenSea's Base trending-collections endpoint. It has no wallet,
signer, trade, approval, transfer, payment, arbitrary-request, pagination, retry, redirect, or SDK
capability.

## Fixed request

| Property                       | Fixed value                                                             |
| ------------------------------ | ----------------------------------------------------------------------- |
| Method                         | `GET`                                                                   |
| Origin                         | `https://api.opensea.io`                                                |
| Path                           | `/api/v2/collections/trending`                                          |
| Query                          | `timeframe=one_day&chains=base&limit=10`                                |
| Authentication                 | `x-api-key`                                                             |
| Maximum results                | `10`                                                                    |
| Retries, redirects, pagination | `0`                                                                     |
| Provider charge                | Not established by the reviewed endpoint contract; collector cannot pay |
| Ledger reserve                 | `1` USD micro-unit (minimum nonzero accounting floor)                   |

The caller supplies no request input. `collectRaw()` builds the exact request, sends only
`Accept: application/json`, `Accept-Encoding: identity`, and the injected API key, and rejects a
provider request for payment with a distinct `PAYMENT_REQUIRED` error. The authorization reserve of
`1` USD micro-unit is RSI's minimum nonzero ledger floor for one request, not a provider charge
estimate. This collector cannot satisfy a `402` or make any x402 payment.

An authenticated `200` must include the complete documented `x-ratelimit-limit`,
`x-ratelimit-remaining`, and `x-ratelimit-reset` receipt. Missing, partial, malformed, or
internally inconsistent success metadata fails closed.

Every live request requires genuine one-shot authorizations from both `@rsi/operations` and the
runtime `research_collection` boundary. Both are bound to operation
`opensea.trending-collections.v1`, the marketplace plane and lane, a shared expiry, and the fixed
request fingerprint before egress.

## Quarantine boundary

Successful bytes remain untrusted in a branded, destroyable quarantine. JSON serialization exposes
only bounded metadata and a `"quarantined"` marker. The separate
`parseOpenSeaTrendingQuarantine()` boundary delegates to the reviewed source-contract parser and
keeps only:

- acquisition and validity timestamps;
- one-based rank and a bounded collection slug;
- normalized Base contract addresses;
- whether the discarded provider response included a pagination cursor.

Quarantine metadata also retains the genuine consumed `NetworkAttemptDispatchReceipt`. Its complete
attempt/session binding and dispatch timestamp distinguish otherwise byte-identical responses from
different authorized attempts. Ingestion must authenticate this receipt and match every field to
the designated durable operations store before capture or publication.

Provider prose, links, usernames, feature flags, and the cursor itself never enter the trusted
projection. Only verified, enabled, non-NSFW collections with Base contracts pass the parser. These
provider safety fields are filters, not independent proof that a collection is safe to trade.

The production entry exposes no quarantine factory. Encrypted-capture recovery must first
authenticate Vault bytes against capture-registry provenance inside ingestion, then invoke the
strict source-contract parser while retaining and wiping the bytes in that boundary. A matching
request fingerprint alone is not proof that bytes came from the network.

Tests use `@rsi/opensea-collector/testing` for an injected offline transport and clock. The
production entry exposes neither hook, and the test suite performs no live network calls.
