# Base RPC provider contract review — 2026-09-05

Status: offline implementation evidence only. No Alchemy credential was read, no Keychain command was run, and no Base RPC request was sent during this review.

## Reviewed primary sources

- [Base RPC overview](https://docs.base.org/base-chain/api-reference/rpc-overview)
- [Base `eth_getBlockByNumber`](https://docs.base.org/base-chain/api-reference/ethereum-json-rpc-api/eth_getBlockByNumber)
- [Base transaction finality](https://docs.base.org/specifications/transactions/transaction-finality)
- [Alchemy HTTP header authentication](https://www.alchemy.com/docs/how-to-use-api-keys-in-http-headers)
- [Alchemy API-key security practices](https://www.alchemy.com/docs/best-practices-for-key-security-and-management)
- [Alchemy JSON-RPC batch requests](https://www.alchemy.com/docs/reference/batch-requests)
- [Alchemy throughput and HTTP 429 behavior](https://www.alchemy.com/docs/reference/throughput)

## Public-documentation recheck — 2026-09-07

Status: **live Base commissioning blocked**. This was an unauthenticated, read-only documentation
review. No Alchemy account, credential, Keychain item, or RPC endpoint was accessed.

The fixed destination and request remain supported by Alchemy's
[Base endpoint directory](https://www.alchemy.com/docs/reference/node-supported-chains),
[Bearer-header authentication guide](https://www.alchemy.com/docs/how-to-use-api-keys-in-http-headers),
Base's
[`eth_chainId` reference](https://docs.base.org/base-chain/api-reference/ethereum-json-rpc-api/eth_chainId),
Base's
[`eth_getBlockByNumber` reference](https://docs.base.org/base-chain/api-reference/ethereum-json-rpc-api/eth_getBlockByNumber),
and Alchemy's [batch-request guide](https://www.alchemy.com/docs/reference/batch-requests).

Public documentation does not, however, establish an internally consistent Alchemy-on-Base
response contract. Alchemy's
[Base-specific `eth_getBlockByNumber` page](https://www.alchemy.com/docs/chains/base/base-api-endpoints/eth-get-block-by-number)
uses the Base endpoint but presents an example with proof-of-work values and withdrawals that
contradict Base's documented proof-of-stake invariants. Separately, Base's current block field list
and example omit `totalDifficulty`, while the general
[Ethereum JSON-RPC reference](https://ethereum.org/developers/docs/apis/json-rpc/) and Alchemy
examples include it. That omission is not evidence that the field is absent and does not authorize
weakening RSI's parser. `totalDifficulty` remains required and must remain `0x0`.

Because a response-shape failure consumes RSI's permanent one-shot attempt, do not authorize or
execute the Base canary until a dated review records reliable Alchemy-on-Base response-shape
confirmation. Unblocking requires either corrected or explicit official Alchemy documentation, or
separately authorized sanitized compatibility evidence reviewed before execution.

Alchemy's [compute-unit schedule](https://www.alchemy.com/docs/reference/compute-unit-costs)
currently assigns zero billable compute units and five throughput compute units to `eth_chainId`,
and 20 compute units to `eth_getBlockByNumber`. Its
[pricing-plan documentation](https://www.alchemy.com/docs/reference/pricing-plans) and
[public pricing page](https://www.alchemy.com/pricing) disagree on the free-tier throughput figure.
Do not encode either public figure as an account limit; the owner must still review the actual
account quota and billing state before any future authorization.

## Fixed RSI request

The canary owns one request and accepts no destination, method, parameter, body, retry, redirect, or provider input:

- network: Base Mainnet, chain ID `8453` (`0x2105`);
- URL: `https://base-mainnet.g.alchemy.com/v2` with no query or fragment;
- authentication: `Authorization: Bearer <dedicated Base read key>`; the key is never placed in the URL;
- method: one HTTP `POST` with `Content-Type: application/json` and identity response encoding;
- JSON-RPC batch: exactly `eth_chainId` with `[]` and `eth_getBlockByNumber` with `["finalized", false]`;
- retries, redirects, fallbacks, pagination, payment, and x402: unavailable;
- timeout: 10 seconds;
- response limit: 1 MiB.

The batch is one HTTP attempt, not two independently corroborating providers. Batch response order may vary. HTTP 200 is insufficient: both expected IDs must be present exactly once and each item must contain a valid `result`, not an error or null result.

## Acceptance policy

RSI accepts only a strict, reviewed Base block shape and fails closed on unknown response fields or fork-shape drift. It verifies the Base chain ID, canonical quantities and hashes, a nonzero block number, Base proof-of-stake invariants represented by the response, and a block timestamp no later than acquisition and no more than two hours old.

The two-hour limit is an RSI operational freshness policy, not a provider promise. A successful response is labeled `providerReportedFinalized`; it is not described as independently proven canonical finality. Any later trading or policy dependency requires a separate decision about independent provider or L1 corroboration.

Private authenticated storage may retain the block number as a recovery identifier. Public projections and receipts must not expose block number, block hash, parent hash, JSON-RPC IDs, provider headers, quota state, or raw response content.

## Mismatch and drift handling

| Concern              | Provider documentation                                                            | RSI behavior                                                                                                |
| -------------------- | --------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| API-key placement    | Alchemy documents URL and header forms and recommends headers for better secrecy. | Header-only Bearer authentication at the fixed `/v2` path. URL-key forms fail closed.                       |
| Batch reliability    | Alchemy supports batches and notes operational tradeoffs.                         | One fixed two-method batch, no retry or fallback.                                                           |
| Finality             | Base supports the `finalized` block tag.                                          | Records only a provider assertion plus a local freshness verdict.                                           |
| Rate limits          | Limits are account/tier dependent and HTTP 429 signals throttling.                | 429 is terminal for this one shot. No current dollar-price or quota claim is encoded.                       |
| Response evolution   | Block fields can evolve with network upgrades.                                    | Unknown or unreviewed shapes fail closed pending a dated contract review.                                   |
| DNS and network path | HTTPS authenticates the configured hostname under the host trust store.           | Destination and redirects are pinned, but this canary does not claim independent DNS/IP-path corroboration. |

## Still unproven

- No dedicated Alchemy Base application or credential has been commissioned for this canary.
- The strict block shape has not been compared with a live account response.
- Current account-specific throughput and quota headers are unknown and deliberately absent from the public contract.
- The one-shot production operator, permanent claim boundary, and authority mutation gate pass offline with mocked host executors. Their real Keychain and provider behavior remains uncommissioned and requires separate live evidence.

Any live validation is a separately authorized one-shot production action. A schema mismatch consumes the attempt and is reviewed offline; it does not trigger a retry.
