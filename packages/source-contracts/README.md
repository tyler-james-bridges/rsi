# RSI marketplace and chain source contracts

`@rsi/source-contracts` is an offline-only Stage A package. It contains no `fetch`, WebSocket,
credential, environment-variable, retry, provider SDK, or filesystem implementation. It prepares
credential-free request descriptors and validates bounded synthetic response fixtures so later
commissioning has an exact contract to test before any transport can be enabled.

The OpenSea contract was reviewed against the official v2 Get Order and Stream documentation on
2026-08-15. REST is the confirming source; Stream is a provisional collection trigger only. The
current fixture normalization deliberately excludes metadata, media, URLs, makers, signatures,
free-form text, and every write/trading endpoint. It binds Base asset identity, active order hash,
protocol, price, start/end time, and the 120-second freshness ceiling. A future quarantined adapter
must map the then-current raw provider schema to this exact record and destroy the raw capture; this
package does not silently assume that the fixture is a live response.

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

- <https://docs.opensea.io/reference/get_order>
- <https://docs.opensea.io/docs/stream-real-time-events>
- <https://www.alchemy.com/docs/reference/node-supported-chains>
- <https://docs.base.org/base-chain/api-reference/rpc-overview>
- <https://docs.robinhood.com/chain/connecting/>
