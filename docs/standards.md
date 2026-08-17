# Standards profile

> [!IMPORTANT]
> These standards describe future integration options. Under the active
> [Observer v1 production-readiness contract](./production-readiness/v1/README.md),
> AgentCash, x402, ERC-8004, ERC-8257, ERC-4337, EIP-712 execution, Robinhood, and
> marketplace-write components remain disabled placeholders.

RSI deliberately keeps the standards surface small. Draft standards are version-pinned behind adapters so their future changes do not leak through the system.

## Adopt

| Standard                                            | RSI usage                                                                                                                                            |
| --------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004) | Public agent identity and reputation/validation references. Registration and feedback are evidence, not authorization.                               |
| [ERC-8257](https://eips.ethereum.org/EIPS/eip-8257) | Publish individual HTTPS tools with origin/manifest commitments, access predicates, and x402 compatibility. Registry discovery does not imply trust. |
| [EIP-712](https://eips.ethereum.org/EIPS/eip-712)   | Domain-separated policy, strategy, and execution-intent signatures with RSI-supplied nonce, expiry, and duplicate protection.                        |
| [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) | Existing audited smart account with revocable, expiring, target/function-scoped agent permissions and hard spending limits.                          |

## Inherit rather than implement

- [ERC-1271](https://eips.ethereum.org/EIPS/eip-1271) through the selected smart account.
- [EIP-3009](https://eips.ethereum.org/EIPS/eip-3009) and ERC-2612/Permit2 behavior through the selected x402 SDK, token, and facilitator.
- ERC-20, ERC-721, ERC-1155, and ERC-165 through assets and protocols RSI consumes.

## Borrow concepts; do not depend yet

- ERC-8196: action/contract allowlists, per-transaction/day limits, validity, revocation, and audit vocabulary.
- ERC-8199: detached wallet, time gates, and owner recovery.
- ERC-8217: optional public Hoodinal-to-agent identity narrative, never funded-wallet control.

## Defer or reject for the MVP

- ERC-8001 until independently controlled agents need public multiparty coordination.
- ERC-8126 until RSI consumes external agent-verification providers.
- ERC-8183 until asynchronous escrowed jobs are more useful than immediate x402 calls.
- ERC-8273 until target applications actually enforce the attestations.
- EIP-7702 because RSI starts with a dedicated smart account rather than delegating a human EOA.
- ERC-6551 for treasury custody because transfer or theft of the controlling NFT can transfer control.
- Subscription NFTs, a protocol token, governance, custom vaults, and custom marketplace contracts.

## Contract decision

RSI v0 deploys **zero custom contracts**. Any future proposal must demonstrate a trustless ownership, exchange, composability, censorship-resistance, or permanent-commitment requirement that existing infrastructure cannot satisfy.
