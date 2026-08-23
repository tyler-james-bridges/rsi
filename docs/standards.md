# Standards profile

> [!IMPORTANT]
> These standards describe future integration options. Under the active
> [single-machine production path](./production-readiness/README.md), the current code
> has no commissioned live adapter, wallet integration, transaction builder, or wallet
> signer. Standards do not activate capabilities.

RSI deliberately keeps the standards surface small. Draft standards are version-pinned behind adapters so their future changes do not leak through the system.

## Integration order

1. **AgentCash/x402 paid research first.** Use deployed payment infrastructure with the dedicated low-balance research wallet, wallet-native human confirmation for the initial canary, and hard origin, payee, asset, network, price, attempt, and daily caps. RSI deploys no payment contract.
2. **EIP-712 exact intents.** Domain-separated policy, strategy, and future execution-intent signatures bind RSI-supplied nonces, expiry, and duplicate protection. Any future transaction still requires confirmation in the separate execution wallet's UI.
3. **ERC-4337 only as an optional later control.** Consider an existing audited account implementation only after supervised results justify bounded automation and its revocable, expiring, target/function-scoped permissions and spending limits are independently verified.
4. **ERC-8004 only after a stable public endpoint exists.** Registration and reputation may support discovery, but identity, feedback, and usage are evidence—not authorization.
5. **ERC-8257 remains optional.** Adopt it only if publishing individual HTTPS tools with pinned origin and manifest commitments creates concrete value. Registry discovery never implies trust.

## Inherit rather than implement

- [ERC-1271](https://eips.ethereum.org/EIPS/eip-1271) through a selected smart account only if the optional ERC-4337 stage is reached.
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
- EIP-7702 because persistent EOA delegation adds authority before RSI has evidence that bounded automation is useful.
- ERC-6551 for treasury custody because transfer or theft of the controlling NFT can transfer control.
- Subscription NFTs, a protocol token, governance, custom vaults, and custom marketplace contracts.

## Contract decision

RSI v0 deploys **zero custom contracts**. Any future proposal must demonstrate a trustless ownership, exchange, composability, censorship-resistance, or permanent-commitment requirement that existing infrastructure cannot satisfy.
