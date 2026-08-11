# Live-capital charter

RSI is designed to learn with real economic consequences. Historical replay is a security test, not a fake portfolio. Live operation begins only when every activation field below is explicitly set and reviewed.

## Objective ordering

1. Zero hard-invariant escapes.
2. Survival and bounded drawdown.
3. Calibrated, provenance-backed research.
4. Net realized P&L after gas, royalties, x402, inference, failed transactions, and slippage.
5. Speed.

Profit never compensates for violating a higher-ranked objective.

## Capital domains

| Domain                    | Purpose                         | Required isolation                                                                |
| ------------------------- | ------------------------------- | --------------------------------------------------------------------------------- |
| Research payment wallet   | AgentCash/x402 paid reads       | Separate key and daily/provider caps; cannot trade or transfer arbitrarily        |
| NFT execution wallet      | Approved marketplace settlement | Fresh ERC-4337 account, scoped session key, no bridge/withdraw/arbitrary approval |
| Treasury/recovery         | Survival reserve and recovery   | Human-controlled multisig; agent cannot access it                                 |
| Robinhood Agentic Trading | Optional equities sleeve        | Dedicated funded account; one policy-gated MCP connection                         |
| Robinhood Banking         | Non-x402 checkout fallback      | Dedicated virtual card, per-purchase approval, low monthly ceiling                |

No primary human wallet, primary brokerage account, or primary credit card becomes an RSI executor.

## Activation sheet

These values intentionally remain unset in source control:

- Initial deposited bankroll: **UNSET**
- Survival reserve percentage: **UNSET**
- Maximum NFT transaction: **UNSET**
- Maximum daily NFT spend: **UNSET**
- Maximum research call/provider/day: **UNSET**
- Maximum live-canary allocation: **UNSET**
- Maximum daily loss and total drawdown: **UNSET**
- Approved chain, marketplace deployment, selectors, collections, and payment assets: **UNSET**
- Human approval threshold and emergency authority: **UNSET**

The executor cannot start while any required value is unset.

## Accounting

- Every deposit, withdrawal, fee, payment, order, failed transaction, realized sale, and valuation update receives an append-only receipt.
- External capital additions are reported separately from earned P&L. They never masquerade as RSI performance.
- NFT NAV uses executable unrelated bids after fees. Assets without trustworthy bids receive a conservative or zero liquidation value.
- Public summaries redact credentials, account numbers, card details, private provider payloads, and sensitive anti-abuse information.

## Autonomy ladder

1. Read-only evidence collection.
2. Paid research within tiny provider caps.
3. Unsigned action proposals.
4. Human-approved live transactions.
5. Autonomous live canaries for a pre-approved asset universe.
6. Broader autonomy only after measured safety and calibration evidence.

Skipping a rung requires a separate explicit decision and new threat review.
