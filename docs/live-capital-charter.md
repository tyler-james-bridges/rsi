# Live-capital charter

> [!IMPORTANT]
> This charter does not grant current authority. The active
> [single-machine production path](./production-readiness/README.md) controls staged
> activation. The current code has no commissioned live adapter, wallet integration,
> transaction builder, wallet signer, or live-capital path.

RSI is designed to learn with real economic consequences. Historical replay is a security test, not a fake portfolio. Live operation begins only when every activation field below is explicitly set and reviewed.

## Objective ordering

1. Zero hard-invariant escapes.
2. Survival and bounded drawdown.
3. Calibrated, provenance-backed research.
4. Net realized P&L after gas, royalties, x402, inference, failed transactions, and slippage.
5. Speed.

Profit never compensates for violating a higher-ranked objective.

## Capital domains

| Domain                    | Purpose                         | Required isolation                                                                                          |
| ------------------------- | ------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| Research payment wallet   | AgentCash/x402 paid reads       | Dedicated low-balance software account; hard call/provider/day caps; no arbitrary transfers or trading      |
| NFT execution wallet      | Approved marketplace settlement | Separate low-balance software account; the owner confirms every transaction in the wallet UI                |
| Treasury/recovery         | Survival reserve and recovery   | Remains outside RSI; a primary personal wallet is never connected                                           |
| Robinhood Agentic Trading | Optional equities sleeve        | Separate credentials, a dedicated low-balance account, and one policy-gated connection if commissioned      |
| Robinhood Banking         | Optional non-x402 fallback      | Separate credentials, per-purchase human confirmation, and a deliberately low local ceiling if commissioned |

The two wallet accounts are software accounts on the owner's existing Mac. They are separate keys and money domains, but no additional computer or special signing device is required. No primary human wallet, primary brokerage account, or primary credit card becomes an RSI executor.

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
- Approved wallet UI and confirmation workflow: **UNSET**
- Emergency-stop authority: **UNSET**

The executor cannot start while any required value is unset. Human confirmation is required for every transaction; it is not replaced by a monetary threshold.

## Accounting

- Every deposit, withdrawal, fee, payment, order, failed transaction, realized sale, and valuation update receives an append-only receipt.
- External capital additions are reported separately from earned P&L. They never masquerade as RSI performance.
- NFT NAV uses executable unrelated bids after fees. Assets without trustworthy bids receive a conservative or zero liquidation value.
- Public summaries redact credentials, account numbers, card details, private provider payloads, and sensitive anti-abuse information.

## Autonomy ladder

1. Read-only evidence collection.
2. Paid research within tiny provider caps.
3. Unsigned action proposals.
4. Human-confirmed live transactions from the dedicated execution wallet.
5. Optional ERC-4337 bounded-automation canaries for a pre-approved asset universe.
6. Broader autonomy only after measured safety and calibration evidence.

Skipping a rung requires a separate explicit decision and new threat review.
