# RSI architecture

## Objective

RSI is one public character composed of separate capability domains. It can improve research and strategy while an independently controlled safety kernel constrains money movement.

The first product is an AI agent service, not a new protocol. Agent reasoning, research, indexing, evaluation, and memory remain offchain. Existing standards and marketplaces handle identity, payments, wallets, assets, and settlement.

## Trust boundaries

```text
┌──────────────────────────── UNTRUSTED ────────────────────────────┐
│ X posts │ webpages │ NFT metadata │ MCP/x402 output │ manifests │
└──────────────────────────────┬────────────────────────────────────┘
                               │ bytes only
                               ▼
                    Quarantine collector
                    - no wallet
                    - no tool installation
                    - no execution credentials
                               │
                               ▼ strict extraction
                      Append-only evidence graph
                               │
                               ▼
                    Mutable RSI strategy/harness
                               │ unsigned typed intent
┌──────────────────────────────┴────────────────────────────────────┐
│                    NON-SELF-MODIFYING KERNEL                      │
│ schema │ provenance │ freshness │ exact assets │ caps │ nonce   │
│ allowlists │ simulation requirement │ duplicate guard │ shutdown │
└──────────────────────────────┬────────────────────────────────────┘
                               │ PolicyApproval
                               ▼
                       Exclusive executor
                ┌──────────────┼───────────────┐
                ▼              ▼               ▼
        ERC-4337 wallet   Robinhood Trading   Banking MCP
        OpenSea / chain   Agentic account     approved checkout
```

Raw posts, HTML, images, OCR, natural-language model output, tool descriptions, and provider-supplied calldata never cross into the executor.

## Processes and privileges

| Process              | May read                                                | May write                             | Explicitly cannot                                       |
| -------------------- | ------------------------------------------------------- | ------------------------------------- | ------------------------------------------------------- |
| Quarantine collector | Public sources and approved provider responses          | Raw snapshot store                    | Invoke tools discovered in content, access signers      |
| Claim extractor      | Quarantined snapshots                                   | Typed claims                          | Emit calldata, destinations, approvals, or instructions |
| Evidence builder     | Typed claims and canonical reads                        | Evidence graph                        | Trade or change policy                                  |
| Strategist           | Evidence and redacted outcomes                          | Unsigned intent and strategy proposal | Sign, execute, add allowlists, raise caps               |
| Policy kernel        | Typed intent, evidence, immutable policy, spend ledger  | Approval/rejection receipt            | Interpret natural language or accept unknown fields     |
| Executor             | `PolicyApproval` and pinned adapter configuration       | One scoped external action            | Research, install tools, alter policy, retry freely     |
| Evaluator            | Append-only observations, decisions, receipts, outcomes | Candidate score                       | Trade, erase incidents, rewrite its own test suite      |

## Intent boundary

The first executable domain object is an NFT purchase intent. It commits to:

- strategy and policy versions;
- policy hash;
- exact chain, marketplace target, collection, token ID, payment asset, recipient, order hash, and maximum outflow;
- evidence IDs;
- unique nonce and expiry.

`@rsi/domain` encodes the object as EIP-712 typed data. A future signer must independently reconstruct the order, verify the EIP-712 digest, simulate it, and revalidate state immediately before broadcast.

## Recursive-improvement boundary

The mutable strategy currently contains only source weights, opportunity threshold, holding period, exit rules, and search terms. Candidate changes move through:

```text
proposed → adversarial replay passed → live canary → evaluated → promoted
     └──────────────── any safety regression ───────────────→ rejected
```

The strategy patch schema intentionally has no wallet, credential, policy, allowlist, cap, evaluator, logging, or adapter-activation fields.

## Chain and account model

- **Base:** likely home for AgentCash/x402 payments and an ERC-8004 identity because of ecosystem support.
- **Robinhood Chain:** candidate first NFT execution environment, using a fresh ERC-4337 smart account and OpenSea-compatible settlement.
- **Robinhood brokerage:** separate custodial Agentic Trading account for an optional equities sleeve.
- **Robinhood Banking:** separate approved-purchase fallback for vendors without x402.

These are separate money domains. The UI may aggregate public performance, but keys, credentials, balances, limits, and execution workers remain isolated. Supporting multiple chains does not mean activating multiple live chains at launch; RSI starts with one explicitly approved execution chain.

## Storage model

The first persistent implementation should use an append-only SQLite event log locally, with content-addressed raw snapshots stored separately. Every derived claim, decision, execution receipt, outcome, strategy proposal, and promotion points back to immutable hashes. Public reporting can reveal hashes, timestamps, decisions, costs, and results without leaking credentials or sensitive brokerage data.
