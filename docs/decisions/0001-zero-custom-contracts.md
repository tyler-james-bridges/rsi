# ADR 0001: Zero custom contracts in RSI v0

- Status: accepted
- Date: 2026-08-11

## Context

RSI needs agent identity, paid HTTP tools, constrained wallet execution, NFT settlement, and public provenance. Existing systems already provide ERC-8004 registries, ERC-8257 tool publication, x402 settlement, ERC-4337 accounts, ERC-721/1155 assets, and OpenSea/Seaport settlement.

Agent reasoning, research, scoring, indexing, evaluation, and recursive harness changes are mutable offchain concerns. Encoding them in Solidity would increase cost and audit surface without producing a new trust guarantee.

## Decision

RSI v0 deploys no custom smart contract. It integrates existing infrastructure through version-pinned adapters and keeps its policy kernel offchain while also relying on hard wallet-level constraints before live autonomy.

## Consequences

- The first build can focus on evidence integrity, policy, key isolation, simulation, reconciliation, and evaluation.
- The repository avoids pretending that a custom contract automatically makes an AI agent safe.
- Some rules initially depend on the local policy gateway. Before live autonomous use, the smart account/session-key implementation must duplicate critical spend and target constraints.
- A future contract requires a new ADR explaining the missing trust guarantee and its state-transition callers, incentives, tests, audit, deployment, and recovery path.
