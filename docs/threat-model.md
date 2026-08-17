# Threat model

> [!IMPORTANT]
> This document includes the future execution threat surface. The active
> [Observer v1 threat model](./production-readiness/v1/observer-threat-model.md) and
> [data-retention contract](./production-readiness/v1/data-classification-retention.md)
> govern the current read-only release. Observer has no raw-data forensics-retention
> exception and no capital authority.

## Prime assumption

An attacker can observe RSI's public prompts, queries, scoring logic, wallet activity, livestream narrative, approved collections, and prior strategy updates. They can then manufacture the exact social or tool signal RSI is looking for.

Therefore: **external activity ranks hypotheses; it never grants authority.**

## Hard invariants

- No raw external content reaches a signer or transaction builder.
- A transaction identifies assets by exact chain, contract, and token ID.
- Destination, recipient, payment asset, maximum outflow, order hash, nonce, and expiry are committed before approval.
- Unknown fields fail schema validation.
- New chains, contracts, selectors, providers, tools, redirects, manifests, and proxy implementations fail closed.
- One exclusive executor owns each state-changing capability.
- No arbitrary calls, arbitrary approvals, bridging, withdrawals, leverage, lending, self-trading, or EIP-7702 delegation.
- A strategy cannot edit policy, tests, logs, evaluator, credentials, emergency stop, or incident history.
- Raw snapshot encryption keys and checkpoint signing keys are separate from each other and from every future wallet key.
- A checkpoint is trusted only when its public key, store ID, key ID, and newest independently retained journal head are pinned.

## Threat gates

| Threat                   | Research gate                                                                                                                  | Execution gate                                                                                      |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------- |
| Coordinated shilling     | Cluster stable author IDs, matching text, URLs, timing, contracts, repost networks, and common funding. Count a cluster once.  | Social popularity may rank an opportunity but cannot make it eligible.                              |
| Compromised account      | Track stable author ID, previous handles/domains, historical contract announcements, edits, deletions, and behavioral changes. | A newly announced contract enters quarantine; approved collections retain the only fast lane.       |
| Fake collection or mint  | Resolve exact chain/address through explorer, marketplace, bytecode, proxy, deployer, ownership, and collection history.       | Initially permit approved secondary listings only; no arbitrary mint calldata.                      |
| Wash trading             | Cluster common funders, circular transfers, buy-backs, repeated counterparties, creator-linked wallets, and outliers.          | Mark value to unrelated executable bids after fees, not floor or reported volume.                   |
| Homograph or redirect    | Normalize punycode, detect mixed scripts/confusables, preserve redirect chain, and key identity by stable IDs.                 | Reject registrable-domain changes and addresses compared only in truncated form.                    |
| Edited or stale data     | Hash every captured version; preserve source-observed and capture times; apply a TTL to both.                                  | Re-fetch owner, listing, order, code, manifest, and price immediately before signing.               |
| Prompt/tool injection    | Parse untrusted bytes in a no-tools process into a closed schema. Discard instruction-like and unknown fields.                 | Signer accepts structured fields only and independently constructs calldata.                        |
| Malicious paid provider  | Enforce content type, schema, size, timeout, same-origin redirect, DNS/IP, response hash, and provider budget.                 | Pin network, asset, payee, endpoint, amount, nonce, and deadline. Payment proves payment—not truth. |
| Transaction substitution | Commit to expected economic result and order hash.                                                                             | Decode all order entries and recipients, simulate, then revalidate before broadcast.                |

## Research storage and checkpoint threats

- X bearer credentials are constructor-injected, never accepted in a query, cassette, event, demo output, or vault metadata. The collector rejects redirects and response bodies containing its credential.
- Exact external bytes and their metadata are encrypted before parsing. Malformed data has no retention exception: it follows the same bounded expiry, verified deletion, and content-free error path as every other capture.
- Capture identifiers are opaque random values rather than content hashes. The encrypted registry keeps source identifiers and request bindings outside permanent events, and verified cleanup destroys its per-attempt key material.
- Vault compromise is contained with a dedicated directory, strict permissions, authenticated encryption, per-capture keys, bounded objects, and filesystem identity checks. A same-user process holding a live wrapping key can still decrypt active data, so production deployment requires process and Keychain isolation.
- SQLite's internal hash chain cannot detect replacement with another internally consistent database. Signed checkpoints and the external-anchor verifier can prove an independently pinned suffix, but production still requires real B2 Object Lock publication, separate Mini/MacBook permissions, and recovery drills.
- Recovery archives are intentionally split into state evidence, sanitized event history, and a signed release bundle. No single component may claim complete restoration, and lifecycle acceptance records all three exact archive hashes.

## Tool activation

Every adapter or discovered tool is classified as `read_only`, `paid_read`, `state_changing`, or `forbidden`.

ERC-8004 registration, ERC-8257 publication, MCP discovery, an x402 receipt, reputation, verification, or high usage does not activate a tool. Activation requires human review, pinned endpoint/origin, pinned manifest and implementation hashes where applicable, a strict schema, capability assignment, price and retry limits, and an adversarial fixture.

## Adversarial regression corpus

Before any candidate strategy receives a live canary, replay at least:

- coordinated shill swarm;
- compromised previously trusted account;
- edited contract address;
- fake mint and copied collection;
- Unicode-confusable domain;
- cross-domain redirect and DNS rebinding;
- wash-trade ring;
- hostile NFT metadata and indirect prompt injection;
- ERC-8257 manifest hash or creator change;
- x402 payee, asset, network, unit, or price substitution;
- malformed/oversized paid response;
- stale listing and filled/cancelled order;
- duplicate intent and retry storm;
- incorrect USDC decimal conversion;
- Seaport recipient or consideration substitution.

The target prompt/tool injection escape rate is exactly zero.

## Circuit breakers

Immediately stop new intents when any of these occurs:

- policy hash or strategy provenance mismatch;
- duplicate execution or unexplained receipt;
- manifest, proxy implementation, creator, payee, or contract-code change;
- identity, chain, asset, ownership, price, or order ambiguity;
- daily spend, loss, drawdown, provider budget, or failed-transaction threshold;
- abnormal coordination cluster or trusted-source behavior change;
- signer, brokerage connection, or account-access anomaly.

Kill sequence: stop intake → cancel and verify pending orders → revoke session keys/card access → disconnect custodial adapters → reconcile balances, positions, receipts, and public state.
