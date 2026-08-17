# RSI architecture

> [!IMPORTANT]
> This document describes RSI's longer-term architecture. The active
> [Observer v1 production-readiness contract](./production-readiness/v1/README.md)
> is authoritative for the current release. Every payment, wallet, transaction, and
> execution component shown below is inactive and out of scope for Observer.

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

`@rsi/domain` encodes the object as EIP-712 typed data. The kernel allowlists the recipient, persists used intent IDs and nonces, and requires a fresh OpenSea observation carrying the exact order hash. A future signer must still independently reconstruct the order, verify the EIP-712 digest, simulate it, and revalidate state immediately before broadcast.

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

The local foundation now uses a transactional SQLite event log. Each event commits to its canonical payload, sequence, predecessor hash, type, aggregate, idempotency key, and timestamp. A metadata head makes direct edits, reordering, and tail deletion detectable on reopen. Duplicate retries return the original event only when the complete request is identical; conflicting reuse fails closed.

The event store can be checkpointed into a separate, hash-linked journal. Each checkpoint signs the exact SQLite head sequence and hash with an injected Ed25519 key, and the verifier checks every historical anchor against the current store. The external-anchor package wraps those signed checkpoints in a separately authorized profile/retention envelope, queues immutable publication records, verifies an independently pinned suffix, and rejects rollback. Its current provider is an offline simulation: a real B2 Object Lock bucket, credentials, and two-device verification remain deployment and drill work.

The policy read/decide/append step runs inside one SQLite `BEGIN IMMEDIATE` transaction. A clean restart rebuilds intent-ID, nonce, and daily-spend state from approved decisions, and multiple local writers sharing that database cannot approve from stale snapshots. This does not coordinate separate database copies or hosts; a future distributed executor still requires one durable authorization authority.

The recorded-fixture policy pipeline does not persist raw fixture files. The X ingestion path sends exact response bytes into an ephemeral AES-256-GCM vault before typed parsing. Each capture has an opaque random identifier and fresh data key; metadata is encrypted with the body, while a separate profile-bound encrypted registry binds the request attempt and private source identifiers. Durable events receive only closed operational counts, timestamps, statuses, and opaque identifiers. Session cleanup destroys capture keys and index material, writes content-free deletion evidence, and reconciles pending or orphaned state after restart. The operator projection and every future transaction component must never read the vault or registry.

Recovery is split deliberately. The state-evidence component signs checkpoint, event-head, schema, release, and runbook evidence but is not itself restorable history. The sanitized event archive preserves and verifies every allowed production event from genesis. The signed release bundle preserves the allowlisted source, lockfile, configuration schemas, runbooks, recovery procedure, SBOM, and test summary. A genuine-store local controller cross-checks all three verification reports and supplies their exact statuses and hashes to lifecycle acceptance. The production command that assembles and verifies both physical copies is still pending.

The X collector pins one endpoint-specific recent-search contract and exposes only live and replay modes. Live mode accepts a bearer credential only through construction, consumes one exact reserved attempt, issues `GET` only to the exact X origin/path, requests identity encoding, refuses compression and redirects, bounds time and decoded response size, and quarantines bytes before parsing. No live recording/cassette sink exists; synthetic cassettes are constructed offline for replay tests. The encrypt-first ingestion boundary accepts live or replay collectors and routes every live body through Vault v2. Because the current official X pages disagree on `post.fields` versus older `tweet.fields` terminology, a real credentialed canary is required before moving the adapter from `quarantined` to `approved`.

The operator service binds to IPv4 loopback, serves fixed same-origin dashboard assets, rejects foreign Host/Origin values, and recursively removes known sensitive field names. Its optional controls accept only a closed local lifecycle vocabulary from a genuine provider; without that provider the surface is read-only. That projection is defense in depth, not a secret-management system: providers must never place credentials or hostile raw content anywhere in response objects.
