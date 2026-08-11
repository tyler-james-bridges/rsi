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

The event store can now be checkpointed into a separate, hash-linked journal. Each checkpoint signs the exact SQLite head sequence and hash with an injected Ed25519 key, and the verifier checks every historical anchor against the current store. Retaining the newest journal head independently detects journal suffix deletion. This is portable authenticated evidence, not yet a production external anchor: the repository does not publish the trusted head to another system, and replacing the database, journal, and locally retained head together remains possible.

The policy read/decide/append step runs inside one SQLite `BEGIN IMMEDIATE` transaction. A clean restart rebuilds intent-ID, nonce, and daily-spend state from approved decisions, and multiple local writers sharing that database cannot approve from stale snapshots. This does not coordinate separate database copies or hosts; a future distributed executor still requires one durable authorization authority.

The recorded-fixture policy pipeline does not persist its raw fixture files. The new X ingestion path instead sends exact response bytes into a dedicated content-addressed AES-256-GCM vault before typed parsing. Vault metadata is encrypted with the body, and SQLite receives only hashes, sizes, fixed provenance values, counts, and a safe failure code. The operator projection and future transaction signer must never read this vault. Key custody, rotation, recovery, and independent backup remain deployment work.

The X collector pins one endpoint-specific recent-search contract and exposes live, record, and replay modes. Live/record accept a bearer credential only through construction, issue GET requests only to the exact X origin/path, refuse redirects, bound time and response size, and quarantine bytes before parsing. The encrypt-first ingestion boundary accepts live or replay collectors but refuses record mode because a cassette sink would run before vault storage; the provided recorder is for volatile testing/capture only. Replay is the only mode used by the integrated demo and tests. Because the current official X pages disagree on `post.fields` versus older `tweet.fields` terminology, a real credentialed canary is required before moving the adapter from `quarantined` to `approved`.

The read-only operator service binds to IPv4 loopback by default and recursively removes known sensitive field names. That projection is defense in depth, not a secret-management system: providers must never place credentials or hostile raw content anywhere in public response objects.
