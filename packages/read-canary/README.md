# `@rsi/read-canary`

`@rsi/read-canary` contains three separate commissioning boundaries for RSI's supervised provider
reads. No provider request is caller-defined, and no public projection exposes raw provider
content.

## Export boundaries

| Import                               | Contents                                                                                                   |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------- |
| `@rsi/read-canary`                   | Fixed X plan, schemas, types, projection helpers, and live one-shot controller                             |
| `@rsi/read-canary/opensea`           | Fixed OpenSea Base trending plan, schemas, types, projection helpers, and live one-shot controller         |
| `@rsi/read-canary/base-rpc`          | Fixed Base Mainnet finalized-anchor plan, schemas, types, projection helpers, and live one-shot controller |
| `@rsi/read-canary/base-rpc-recovery` | Base RPC receipt type plus credentialless, collectorless storage-only recovery                             |

The Base RPC live entry exports the exact plan constants, including plan ID, request fingerprint,
RPC method set, limits, method-set acknowledgement, and internal ledger reserve; the strict command
and receipt schemas; the content-free projection reader; and `BaseRpcReadCanaryController`. The
recovery entry exports only `recoverBaseRpcReadCanary`, its options type, and the receipt type. Keep
recovery imports on that separate entry so its graph cannot gain a collector, credential host, or
network path.

## One-shot lifecycle

A fixed authenticated event-store key is the durable singleton claim. Competing request IDs,
controller instances, and process restarts cannot create a second dispatch from the same canary
state. A crash never auto-retries a dispatched request.

The controller consumes a process- and revision-bound `research_collection` authorization at the
collector's final egress seam, consumes one durable network attempt, encrypts the response before
parsing, and emits a strict receipt without provider content, URLs, source identifiers, headers, or
credentials. It never retries, follows pagination, selects an alternate provider, or invokes a
payment path. Runtime authorization holds its cross-process write lock across both the transport
invocation and the later content-free result checkpoint, so STOP and completion have defined
winners.

The durable completion order is result checkpoint, exact attempt closure, Vault key destruction,
authenticated capture-registry tombstone, then public receipt. Startup first repairs the Vault and
registry seam, then finishes any claimed canary entirely from authenticated local state. Recovery
has no provider credential or collector dependency and cannot issue a second request. A captured
receipt is not trusted until the exact runtime audit, capture event, result checkpoint, closure
facts, and verified key-destruction state agree.

The distinct `@rsi/read-canary/opensea` entry applies this lifecycle to one code-owned Base
trending-collections request. Its public plan and receipt contain no collection slugs, contract
addresses, Vault capture identifiers, API-key material, or provider response data. Non-capture
failures receive a strict content-free checkpoint before attempt closure, pending-capture cleanup,
or receipt publication.

The distinct `@rsi/read-canary/base-rpc` entry applies it to one code-owned Base Mainnet JSON-RPC
batch containing only `eth_chainId` and `eth_getBlockByNumber("finalized", false)`. The receipt
contains no block number, hash, parent hash, JSON-RPC ID, provider header, quota value, raw content,
capture ID, attempt ID, or request UUID. `providerReportedFinalized` is not independent finality or
canonical-chain proof.

## Commissioning state

- X was commissioned once on 2026-08-25 and remains consumed. Its historical durable receipt still
  requires a separately authorized, receipt-verifying permanent-marker backfill.
- OpenSea is implemented and offline-verified but uncommissioned.
- Base RPC is implemented and offline-verified but uncommissioned.

The providers use distinct fixed Keychain accounts. No credential may be accepted through command
arguments, environment variables, dashboard fields, repository files, chat, screenshots, or
livestream output.

All Stage 1 production operators require exactly Node `24.19.0` and pnpm `11.20.0`, use code-owned
storage, and bind only to `127.0.0.1:8787`. X, OpenSea, Base RPC, and the X marker backfill share one
owner-only Stage 1 profile lock acquired before storage, recovery, or Keychain access. Graceful
`SIGINT`/`SIGTERM` shutdown releases it only after the operator has fully closed. Abrupt process
termination such as `SIGKILL` leaves the lock artifact in place while the OS remains running. Any
artifact retained after a host crash receives the same fail-closed treatment, and no startup may
auto-delete it. Acquisition synchronizes the lock file and containing directory before continuing;
the `SIGKILL` regression is a live-OS test, not a hardware power-loss simulation.

Run exactly one Stage 1 action at a time. Never work around an occupied port or lock refusal with an
alternate port, path, or second checkout. Before manually recovering a retained lock, first prove
that no RSI process remains; restart the Mac if that proof is uncertain. Stage 0 is separate: its
development state belongs under `.local/stage0/` and it is refused access to canonical Stage 1
storage.

Starting a Stage 1 operator may inspect Keychain presence and read storage keys for recovery, but
it does not itself authorize a provider request. Entering `RESEARCH` also does not authorize a
request. The one-shot dashboard submission is a separate explicit live-request boundary.

Follow the [Stage 1 commissioning
runbook](../../docs/production-readiness/commissioning-runbook.md) for safe Keychain provisioning,
the X marker backfill, and the separate OpenSea and Base RPC authorization ceremonies.
