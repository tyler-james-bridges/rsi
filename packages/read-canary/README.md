# `@rsi/read-canary`

`@rsi/read-canary` contains separate commissioning boundaries for RSI's supervised provider reads.
The root entry owns the code-reviewed X recent-search plan and the `@rsi/read-canary/opensea`
subpath owns one fixed Base trending-collections plan. Neither provider request is caller-defined,
and neither public projection exposes raw provider content.

A fixed authenticated event-store key is the durable singleton claim. Competing request IDs,
controller instances, and process restarts cannot create a second dispatch from the same canary
state. A crash never auto-retries a dispatched request.

The controller consumes a process- and revision-bound `research_collection` authorization at the
collector's final egress seam, consumes one durable X network attempt, encrypts the response before
parsing, and emits a strict receipt without post text, URLs, source identifiers, headers, or
credentials. It never retries or follows a pagination token. Runtime authorization holds its
cross-process write lock across both the transport invocation and the later content-free result
checkpoint, so STOP and completion have defined winners.

The durable completion order is result checkpoint, exact attempt closure, Vault key destruction,
authenticated capture-registry tombstone, then public receipt. Startup first repairs the Vault and
registry seam, then finishes any claimed canary entirely from authenticated local state. Recovery
has no bearer-token or collector dependency and cannot issue a second request. A captured receipt is
not trusted until the exact runtime audit, capture event, result checkpoint, closure facts, and
verified key-destruction state agree.

The X singleton was commissioned once on 2026-08-25 and remains consumed. The OpenSea singleton is
implemented and offline-verified but uncommissioned. Each provider uses distinct fixed macOS
Keychain services; no credential may be accepted through command-line arguments, environment
variables, dashboard fields, or repository files.

The distinct `@rsi/read-canary/opensea` entry point applies the same durable, one-shot lifecycle to
the code-owned Base trending-collections request. Its public plan and receipt contain no collection
slugs, contract addresses, Vault capture identifiers, API key material, or provider response data.
Recovery is storage-only: it accepts no API key or collector and cannot perform network egress.
Non-capture failures receive a strict content-free checkpoint before attempt closure, pending-capture
cleanup, or receipt publication. Full registry/Vault reconciliation must then prove that no
unregistered encrypted capture remains before a receipt can publish, so restart recovery preserves
the exact failure classification and sanitized rate-limit facts without retrying the provider
request.
