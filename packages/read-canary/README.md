# `@rsi/read-canary`

`@rsi/read-canary` is the commissioning boundary for RSI's first supervised live read. It owns one
code-reviewed X recent-search plan and exposes only its content-free fingerprint, request count,
result count, and maximum provider-credit estimate. The raw query is not an operator input or public
projection.

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

The current plan remains uncommissioned until a dedicated app-only X credential and the required
local state keys are present in their fixed macOS Keychain services. No credential may be accepted
through command-line arguments, environment variables, dashboard fields, or repository files.
