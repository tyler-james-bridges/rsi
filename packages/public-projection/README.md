# RSI public projection

`@rsi/public-projection` defines the offline, content-free public artifact boundary. It never
collects data, accesses credentials, publishes, deploys, or calls a provider.

An unsigned candidate contains only random identifiers, environment, permitted release hashes,
counts, aggregate micro-dollar cost, closed verification statuses, and qualification progress. A
receipt cannot be signed until at least 24 hours after session acceptance and an explicit local
approval is supplied. Signed receipts, corrections, and tombstones form one Ed25519-authenticated
predecessor chain.

`verifyPublicArtifactChain` is browser-compatible through an injected WebCrypto adapter. Any schema,
hash, signature, sequence, predecessor, pin, correction, or tombstone failure returns only
`UNVERIFIED`; the viewer must not render partially trusted fields.

This package does not provision R2, Cloudflare Pages, DNS, a public key pin, or the separate
`rsi-observer-web` repository. Those remain later explicit checkpoints.
