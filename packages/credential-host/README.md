# `@rsi/credential-host`

This package contains separate fixed macOS Keychain boundaries for supervised read canaries. The
root export remains the X boundary. The OpenSea trending boundary is available only through
`@rsi/credential-host/opensea-trending`, with test injection isolated in
`@rsi/credential-host/opensea-trending-testing`.

Each boundary invokes only `/usr/bin/security find-generic-password`. The X host uses its existing
four code-owned services under `rsi-stage1-x-read-canary`. The OpenSea host is separately branded
as `DarwinOpenSeaTrendingKeychain` and uses fixed account
`rsi-stage1-opensea-read-canary`, API-key service `dev.rsi.canary.opensea-read`, and the three
storage-key services `dev.rsi.canary.operations-state`, `dev.rsi.canary.capture-registry`, and
`dev.rsi.canary.vault-wrapping`. Its graph has no X service or bearer access. Secret values are
never accepted through arguments, environment variables, configuration files, or operator
requests.

Both production hosts have zero-argument constructors. Executor and platform substitution are
available only from their explicit testing entries. Restart recovery uses `withStorageSecrets`,
which reads only the three local state keys and never reveals the provider credential.

Presence checks omit `-w`. Commissioning reads use `-w`, enforce an 8 KiB output ceiling, and never
interpret stderr. The host clears the original `execFile` buffers, executor handoff buffers, Base64
decode buffers, and temporary state-key arrays. Callback key views are cleared after both success and
failure. Only the Keychain item-not-found exit status is reported as `missing`; timeouts, execution
failures, malformed results, and other exit statuses are `unavailable`.

Secret properties are non-enumerable, so accidental JSON serialization or object spread emits no
credential material. Bearer or API-key text necessarily exists briefly in process memory while
Node builds the provider header; JavaScript strings cannot be overwritten in place. A live
controller must remain one-shot and release its reference after the call. Package tests use only
injected executors and do not access the actual Keychain.
