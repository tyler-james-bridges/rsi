# `@rsi/credential-host`

This package is the fixed macOS Keychain boundary for the supervised X read canary. It invokes only
`/usr/bin/security find-generic-password` against four code-owned canary service names and the fixed
`rsi-stage1-x-read-canary` account. Secret
values are never accepted through arguments, environment variables, configuration files, or
operator requests.

The production host has a zero-argument constructor. Executor and platform substitution are
available only from the explicit `@rsi/credential-host/testing` entry. Restart recovery uses
`withStorageSecrets`, which reads only the three local state keys and never reveals the X bearer.

Presence checks omit `-w`. Commissioning reads use `-w`, enforce an 8 KiB output ceiling, and never
interpret stderr. The host clears the original `execFile` buffers, executor handoff buffers, Base64
decode buffers, and temporary state-key arrays. Callback key views are cleared after both success and
failure. Only the Keychain item-not-found exit status is reported as `missing`; timeouts, execution
failures, malformed results, and other exit statuses are `unavailable`.

Secret properties are non-enumerable, so accidental JSON serialization or object spread emits no
credential material. Bearer text necessarily exists briefly in process memory while Node builds the
Authorization header; JavaScript strings cannot be overwritten in place. The live controller is
one-shot and releases its reference after the call.
