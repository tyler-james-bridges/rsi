# `@rsi/preflight`

Strictly read-only host and runtime observations for RSI profiles. Preflight reports facts and
policy status; it never remediates the host, changes settings, makes network requests, or reads a
credential value.

```bash
pnpm preflight -- --profile production-observer --json
```

The CLI accepts `observer` as a convenience alias but always emits the canonical
`production-observer` profile ID.

A non-ready report exits with status 2. Invalid CLI arguments exit with status 64. The current
clock check intentionally remains `unknown` unless the library caller injects two independent time
references; the CLI does not contact a time server. Canary and production preflight also remain
`unknown` unless the session supervisor injects a currently active wake assertion with a canonical,
positive duration of no more than 120 minutes. Global AC sleep must remain enabled outside those
supervised sessions.

Apple documents the
[AirPlay Receiver UI](https://support.apple.com/guide/mac-help/mchld7e543a0/mac) and a
[managed restriction](https://support.apple.com/guide/deployment/restrictions-for-mac-computers-depba790e53/web),
but those primary references expose no supported read-only CLI status source. The stock Darwin host
therefore reports that fact as unavailable; an approved provisioning/device-management evidence
adapter must inject a boolean before sharing can pass. Preflight never infers the state from an
undocumented preference key.

This snapshot preflight does not detect a clock jump that happens after the report. The session
operations layer must separately latch backward jumps and runtime discontinuities greater than two
seconds; a preflight pass is not evidence that this later control exists.

The Darwin adapter uses `execFile` without a shell, a three-second timeout, a 64 KiB output cap, a
minimal non-secret environment, and fixed absolute command paths. Its command set is limited to:

- `sw_vers`, `id`, `fdesetup`, `socketfilterfw`, `launchctl`, `pmset`, and `df` read operations;
- `security find-generic-password -s ...`, whose exit status alone records Keychain item presence.

The Keychain adapter never passes `-w` or `-g` and discards all command output at the host boundary;
callers receive presence status only. Production callers should store only the sanitized
`PreflightReport`.

Each durable control plane has its own per-profile Keychain service. In particular,
`operations_state`, `capture_registry`, `vault_wrapping`, `external_anchor_state`, `alert_state`,
and `session_state` are distinct keys. They must never be collapsed into a shared state key or
reused across canary and production-observer.

## Volatile reviewed pins

- Node `24.19.0`: current Node 24 LTS archive release reviewed 2026-08-14.
- pnpm `11.20.0`: project package-manager decision Q78/Q163-Q172.
- macOS `26.6.1`: accepted host-hardening baseline; revalidate before provisioning and each release.
