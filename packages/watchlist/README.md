# Import an offline Base watchlist

Start `pnpm operator` and open the loopback dashboard. The process starts in `STOPPED`.
Enter `RESEARCH`, choose a local JSON snapshot, and select **Preview offline snapshot**.
Review the digest, predecessor, runtime process, revision, freshness, and changes before selecting
**Confirm exact preview**. The browser sends JSON content, never a local path or provider URL.

For a fictional test, choose `packages/watchlist/fixtures/offline-example.json`. Its timestamp is
historical, so the dashboard labels it stale. The data is operator-supplied and unverified.
It does not prove an OpenSea response, identify a token, or authorize a trade.

The default watchlist database is `rsi-watchlist.sqlite` beside the research database. Use
`--watchlist-db PATH` to select another isolated local file. STOP blocks imports but permits reads.
No reset, delete, fetch, export, payment, credential, or execution command exists.

## Input contract

The JSON envelope contains only the fields shown in the fictional example. It admits at most ten
ranked contract groups and sixteen Base addresses per group. Ranks start at one and follow array
order. Slugs cannot repeat. Addresses cannot repeat within or across groups. Addresses normalize
to lowercase and sort before hashing. `validUntil` must be exactly 120 seconds after `acquiredAt`.
The parser rejects cycles and shared references. Preview also rejects an `acquiredAt` value later
than its trusted evaluation time.

A contract-set change creates a new group. A slug change does not change group identity, but does
change snapshot identity. `left_window` renders as "left the observed list", not a deletion,
delisting, or sale. Pagination sets the partial indicator. Freshness is evaluated at read time.

## History and confirmation

The separate hash-chained event history accepts at most 1,000 snapshots and displays twenty
entries. New snapshots require the previewed head and increasing acquisition time. Exact retries
require the same normalized snapshot and original predecessor, and return the original import time
without another watchlist event. A fresh preview of an already imported snapshot names a different
predecessor and is not an exact retry in the dashboard flow. A direct local API client can submit a
current, self-consistent binding with the original predecessor.

Confirmation reparses the input and binds its digest to the submitted runtime process, revision,
head, and evaluation time. The dashboard resends its latest preview binding, but the server does
not authenticate that `/api/watchlist/preview` issued it. The runtime permit is the authorization
boundary. A new import must have the same fresh or stale classification at the submitted evaluation
time and final checkpoint. If the classification changes, preview again. An exact retry can still
return its stored result after the snapshot becomes stale.

A one-shot `watchlist_import` permit records its receipt before the protected synchronous commit.
The runtime holds its write lock while the watchlist acquires its own. A mandatory checkpoint then
rechecks STOP, process, revision, and expiry before the append. Reopen verifies the event hash chain,
the stored authorization fields, and the semantic history before serving a view. Reopen does not
consult the separate runtime database.

Hash chains cannot detect replacement with an older valid copy or a coherent rewrite by a
malicious same-user process. Offline input cannot prove provider origin, durable marketplace
identity, prices, returns, or current availability. See
[ADR 0002](../../docs/decisions/0002-offline-base-watchlist.md) for the accepted contract.
