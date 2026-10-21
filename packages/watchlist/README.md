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
order. Slugs and addresses cannot repeat across groups. Addresses normalize to lowercase and
sort before hashing. `validUntil` must be exactly 120 seconds after `acquiredAt`.

A contract-set change creates a new group. A slug change does not change group identity, but does
change snapshot identity. `left_window` renders as "left the observed list", not a deletion,
delisting, or sale. Pagination sets the partial indicator. Freshness is evaluated at read time.

## History and confirmation

The independent hash-chained event history accepts at most 1,000 snapshots and displays twenty
headers. New snapshots require the previewed head and increasing acquisition time. Exact retries
require the original snapshot and predecessor, and return the original import time without another
event. A fresh preview of an already imported snapshot names a different predecessor and is not
an exact retry. Refresh and choose a newer acquisition to continue.

Confirmation reparses the input and binds its digest to the previewed runtime process and revision.
A one-shot `watchlist_import` permit records its receipt before the protected synchronous commit.
STOP either wins the runtime lock and prevents import, or follows the complete watchlist transaction.
Reopen verifies the event hash chain and semantic history before serving a view.

Hash chains cannot detect replacing the entire database with an older valid copy. Offline input
cannot prove provider origin, durable marketplace identity, prices, returns, or current availability.
See [ADR 0002](../../docs/decisions/0002-offline-base-watchlist.md) for the accepted contract.
