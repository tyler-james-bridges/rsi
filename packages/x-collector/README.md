# `@rsi/x-collector`

A credential-injected, read-only collector for one X API v2 operation: recent Post search. It has no posting, liking, following, Direct Message, account-write, payment, pagination, retry, or arbitrary-request capability.

## Pinned one-request API contract

The contract was reviewed against official X documentation and its published OpenAPI description on 2026-08-25. `X_RECENT_SEARCH_API_CONTRACT_VERSION` identifies the reviewed dialect.

| Property                 | Fixed value                                        |
| ------------------------ | -------------------------------------------------- |
| Method                   | `GET`                                              |
| Origin                   | `https://api.x.com`                                |
| Path                     | `/2/tweets/search/recent`                          |
| Maximum results          | `max_results=10`                                   |
| Ordering                 | `sort_order=recency`                               |
| Fields and expansions    | None                                               |
| Pagination input/follow  | None                                               |
| Reviewed maximum reserve | `50000` USD micro-units ($0.05 for ten Post reads) |

The caller supplies only a closed `{ query }` object. RSI enforces a 1–512 character, nonblank, control-character-free query. Unknown properties are rejected, including `maxResults`, `nextToken`, `paginationToken`, time ranges, fields, expansions, URL, method, headers, and redirect controls. The package always emits exactly the three query parameters `query`, `max_results=10`, and `sort_order=recency`.

The [Search Posts Recent reference](https://docs.x.com/x-api/posts/search-recent-posts) and [OpenAPI contract](https://docs.x.com/openapi.json) identify the endpoint and app-only Bearer authentication. X's [search overview](https://docs.x.com/x-api/posts/search/introduction) and [query guide](https://docs.x.com/x-api/posts/search/integrate/build-a-query) specify the 512-character self-serve query limit. With no explicit time range, X's [pagination guide](https://docs.x.com/x-api/posts/search/integrate/paginate) says recent search covers the last seven days and ends approximately thirty seconds before the request.

X's current first-party pages disagree about `post.fields` versus `tweet.fields` and the corresponding edit-history names. This contract avoids that unstable surface by sending neither fields nor expansions. The response boundary trusts only `id` and `text`; it permits either documented edit-history spelling as optional validated drift and projects neither spelling into trusted data. A response containing both dialects fails closed.

The [application-only authentication guide](https://docs.x.com/fundamentals/authentication/oauth-2-0/application-only) describes Bearer Token use for server-to-server, read-only public-data access and says tokens must be treated like passwords and used over HTTPS. The [X IDs guide](https://docs.x.com/fundamentals/x-ids) says v2 IDs are strings; the parser preserves bounded decimal IDs as strings.

## API

```ts
import { createXRecentSearchCollector, parseXRecentSearchResponse } from "@rsi/x-collector";

const collector = createXRecentSearchCollector({
  attemptAuthorization,
  bearerToken: keychainInjectedBearerToken,
  runtimeAuthorization,
});

const raw = await collector.collectRaw({
  query: '"example collection" -is:retweet',
});

// raw.copyBytes() remains untrusted and quarantined here.
// Production orchestration must place these bytes in @rsi/vault before writing
// any durable metadata or event.
const typed = parseXRecentSearchResponse(raw);
```

Collectors are branded in a module-private `WeakSet` by the closed factory. `isXRecentSearchCollector` rejects structural clones and lookalikes, allowing the ingestion boundary to fail before egress if a caller tries to bypass factory validation. The production package entry accepts no fetch or clock injection; tests use the explicit `@rsi/x-collector/testing` entry or replay stores rather than wrapping the collector object.

`collectRaw` never parses JSON. It returns defensive-copy raw bytes plus bounded metadata: endpoint, request fingerprint, response hash, byte count, status, content type, canonical UTC `acquiredAt`, fixed result limit, provenance, and optional structured rate-limit data. JSON serialization emits only that metadata and a `"quarantined"` marker; it omits the canonical request and research query.

Only the three documented rate headers are read: `x-rate-limit-limit`, `x-rate-limit-remaining`, and `x-rate-limit-reset`. They must be either wholly absent or wholly present as canonical safe integers with `0 <= remaining <= limit`. The raw header names and values are never retained. The immutable receipt projection is `{ limit, remaining, resetAtUnixSeconds }`. X documents these headers in its [rate-limit reference](https://docs.x.com/x-api/fundamentals/rate-limits); it does not document a per-response billing header.

`parseXRecentSearchResponse` is a separate trust-boundary operation. It requires a closed response containing `meta.result_count`, zero to ten unique `{ id, text }` Posts, consistent newest/oldest IDs for nonzero results, and at most one bounded opaque `meta.next_token`. Absent `data` is accepted only when `result_count` is zero. A nonempty `errors` array raises `PARTIAL_RESPONSE`, leaving the source bytes in quarantine rather than presenting partial data as complete. `next_token` can be recorded as provenance, but this package has no parameter or loop capable of using it.

## Cost and authorization boundary

X's [current pricing page](https://docs.x.com/x-api/getting-started/pricing) lists Post reads at $0.005 per returned resource and says prices can change. Ten Post reads therefore have a reviewed maximum charge of $0.05, represented as `50000` USD micro-units. Every live call requires both a genuine revision-bound runtime `research_collection` authorization and a genuine fully funded durable attempt authorization. Both bind the same attempt, expiry, operation, and prepared request fingerprint before egress. The collector consumes the attempt and invokes its sole fetch from inside the runtime authorization's synchronous SQLite-locked dispatch callback, so another process cannot persist STOP between the final runtime check and dispatch. A pricing or contract change requires a deliberate version and reserve review before another live call.

Transport invocation is irreversible. If the runtime transaction fails to commit after fetch has
already launched, the collector still awaits the response through bounded quarantine and destroys
it before reporting the runtime failure. This prevents an abandoned response promise while keeping
the missing durable runtime audit fail-closed.

## Synthetic fixtures and replay

The callable collector has no live recording mode. A live paid response can only leave quarantine through the encrypted capture boundary; it cannot be copied into an injected cassette sink. Tests build explicitly synthetic cassettes offline and seed a read-only replay source:

```ts
const request = prepareRecentSearchRequest({ query: "fictional example" });
const synthetic = quarantineNetworkResponse(
  request,
  200,
  "application/json",
  fictionalBytes,
  fixedFixtureTime,
);
const cassettes = new MemoryCassetteStore([createXRecentSearchCassette(request, synthetic)]);

const replay = createXRecentSearchCollector({
  mode: "replay",
  cassetteStore: cassettes,
});
const replayed = await replay.collectRaw({ query: "fictional example" });
```

Replay configuration rejects both credentials and fetch implementations, so a replay cannot fall through to the network. Cassettes are keyed by a SHA-256 fingerprint of a credential-free canonical request and bind the exact response bytes, response hash, content metadata, optional structured rate-limit receipt, and canonical `acquiredAt` with an integrity hash. Replay revalidates the closed envelope, pinned request, base64 encoding, all hashes, timestamp, byte length, and rate-limit invariants before returning byte-identical quarantine data.

Only an in-memory synthetic-fixture store is included. There is no network recorder or automatic plaintext filesystem recorder. Committed fixtures must be fictional and credential-free. Authorization headers are never part of canonical requests, quarantines, errors, or cassettes; a network body that echoes the injected token is refused before quarantine.

## Transport boundary

The collector builds its own `Request`, sends only `GET`, sets `Accept`, `Accept-Encoding: identity`, and `Authorization`, omits ambient credentials, and uses `redirect: "error"`. It rejects any non-identity content encoding so native fetch cannot compare a decompressed body against a compressed wire `Content-Length`. It also rejects redirect statuses, redirected/final-URL responses, non-200 statuses, non-allowlisted media types, invalid or excessive declared lengths, and streamed bodies that cross the configured byte limit. A private abort controller covers both response establishment and streaming; callers may also provide an `AbortSignal`.

Every authorized collection performs exactly one transport dispatch. There is no automatic retry for 429 or transient 5xx responses, and no pagination follow-up. Transport errors and response bodies are never copied into errors.

Tests use only the test-only transport factory, injected fetch functions, and Web streams. They do not contact X or any other network service.
