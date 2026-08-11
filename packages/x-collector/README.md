# `@rsi/x-collector`

A credential-injected, read-only collector for one X API v2 operation: recent Post search. It has no posting, liking, following, Direct Message, account-write, payment, or arbitrary-request capability.

## Pinned API contract

The contract was reviewed against official X documentation on 2026-08-11. `X_RECENT_SEARCH_API_CONTRACT_VERSION` identifies the reviewed dialect.

| Property              | Fixed value                                                                               |
| --------------------- | ----------------------------------------------------------------------------------------- |
| Method                | `GET`                                                                                     |
| Origin                | `https://api.x.com`                                                                       |
| Path                  | `/2/tweets/search/recent`                                                                 |
| Post fields parameter | `post.fields=id,text,created_at`                                                          |
| Expansion             | `expansions=author_id`                                                                    |
| User fields           | `user.fields=id,name,username,created_at`                                                 |
| Content types         | `application/json` and the two explicit UTF-8 variants exported as `X_JSON_CONTENT_TYPES` |

The caller supplies only a closed `{ query, maxResults?, nextToken? }` object. `query` is bounded by the endpoint's documented 1–4096 range, `maxResults` by 10–100, and `nextToken` by a bounded URL-safe opaque-token grammar. Unknown properties are rejected. URL, method, headers, redirect behavior, expansions, fields, and arbitrary parameters cannot be supplied by a caller.

The endpoint-specific [Search Posts Recent API reference](https://docs.x.com/x-api/posts/search-recent-posts) currently names `post.fields` and models `edit_history_post_ids`. It lists `id`, `text`, and `created_at` as selectable fields; `author_id` is obtained by the fixed author expansion, and edit history is modeled as a default response field.

X's official documentation is internally inconsistent at the review date. The [recent-search quickstart](https://docs.x.com/x-api/posts/search/quickstart/recent-search), [Fields](https://docs.x.com/x-api/fundamentals/fields), [Expansions](https://docs.x.com/x-api/fundamentals/expansions), and [Data Dictionary](https://docs.x.com/x-api/fundamentals/data-dictionary) still show the older `tweet.fields` / `edit_history_tweet_ids` dialect. This package deliberately follows the live endpoint-specific reference and does not silently merge both shapes. The strict parser rejects the legacy key, making documentation or API drift visible. Live compatibility remains unproven until a credentialed canary is run by an authorized operator; a canary result should trigger an explicit contract-version review, never a permissive schema change.

The [application-only authentication guide](https://docs.x.com/fundamentals/authentication/oauth-2-0/application-only) describes Bearer Token use for server-to-server, read-only public-data access and says tokens must be treated like passwords and used over HTTPS. The [X IDs guide](https://docs.x.com/fundamentals/x-ids) says v2 IDs are strings; the parser preserves bounded decimal IDs as strings.

## API

```ts
import {
  MemoryCassetteStore,
  createXRecentSearchCollector,
  parseXRecentSearchResponse,
} from "@rsi/x-collector";

const collector = createXRecentSearchCollector({
  bearerToken: process.env.X_BEARER_TOKEN!,
});

const raw = await collector.collectRaw({
  query: '"example collection" -is:retweet',
  maxResults: 10,
});

// raw.copyBytes() remains untrusted and quarantined here.
// Production orchestration must place these bytes in @rsi/vault before writing
// any durable metadata or event.
const typed = parseXRecentSearchResponse(raw);
```

`collectRaw` never parses JSON. It returns defensive-copy raw bytes plus bounded metadata: endpoint, request fingerprint, response hash, byte count, status, content type, canonical UTC `acquiredAt`, result limit, and provenance. JSON serialization emits only that metadata and a `"quarantined"` marker; it omits the canonical request and research query.

`parseXRecentSearchResponse` is a separate trust-boundary operation. It requires the endpoint-specific closed response shape, string stable IDs, edit history containing the current Post ID, canonical timestamps, exact result counts/newest/oldest IDs, and a one-to-one set correlation between Post `author_id` values and `includes.users`. Author creation must precede the Post, and Post creation must not be later than `acquiredAt`. Partial-error or extra-field responses are rejected rather than laundered into typed evidence.

## Record and replay

Recording is opt-in and storage is injected:

```ts
const cassettes = new MemoryCassetteStore();
const recorder = createXRecentSearchCollector({
  mode: "record",
  bearerToken: process.env.X_BEARER_TOKEN!,
  cassetteStore: cassettes,
});

const recorded = await recorder.collectRaw({ query: "fictional example" });

const replay = createXRecentSearchCollector({
  mode: "replay",
  cassetteStore: cassettes,
});
const replayed = await replay.collectRaw({ query: "fictional example" });
```

Replay configuration rejects both credentials and fetch implementations, so a replay cannot fall through to the network. Cassettes are keyed by a SHA-256 fingerprint of a credential-free canonical request and bind the exact response bytes, response hash, content metadata, and canonical `acquiredAt` with an integrity hash. Replay revalidates the closed envelope, pinned request, base64 encoding, all hashes, timestamp, and byte length before returning byte-identical quarantine data. Exact duplicate writes are idempotent; a changed response for an existing request fingerprint fails closed.

Only an in-memory store is included. There is intentionally no automatic plaintext filesystem recorder. Live response bodies must go through the encrypted `@rsi/vault` before any durable metadata/event is written. Committed fixtures must be fictional and credential-free. Authorization headers are never part of canonical requests, quarantines, errors, or cassettes; a network body that echoes the injected token is refused before quarantine or recording.

## Transport boundary

The collector builds its own `Request`, sends only `GET`, sets only `Accept` and `Authorization`, omits ambient credentials, and uses `redirect: "error"`. It also rejects redirect statuses, redirected/final-URL responses, non-200 statuses, non-allowlisted media types, invalid or excessive declared lengths, and streamed bodies that cross the configured byte limit. A private abort controller covers both response establishment and streaming; callers may also provide an `AbortSignal`. Transport errors and response bodies are never copied into errors.

Tests use only injected fetch functions and Web streams. They do not contact X or any other network service.
