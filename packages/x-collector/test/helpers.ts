import { createXRecentSearchCollector, type XRecentSearchFetch } from "../src/index.js";

export const TEST_BEARER_TOKEN = "test-bearer-token-never-persist-0123456789";
export const ACQUIRED_AT = "2026-08-11T19:20:21.123Z";
export const FIXED_CLOCK = (): Date => new Date(ACQUIRED_AT);

export function validResponseObject(): {
  data: Array<{
    id: string;
    text: string;
    author_id: string;
    created_at: string;
    edit_history_post_ids: string[];
  }>;
  includes: {
    users: Array<{ id: string; name: string; username: string; created_at: string }>;
  };
  meta: {
    result_count: number;
    newest_id: string;
    oldest_id: string;
    next_token: string;
  };
} {
  return {
    data: [
      {
        id: "1900000000000000002",
        text: "A fictional second post for an offline fixture.",
        author_id: "2244994945",
        created_at: "2026-08-11T18:02:03.000Z",
        edit_history_post_ids: ["1899999999999999999", "1900000000000000002"],
      },
      {
        id: "1900000000000000001",
        text: "A fictional first post for an offline fixture.",
        author_id: "783214",
        created_at: "2026-08-11T17:02:03Z",
        edit_history_post_ids: ["1900000000000000001"],
      },
    ],
    includes: {
      users: [
        {
          id: "2244994945",
          name: "Fictional Developer",
          username: "fictional_dev",
          created_at: "2013-12-14T04:35:55.000Z",
        },
        {
          id: "783214",
          name: "Fictional Account",
          username: "fictional_x",
          created_at: "2007-02-20T14:35:54Z",
        },
      ],
    },
    meta: {
      result_count: 2,
      newest_id: "1900000000000000002",
      oldest_id: "1900000000000000001",
      next_token: "ABC_123",
    },
  };
}

export function validResponseBytes(): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(validResponseObject()));
}

export function jsonResponse(
  body: ConstructorParameters<typeof Response>[0] = validResponseBytes(),
  init: ResponseInit = {},
): Response {
  const headers = new Headers(init.headers);
  if (!headers.has("content-type")) headers.set("content-type", "application/json; charset=utf-8");
  return new Response(body, { ...init, headers, status: init.status ?? 200 });
}

export async function quarantineObject(value: unknown) {
  const fetch: XRecentSearchFetch = async () => jsonResponse(JSON.stringify(value));
  return createXRecentSearchCollector({
    bearerToken: TEST_BEARER_TOKEN,
    fetch,
    now: FIXED_CLOCK,
  }).collectRaw({ query: "fictional evidence", maxResults: 10 });
}
