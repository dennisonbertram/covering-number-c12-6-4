# X/Twitter recency follow-up for \(C(12,6,4)\)

Checked at `2026-07-24T15:56:42Z` using the connected X API v2 search
endpoint.

## Exact recent query

Archive mode: `recent` (the API's seven-day recent-search window)

```text
("C(12,6,4)" OR "C(12, 6, 4)" OR "12,6,4 covering" OR
"covering number 41") -is:retweet
```

Result:

```json
{"posts":[],"next_token":null,"result_count":0}
```

A second semantic-variant recent query also returned zero posts:

```text
("covering design" OR "covering number")
("12 6 4" OR "12-point" OR "forty-one blocks" OR "41 blocks")
-is:retweet
```

The independent recent-counts endpoint returned `total_tweet_count: 0` for
the exact query, with zero in every daily bucket from
`2026-07-17T15:57:23Z` through `2026-07-24T15:57:23Z`.

## Broad sanity query

```text
("C(12,6,4)" OR "C(12, 6, 4)" OR "covering number" OR
"covering design") -is:retweet
```

The endpoint returned 21 posts. Manual inspection found that all were
irrelevant uses such as visual or industrial "design," sports jersey numbers,
and general mathematical material. None claimed a result about the covering
number \(C(12,6,4)\).

## Full-archive attempt and limitation

An exact full-archive search was attempted over
`2025-07-24T00:00:00Z` through `2026-07-24T23:59:59Z`. The X API returned:

```json
{
  "errorKind": "tier_unavailable",
  "status": 403,
  "message": "Full-archive search requires Pro or Enterprise on this access tier."
}
```

Accordingly, the evidence supports the narrow statement that no matching post
appeared in X's live seven-day recent-search corpus. It does **not** establish
the absence of all older or unindexed X posts.

As a supplementary public-index check, web searches for
`site:x.com "C(12,6,4)"`, its spaced variant, and
`site:x.com "covering number" "12" "6" "4"` returned no results.
