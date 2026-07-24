# X recent-search refresh

Read-only X API search refreshed on 2026-07-24 at 18:53 UTC.

Window:

- start: `2026-07-17T18:55:00Z`
- end: `2026-07-24T18:52:00Z`
- endpoint: `GET /2/tweets/search/recent`
- corroborating endpoint: `GET /2/tweets/counts/recent`
- retweets excluded

Queries:

```text
"C(12,6,4)" -is:retweet
"C(12, 6, 4)" -is:retweet
("12,6,4" OR "12, 6, 4") (covering OR cover OR blocks) -is:retweet
(C1264 OR "covering design") ("41" OR "forty-one") ("12" OR "v=12") -is:retweet
```

For every query, the recent-search endpoint returned:

```json
{"posts":[],"next_token":null,"result_count":0}
```

For every query, the counts endpoint returned total count zero. Each of its
eight UTC daily/partial-day buckets was also zero.

This establishes only the result of the accessible seven-day X recent-search
API. It does not establish absence from private posts, deleted posts, posts
outside the query vocabulary, or the unavailable full archive.
