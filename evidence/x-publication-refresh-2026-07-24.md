# X recent-search publication refresh

This is the final pre-publication X API check for a recent public claim about
\(C(12,6,4)\).

## Window and endpoints

- queried: 2026-07-24 at approximately 19:58 UTC;
- explicit window: `2026-07-17T19:58:00Z` through
  `2026-07-24T19:57:00Z`;
- endpoints: X API v2 recent post search and recent post counts;
- retweets excluded;
- result limit for each search: 100.

## Exact queries and results

| Query | Search posts | Count endpoint |
|---|---:|---:|
| `"C(12,6,4)" -is:retweet` | 0 | 0 |
| `"C(12, 6, 4)" -is:retweet` | 0 | 0 |
| `("12,6,4" OR "12, 6, 4") (covering OR cover OR blocks) -is:retweet` | 0 | 0 |
| `(C1264 OR "covering design") ("41" OR "forty-one") ("12" OR "v=12") -is:retweet` | 0 | 0 |
| `("covering number" OR "covering design") ("12,6,4" OR "12 6 4") -is:retweet` | 0 | 0 |
| `("C(12,6,4)" OR "C(12, 6, 4)") (proof OR solved OR equals OR "=41") -is:retweet` | 0 | 0 |

For every query, the search response was an empty post list with
`result_count: 0`; the count response reported `total_tweet_count: 0`, with
zero in every daily bucket.

## Full-archive limitation

A separate full-archive search and count attempt for
`"C(12,6,4)" -is:retweet`, covering 2006-03-21 through the publication
refresh time, returned HTTP 403 with:

```text
Full-archive search requires Pro or Enterprise on this access tier.
```

Accordingly, this evidence supports only the stated seven-day recency check.
It does not prove that no older, deleted, private, differently worded, or
unindexed post exists.

## Immediate pre-release refresh

The same six search and count queries were run again at approximately
20:31 UTC, with the explicit recent-search window
`2026-07-17T21:00:00Z` through `2026-07-24T20:30:00Z`. Every search again
returned `result_count: 0` and an empty post list; every count query again
returned `total_tweet_count: 0`. No new recent X result was found before the
repository release was frozen.
