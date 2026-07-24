# Prior-art and recent-publication search

Search date: **2026-07-24**

This record answers a narrow question: did the searches below find a public
solution of the exact covering number \(C(12,6,4)\) before this proof was
released? They did not. This is evidence for a novelty review, not a proof
that no private, unindexed, differently worded, or unpublished solution
exists.

## Authoritative covering repositories

The [La Jolla Covering Repository entry for
\(C(12,6,4)\)](https://ljcr.dmgordon.org/cover/show_cover.php?v=12&k=6&t=4)
was opened directly on 2026-07-24. It displayed

```text
40 <= C(12,6,4) <= 41
```

and published the 41-block upper-bound witness used in this repository.

The [La Jolla Coverings Repository Zenodo
dataset](https://zenodo.org/records/19735294) was also opened directly. The
record identifies version 1.2, published 2026-04-24, and describes the
dataset as containing the best-known covering designs and their historical
improvements.

These are the strongest sources found for the maintained state of this
specific covering-number table.

The [OEIS entry A011984](https://oeis.org/A011984), for the sequence
\(C(n,6,4)\), was also opened directly on 2026-07-24. Its values stopped at
\(n=11\), and its comment for the next term stated only `a(12) <= 41`.
Thus it, too, contained no exact value for \(C(12,6,4)\) at inspection time.

## Direct X API search

The X API v2 recent-search and recent-count endpoints were queried over the
explicit interval

```text
start: 2026-07-17T15:00:00Z
end:   2026-07-24T14:53:00Z
```

for each of the following queries:

```text
"C(12,6,4)" -is:retweet
"C(12, 6, 4)" -is:retweet
"covering number" "12,6,4" -is:retweet
"covering design" "12,6,4" -is:retweet
"(12,6,4)" (covering OR cover) -is:retweet
"12, 6, 4" (covering OR cover) -is:retweet
C1264 (covering OR design) -is:retweet
"La Jolla Covering Repository" -is:retweet
```

For every query:

- `GET /2/tweets/counts/recent` returned `total_tweet_count: 0`; and
- `GET /2/tweets/search/recent` returned `posts: []` and
  `result_count: 0`.

The structured result is pinned in `x-recent-search.json`.

A follow-up at `2026-07-24T15:56:42Z` used one combined exact query and a
second semantic variant. Both returned zero recent posts; the independent
recent-counts endpoint returned zero in every daily bucket. A broad sanity
query returned 21 irrelevant uses, none concerning this covering number.
The exact scope and the repeated full-archive 403 limitation are recorded in
`x-recency-followup.md`.

A full-archive count and search were attempted for
`"C(12,6,4)" -is:retweet`. Both returned HTTP 403 with the explicit API
classification `tier_unavailable`: full-archive search requires X Pro or
Enterprise on the connected access tier. Accordingly, this record makes only
the exact seven-day API claim above. It does not claim complete access to
X's historical archive.

## GitHub search

GitHub repository, code, issue, and commit searches were run with the exact
string `"C(12,6,4)"`.

The repository search found one directly relevant repository:
[ctkrug/proofs-covering-c1264](https://github.com/ctkrug/proofs-covering-c1264).
GitHub metadata reported:

```text
created: 2026-07-22T01:47:11Z
pushed:  2026-07-23T21:49:12Z
public:  true
```

Its README explicitly retained the gap `40 <= C(12,6,4) <= 41`, reported
47 canonical frontier nodes still open, and stated: `No exact-value claim is
made.` Its latest commit at inspection time was
[`4db3bcd93664222f9ee156d57e070b0ce15bbeca`](https://github.com/ctkrug/proofs-covering-c1264/commit/4db3bcd93664222f9ee156d57e070b0ce15bbeca),
dated 2026-07-23T21:49:05Z.

The exact-code search also found
[`elementalcollision/leibniz-daemon`](https://github.com/elementalcollision/leibniz-daemon/blob/09924f9501bf15cd036cc9da189fe0d094b18cdf/docs/results/tier1_exact_ladder.json).
Its pinned result for this cell reported a 44-block feasible solution,
`proven_optimal: false`, and verdict `above-record`; it is not a solution of
the 40-versus-41 gap.

No GitHub hit inspected in this search claimed or supplied a completed proof
of the exact value.

## Indexed-web search

The following exact and phrase variants were searched on the indexed web:

```text
"C(12,6,4)" covering number proof
"C(12, 6, 4)" covering design
"C1264" covering design
"40 <= C(12,6,4) <= 41"
"C(12,6,4) = 41" covering
"C(12, 6, 4) = 41" covering
site:github.com "C(12,6,4)"
```

The searches returned the La Jolla records, older covering-design literature,
the open GitHub campaign described above, unrelated uses of the same number
tuple, and no completed proof of the exact covering number.

## Conclusion and limitation

As of the stated search time, the authoritative table still listed the
one-unit gap; the direct recent X API search found zero matching posts; and
the indexed-web and GitHub searches found no completed proof. The result in
this repository should therefore be treated as a candidate new
computer-assisted result and submitted to external mathematical review.

Search cannot establish universal priority. A differently phrased post, an
unindexed document, a private communication, or content outside the available
X window could have been missed.
