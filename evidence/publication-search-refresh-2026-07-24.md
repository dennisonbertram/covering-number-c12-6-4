# Publication-time public search refresh

Checked on 2026-07-24 between approximately 19:59 and 20:02 UTC.

## Maintained covering repository

The live La Jolla Covering Repository entry still displayed

```text
40 <= C(12,6,4) <= 41
```

and identified 40 as the Schönheim lower bound:

<https://ljcr.dmgordon.org/cover/show_cover.php?v=12&k=6&t=4>

Its tables page said it was last updated on 2026-04-21:

<https://ljcr.dmgordon.org/cover/table.html>

The individual entry was opened once more immediately before release, at
approximately 20:32 UTC, and still displayed the same \(40\)-to-\(41\)
range and Schönheim lower-bound attribution.

## Indexed-web searches

The following exact searches were refreshed:

```text
"C(12,6,4)" covering 41 proof
"C(12, 6, 4)" covering design solved
"C(12,6,4)=41"
"covering number" "12,6,4"
```

No result supplied a proof that \(C(12,6,4)=41\). The only mathematically
relevant historical hit among the returned results stated the older range
\(40\le C(12,6,4)\le42\); the other hits were unrelated uses of the same
number tuple.

## GitHub searches

Authenticated GitHub global searches were run over code, repositories,
issues, and pull requests.

Exact code queries:

```text
"C(12,6,4)"
"C(12, 6, 4)"
"C(12,6,4)" "41"
"C(12,6,4)" "optimal"
"C(12,6,4)" "proof"
```

The spaced form and the three proof/optimality refinements returned zero code
matches. The unspaced form returned one file:

<https://github.com/elementalcollision/leibniz-daemon/blob/09924f9501bf15cd036cc9da189fe0d094b18cdf/docs/results/tier1_exact_ladder.json>

That row records `best_known: 41`, reports only a 44-block feasible result,
and explicitly says `proven_optimal: false`; it is not a solution. Three
issue/PR search hits and the broad repository-name results were unrelated
numeric or source-code matches.

The exact spaced and unspaced code searches and the combined issue/PR search
were repeated at approximately 20:33 UTC. They returned the same one
non-optimal code row, zero spaced-form rows, and the same three unrelated
issue/PR matches.

## Scope

These checks support the statement that no prior completed solution was found
in the maintained table, indexed web, GitHub, or the separately recorded
seven-day X search. They cannot establish universal priority or absence from
private, deleted, unindexed, or differently worded material.
