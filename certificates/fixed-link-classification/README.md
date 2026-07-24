# Fixed-link classification audit

This component independently classifies the possible link of a fixed
nonmatching pair in a hypothetical 40-block \(C(12,6,4)\) cover.

It proves the following finite statements:

- there is no eight-block \(C(10,4,2)\) cover;
- there are exactly 359,100 distinct labelled nine-block
  \(C(10,4,2)\) covers;
- exactly 119,700 have the two distinguished partner points of degree four;
- the full stabilizer of the matching and fixed pair has order 768;
- its action partitions those 119,700 links into exactly 266 disjoint orbits;
- the published representative checksum is the checksum of the canonical
  minimum of every orbit; and
- every representative lifts to nine distinct global block variables and
  exactly 210 unit clauses: nine positive and 201 negative.

This is a classification and encoding audit. It does **not** prove that the 266
global cases are UNSAT. That conclusion belongs to the separately replayed
proof-certificate campaign.

## Two independent enumerations

`canonical_enum.cpp` makes no assumption about point degrees. At each node it
chooses the least uncovered pair. Among the blocks in a completion that cover
that pair, the least-indexed one is the unique witness. A branch choosing a
larger witness permanently forbids all smaller candidates. Thus every block
set is generated exactly once, rather than as many block orders followed by
deduplication.

The Python auditor reconstructs the result through a different decomposition.
For a fixed heavy set of six points, an anchored light point partitions the
other nine points into three triples in 280 ways. Each of the other three light
points then has ten complementary two-triple partitions. Consistency and the
remaining heavy-only blocks give exactly 1,710 covers. Relabelling the heavy
set in all \(\binom{10}{6}=210\) ways reproduces all 359,100 covers exactly.

The group audit starts from eight generators, computes their closure, verifies
that it is precisely the order-768 matching stabilizer, traverses every orbit,
and then checks every representative again using all 768 group images.

## Offline replay

From the repository root:

```sh
python3 -S \
  certificates/fixed-link-classification/verify_frozen_classification.py
```

The verifier compiles into and writes only within an automatically removed
temporary directory. On the original audit machine, the complete replay takes
roughly three minutes.

To require a proof campaign to use the exact regenerated representatives:

```sh
python3 -S \
  certificates/fixed-link-classification/verify_frozen_classification.py \
  --candidate-representatives PATH/TO/link_representatives.txt
```

The candidate must be a regular, non-symlink file with exact byte identity.

## Stable outputs

- all covers:
  `52951ea29f8e249a739a6d4eef31d874e552f789cbe0f99d93722bd7437547d9`;
- 266 canonical representatives:
  `369a844c4590d435fc24f82424a0775d51ce326d243aaf740d025c52c81d652b`;
- conceptual 266-case hash manifest:
  `3352f4cfa1009d09fda4e7af6c5a06b4fd6821fd5437f7a707b357d8c31dc8be`;
- compact global base:
  `637d9326388f77f933f3d066cd762d8c0ac4b2df0d2260d688e031d55959e7f0`.

`results/AUDIT_REPORT.json` is the deterministic, path-free expected report.
`EVIDENCE.md` records the original independent comparison and the audit of the
prototype pruning and sweep scripts.
