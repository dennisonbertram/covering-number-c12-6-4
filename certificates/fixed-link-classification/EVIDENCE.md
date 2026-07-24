# Independent fixed-link evidence memo

## Verdict

The fixed-link enumeration, admissibility filter, stabilizer action, orbit
partition, canonical representatives, and 210-unit case construction all
**pass** independent reconstruction.

The prototype sweep logs are complete as records but are not UNSAT
certificates. They contain no CNF digest, solver digest or version, exit code,
raw solver output, or proof digest. The release theorem must therefore rely on
the separate LRAT campaign, not on those logs.

## Original independent run

The scratch audit used two structurally different algorithms.

1. A canonical-witness C++ search found no eight-block cover in 0.073 seconds.
   It then visited 442,599,804 search nodes and enumerated 359,100 nine-block
   covers in 130.945 seconds. Its sorted output was byte-identical to the
   independently supplied list.
2. A pure-standard-library Python audit used the light-point partition
   construction, rebuilt the group from generators, traversed every orbit, and
   rebuilt every global case in 34.178 seconds.

Original scratch hashes:

- canonical C++ source:
  `ed9cc2f731e6638121dc698ee00b9744f8affe70ffe92a22544c4816e75c304d`;
- compiled audit binary:
  `f8233b179ce31dc2818832c2c46863fa2223c8b7e540f37dbd0a9779fcecc9e9`;
- 359,100-cover output:
  `52951ea29f8e249a739a6d4eef31d874e552f789cbe0f99d93722bd7437547d9`;
- original Python audit source:
  `d8d665783e0cb147ebd7937525ce6927ff3837bfe622b8ee7a8728c15535109e`;
- original audit result:
  `375977f8edd556f99c0d31e14f6f39665de9f8e557cd137e4acbd0737c42d17f`;
- original audit stdout:
  `5ecb1266dd008fadef16aefc0a929dfb6637b67d72abf729f9ac109c0777b95d`;
- canonical representative output:
  `369a844c4590d435fc24f82424a0775d51ce326d243aaf740d025c52c81d652b`;
- conceptual-case hash manifest:
  `3352f4cfa1009d09fda4e7af6c5a06b4fd6821fd5437f7a707b357d8c31dc8be`.

The portable component retains the exact canonical C++ source. The Python
source was adapted to remove all staging paths and comparison-target
dependencies.

## Exact counts

- anchor partitions of nine points into triples: 280;
- three-light-point option tuples: 280,000;
- consistent option tuples before heavy-only completion: 10,090;
- covers for one prescribed six-point heavy set: 1,710;
- choices of the heavy set: 210;
- all distinct labelled covers: 359,100;
- partner-heavy admissible links: 119,700;
- order of \(\operatorname{Stab}(M,P)\): 768;
- disjoint orbits and canonical representatives: 266;
- sum of all orbit sizes: 119,700.

Orbit-size histogram:

| Orbit size | Orbits |
| ---: | ---: |
| 12 | 1 |
| 16 | 1 |
| 24 | 5 |
| 48 | 12 |
| 96 | 30 |
| 128 | 2 |
| 192 | 60 |
| 256 | 1 |
| 384 | 37 |
| 768 | 117 |

## Why the stabilizer has order 768

The fixed nonmatching pair meets two matching edges. An automorphism preserving
the matching and the pair either fixes those two selected endpoints or swaps
them, giving two choices; the partners are then forced. The other four matching
edges may be permuted arbitrarily and flipped independently. Hence

\[
|\operatorname{Stab}(M,P)|=2\cdot 4!\cdot 2^4=768.
\]

The generated closure was checked element by element to preserve the
distinguished partner pair and the four remaining duos. Its size reached the
upper bound above, so it is the full stabilizer rather than a proper subgroup.

## Prototype pruning audit

The prototype cover generator's pruning is sound:

- Choosing a block through the least uncovered pair is complete because every
  completion must contain such a block.
- After \(k\) blocks, `waste` is exactly \(6k\) minus the number of distinct
  covered pairs. A nine-block cover has final waste \(54-45=9\), and waste
  cannot decrease, so pruning above nine is valid.
- A selected block cannot be selected again: all six of its pairs cease to be
  uncovered immediately.
- Returning when all pairs are covered with fewer than nine blocks would omit
  padded nonminimal nine-block families if an eight-block cover existed. The
  independent canonical search explicitly discharged this dependency by
  finding zero eight-block covers.
- The 28-entry incidence array is exact because a fixed pair belongs to
  \(\binom{8}{2}=28\) four-subsets.

The prototype orbit classifier's assumptions were also independently checked:

- all 359,100 input rows are nine distinct in-range blocks and cover all 45
  pairs;
- all have degree multiset \(3^4 4^6\);
- requiring both distinguished partner coordinates to have degree four gives
  exactly 119,700 links;
- the 768 generated permutations are distinct and form the full group;
- orbit union, disjointness, canonical minima, and full-group images all agree.

## Global-case construction

For the fixed global pair \(P=\{0,2\}\), the remaining link coordinates map to

```text
1, 3, 4, 5, 6, 7, 8, 9, 10, 11.
```

Each local representative lifts to nine distinct six-subsets containing
\(P\). There are exactly \(\binom{10}{4}=210\) global block variables
containing \(P\). The case extension sets the selected nine variables true and
the other 201 false. The resulting header has 122,519 variables and 356,617
clauses. All 266 conceptual CNF hashes are regenerated and summarized by
`3352f4c...dc8be`.

A retained prototype case at index 68 matched the independently rebuilt bytes
exactly; its SHA-256 was
`bd4246cc5f9b38d3f46a4349026527873ef93078dd2132cbc48e59c0afdb4389`.

## Sweep-log limitation

The two prototype logs contain exactly one record for every index 0 through
265, and all 266 status strings say `UNSATISFIABLE`. Their hashes were:

- even indices:
  `ed23e17e124b8d529348f60abc0b0ddc6a6efd0519dee4ae4e5619d75f52790f`;
- odd indices:
  `99559672679488eb99e7cd7aeb2851767155ee2c6cc43638466f46927655dd3f`.

The sweep shell used append mode, ignored generator and solver exit codes, and
reduced solver output to one status token. A rerun could duplicate records, a
generation failure could leave no bound input, and the recorded status cannot
be tied to a specific CNF or proof. The present record set passed
uniqueness/completeness checks, but its UNSAT strings are intentionally excluded
from the proof trust chain.
