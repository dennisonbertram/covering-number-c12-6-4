# Residual compact-leaf strengthening and benchmark

Date: 2026-07-24  
Scope: read-only analysis of the live compact campaign, followed by diagnostic
solver runs on independently generated copies under
`/private/tmp/c12-residual-benchmark.lg3gd8`  
Source refinement manifest:
`f5066fcf1b978b5e967cf921d0d3dbeb7ad97c4f10d707cbc06cdb89bd179c0e`

No live campaign CNF, result, proof, or manifest was modified. The benchmark
runs did not request proof output and therefore are performance evidence, not
certificate receipts.

## Residual pattern

At `2026-07-24T19:10:15Z`, 105 of the 130 profile children had result
records: 64 were verified UNSAT and 41 had returned `UNKNOWN` at the
300-second limit. The 41 residual child indices were

```text
25-30, 49-54, 64-71, 89-93, 95, 106-112, 119-126.
```

They were precisely middle type-profile cases for parents 4, 9, 10, 11, 31,
and 32. Every residual had \(n_0\ge2\), witness kind zero, and the already
fixed type-zero block

\[
B_0=\{0,2,4,6,8,10\},
\]

whose primary variable is 287. The descending live run had not yet reached
all parent-3 children, so this list is a timestamped snapshot rather than a
final campaign leaf list.

A later screen exposed three additional parent-4 timeouts:

```text
19: n0=0, n1=22, fixed type-1 witness variable 36
20: n0=0, n1=22, fixed type-1 witness variable 45
21: n0=1, n1=20, fixed type-0 witness variable 287
```

These low-\(n_0\) cases motivated a second benchmark of the uniform entailed
layer without any symmetry clause.

## Entailed triple and high-triple layer

For every triple \(T\), let \(r_T\) be its selected-block degree. The nine
quadruples \(T\cup\{z\}\) must be covered, while one block through \(T\)
covers exactly three of them. Hence \(r_T\ge3\). The shared formula already
has \(r_T\le4\).

For every triple, the proposed extension builds a full-equivalence prefix
counter through level four, asserts its level-three output, and calls its
level-four output \(h_T\). Thus \(h_T=1\) exactly when \(r_T=4\).

All 60 triples containing a normalized matching edge have degree four. For a
nonmatching pair \(P\), pair-degree tightness gives

\[
\sum_{z\notin P}r_{P\cup\{z\}}=4\lambda_P=36.
\]

Two of those ten triples contain a matching edge and have degree four.
Consequently exactly four of the other eight, all transversal triples, have
degree four. Appending an exact-four-of-eight full-equivalence counter for
each of the 60 nonmatching pairs exposes this 3-GDD incidence condition.

The deterministic extension has:

```text
220 * 84 * 4 = 73,920  triple-prefix gates
 60 *  8 * 5 =  2,400  exact-four-of-eight gates
                    = 76,320  fresh variables
                      284,640 appended clauses
```

The four-clause recurrence is

\[
s_{i,j}\leftrightarrow
s_{i-1,j}\lor(s_{i-1,j-1}\land x_i).
\]

A truth-table check of one gate and induction on \(i\) prove that
\(s_{i,j}\) is true exactly when at least \(j\) of the first \(i\) inputs are
true. Every primary assignment has a unique extension to these gates.

## Residual stabilizer and one-clause symmetry cover

Let \(F\) be the fixed family of type-3 supports for a source child and

\[
G_F=C_2^6\rtimes\operatorname{Stab}_{S_6}(F).
\]

After the first witness is fixed, the group that may be used is not \(G_F\)
but the residual stabilizer

\[
L_F=\operatorname{Stab}_{G_F}(B_0).
\]

Because \(B_0\) chooses endpoint zero in every matched pair, fixing it forces
all six endpoint-flip bits to zero. Thus \(L_F\) is isomorphic to
\(\operatorname{Stab}_{S_6}(F)\). Direct enumeration gave:

| Parent | \(|L_F|\) | Orbits on the other 63 type-0 blocks |
|---:|---:|---:|
| 3 | 8 | 23 |
| 4 | 72 | 9 |
| 9 | 4 | 35 |
| 10 | 6 | 19 |
| 11 | 4 | 35 |
| 31 | 16 | 17 |
| 32 | 24 | 10 |

For each orbit \(O\), choose its lexicographically least block \(b_O\) and
append the single primary clause

\[
\bigvee_O x_{b_O}.
\]

This clause is a symmetry cover, not an entailed clause. If a source child
had a primary model, \(n_0\ge2\) would provide a selected type-0 block
\(W\ne B_0\). Some element of \(L_F\) maps \(W\) to the representative of
its orbit while preserving \(F\), \(B_0\), the matching, and all semantic
constraints. The permuted primary model therefore satisfies the clause.

The compact and profile cardinality CNFs are not assumed to have a literal
syntactic automorphism: after permuting the primary assignment, their
audited existential completeness supplies a fresh auxiliary extension.
This re-extension step is essential to the soundness argument.

An independent generator or auditor can reconstruct the clause by:

1. enumerating all 720 pair permutations and 64 flip masks;
2. retaining exactly the elements preserving both \(F\) and \(B_0\);
3. checking identity, closure, inverses, and the displayed group order;
4. partitioning the 63 remaining type-0 blocks into complete \(L_F\)-orbits;
5. checking disjointness, union, orbit closure, and deterministic minima.

One symmetry-covered child replaces one source child, so this construction
does not increase the leaf count.

For completeness, analogous clauses exist for the three low-\(n_0\) cases.
The parent-4 pre-witness group has order 4,608.

- Child 19 fixes a type-1 witness whose pre-witness orbit has size 192.
  Its residual stabilizer has order \(4608/192=24\) and 65 orbits on the
  other 479 type-1 blocks.
- Child 20 fixes a type-1 witness whose pre-witness orbit has size 288.
  Its residual stabilizer has order \(4608/288=16\) and 79 orbits on the
  other 479 type-1 blocks.
- Child 21 fixes \(B_0\). Its residual stabilizer has order 72 and 17
  orbits on all 480 type-1 blocks.

The independently enumerated representative-variable clauses are:

```text
child 19:
37 38 40 41 42 45 47 55 56 57 60 62 111 112 113 116 118 218 219
220 222 223 224 227 229 237 238 239 242 244 286 291 292 297 298
300 301 312 317 318 320 321 382 387 388 390 391 735 737 741 743
761 763 811 813 814 815 817 818 830 832 833 886 888 889 0

child 20:
36 37 46 48 51 52 60 61 63 70 71 73 107 108 116 117 119 126
127 129 218 219 227 228 230 233 234 242 243 245 252 253 255 282
283 286 298 299 302 303 306 318 319 323 324 326 328 329 372 373
376 388 389 393 394 396 398 399 735 736 738 755 756 758 806 807
809 811 812 821 822 824 826 827 877 878 880 882 883 0

child 21:
36 37 40 41 45 46 48 55 56 60 61 63 111 112 116 117 119 0
```

For children 19 and 20, a model contains 21 selected type-1 blocks besides
the fixed witness; for child 21 it contains 20 selected type-1 blocks. Pick
one such block and map it to its orbit representative with the appropriate
residual stabilizer. This is the same primary-projection symmetry-cover proof
as above. These clauses are optional and were not used in the uniform
entailed-only benchmark below.

## Exact quadruple-excess layer

For a quadruple \(Q\), let \(q_{Q,j}\) indicate \(r_Q\ge j\), for
\(j=2,3,4\). Coverage and the triple ceiling give \(1\le r_Q\le4\). For a
triple \(T\),

\[
\sum_{Q\supset T}r_Q=3r_T
\]

because each block through \(T\) supplies three quadruple extensions.
Therefore

\[
\sum_{Q\supset T}
  (q_{Q,2}+q_{Q,3}+q_{Q,4})
=3h_T.
\]

The exact identity is encoded by full-equivalence quadruple counters,
implications \(q_{Q,j}\Rightarrow h_T\) for every \(T\subset Q\), an
unconditional at-most-three counter on the 27 threshold atoms around each
triple, and a conditional \(h_T\Rightarrow\) at-least-three clause. Beyond the
triple/3-GDD layer this adds 79,200 gates and 298,375 clauses. Including the
triple/3-GDD layer, the uniform entailed extension totals:

```text
155,520 fresh variables
583,015 appended clauses
```

An optional residual-orbit clause would increase the clause count to
583,016.

This remains smaller than the earlier all-pair/point strengthening, which
would add 262,584 variables and 1,023,996 clauses per source leaf.

## Diagnostic benchmark

All runs used the copied CaDiCaL binary with SHA-256
`1639c68fd8da9db992a37c978e3ccee5833830fd135c412090926ce95937c312`
and options `-q --no-binary -t 120`. They ran sequentially while the live
four-worker campaign was active, so wall times are indicative rather than
isolated-machine measurements.

| Source child | Recorded source | Smaller triple + orbit | Strong entailed, no orbit | Strong + orbit |
|---|---:|---:|---:|---:|
| 67, parent 10, \(n_0=5\) | UNKNOWN at 300 s | UNSAT in 63.75 s | not run | not run |
| 122, parent 32, \(n_0=5\) | UNKNOWN at 300 s | UNSAT in 49.18 s | not run | not run |
| 27, parent 4, \(n_0=7\) | UNKNOWN at 300 s | UNKNOWN at 120 s | UNSAT in 23.92 s | UNSAT in 17.00 s |
| 19, parent 4, \(n_0=0\) | UNKNOWN at 300 s | not run | UNSAT in 19.52 s | not run |
| 20, parent 4, \(n_0=0\) | UNKNOWN at 300 s | not run | UNSAT in 19.43 s | not run |
| 21, parent 4, \(n_0=1\) | UNKNOWN at 300 s | not run | UNSAT in 10.66 s | not run |

For child 27, adding the exact quadruple-excess layer to the combined formula
returned UNSAT in 17.00 seconds. The copied child-27 CNFs had:

| Variant | Variables | Clauses | SHA-256 |
|---|---:|---:|---|
| Triple/3-GDD + orbit | 207,159 | 680,509 | `8b55c5a9153dc506a9168b5c499896090b5f8c0e09ce3db1908b47c4aaed9517` |
| Exact excess + triple/3-GDD + orbit | 286,359 | 978,884 | `0f0360a34388f1fd7287673baa37b597d360114b9cdc54f2d9ada9858245311b` |
| Exact excess + triple/3-GDD, no orbit | 286,359 | 978,883 | `66da151865561fbf0e25dc9deb494234865e2c760fa1987b20fc195b17291317` |

The copied uniform strong CNFs for the three low-\(n_0\) cases were:

| Child | Variables | Clauses | SHA-256 |
|---:|---:|---:|---|
| 19 | 285,825 | 976,804 | `36f164f44b0958ca409a607935401aaba5d8499a3cf58dceb326c05d2e8aab54` |
| 20 | 285,825 | 976,804 | `c7e8f1302288d0566d4d4482df660c66e5fde86d6e51bf73b5ff7925d10adcc1` |
| 21 | 285,951 | 976,993 | `6baae5724fcd50b1abde5109e1e4c3bd246975eba0b3d7af675d8bd78ab8c63b` |

## Recommendation and audit requirements

Use the uniform exact-excess plus triple/3-GDD extension, with no orbit
clause, for every frozen timeout source. It is purely entailed, applies
without checking a positive second-witness count, and solved all four copied
strong-layer benchmarks in 10.66--23.92 seconds. The orbit clauses remain
valid optional escalations, but the production campaign does not currently
need their additional symmetry-cover argument. The uniform extension remains
substantially smaller than the existing broad strengthening.

The production generator must retain the complete source CNF byte for byte,
start fresh variables above the source header maximum, pin every source and
extension hash, and use explicit fail-closed checks rather than Python
`assert`. A separately implemented auditor should reconstruct the primary
scopes, all gate clauses, section hashes, header counts, and final CNF bytes.
In the recommended mode the refinement record labels every new constraint as
entailed and needs no symmetry-cover edge or group computation. If an
optional representative clause is later used, the auditor must additionally
reconstruct the \(L_F\)-orbits and label that clause as a primary-projection
symmetry cover. Formal completion still requires CaDiCaL proof output,
DRAT-to-LRAT conversion, C `lrat-check`, and CakeML replay for every final
leaf.
