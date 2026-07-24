# Functional-gate cross-check of the global encoding

This directory is an independent semantic cross-check of the two global
\(C(12,6,4)\) SAT roots.  It replaces the other encoding's cardinality
machinery with explicit functional prefix counters and uses no PySAT code.

**Status:** the encoding and both root files have passed the independent
structural audit described below.  These files are **not yet an UNSAT
certificate**.  At packaging time, the live CaDiCaL jobs writing
`gate_root0.bdrat` and `gate_root1.bdrat` had not finished, and neither proof
had been replayed.  Do not cite this package as proving root UNSAT unless
both resulting proof traces later pass an independent checker.

## Files

- `generate_gate_roots.py` deterministically generates either root without
  PySAT.
- `audit_gate_roots.py` independently reconstructs every object, gate,
  clause, section, and root unit.
- `gate_root0.cnf`, `gate_root0.json`, `gate_root1.cnf`, and
  `gate_root1.json` are the pinned artifacts.
- `audit.log`, `regeneration.log`, `mutation-test.log`, and `benchmark.log`
  record the independent checks.
- `SHA256SUMS` pins every published file except the manifest itself.

The live `.bdrat` files are intentionally not included: they were incomplete
and unverified when this package was assembled.

## Mathematical model

Primary variables 1 through 924 correspond, in lexicographic order, to the
six-element subsets of \(\{0,\ldots,11\}\).  Both roots assert:

1. exactly 40 distinct blocks are selected;
2. every quadruple is contained in a selected block;
3. for the fixed matching
   \(M=\{01,23,45,67,89,10\,11\}\), matching-pair degrees are at most 10
   and all other pair degrees are at most 9; and
4. every triple degree is at most 4.

The 40 blocks contain \(40\binom62=600\) pair incidences, exactly the sum of
the 66 pair ceilings:

\[
6\cdot10+60\cdot9=600.
\]

Thus every pair ceiling is tight.  The nonmatching pairs have degree nine.
For any triple, choose one of its at least two nonmatching constituent pairs.
The nine blocks through that pair induce an optimal \(C(10,4,2)\) cover, so
the independently established local degree theorem makes the triple degree
three or four.  Quadruple coverage supplies the lower bound three, while the
CNF records the required upper bound four.

Classify a block by the number \(d\in\{0,1,2,3\}\) of matching pairs it
contains.  If \(n_d\) counts selected blocks of type \(d\), tight matching
pair degrees give

\[
n_0+n_1+n_2+n_3=40,\qquad
n_1+2n_2+3n_3=60.
\]

There are 221 nonnegative integer profiles satisfying these equations.
Every profile has \(n_0>0\), or else it has \(n_1>0\).  The matching
stabilizer is transitive on all 64 type-0 blocks and on all 480 type-1
blocks.  Consequently:

- root 0 fixes the type-0 block `0 2 4 6 8 10`;
- root 1 forbids every type-0 block and fixes the type-1 block
  `0 1 4 6 8 10`.

These two roots exhaust the model up to matching-preserving symmetry.

## Functional cardinality gates

For input literals \(x_1,\ldots,x_n\), the auxiliary variable \(s_{i,j}\)
means that at least \(j\) of the first \(i\) inputs are true.  Every gate is
the full equivalence

\[
s_{i,j}\longleftrightarrow
s_{i-1,j}\lor(s_{i-1,j-1}\land x_i).
\]

With the initial row fixed to \(s_{0,0}=\mathsf{true}\) and
\(s_{0,j}=\mathsf{false}\) for \(j>0\), prefix induction gives every primary
assignment exactly one auxiliary extension.  Final positive and negative
threshold units therefore have their literal exact/at-most meanings.

The auditor does not import the generator.  It independently:

- exhaustively truth-table-checks every generated gate equivalence;
- reconstructs all 270,144 auxiliary variables and every clause in order;
- checks that auxiliaries are exactly variables 925 through 271,068;
- checks the four base sections, their shapes, boundaries, and hashes;
- verifies both root-unit sets and metadata files;
- computes all 221 type profiles; and
- explicitly computes the full type-0 and type-1 stabilizer orbits.

The shared base has 1,044,768 clauses and clause-body SHA-256
`fc7e5de081b3805cd8c77f27c581b6fd6ab3a97b92a2928c3d60fafd2fb76e73`.

## Reproduce

Run the pinned audit:

```sh
python3 audit_gate_roots.py
```

Regenerate into a separate directory:

```sh
python3 generate_gate_roots.py \
  --root 0 --output /tmp/gate_root0.cnf --metadata /tmp/gate_root0.json
python3 generate_gate_roots.py \
  --root 1 --output /tmp/gate_root1.cnf --metadata /tmp/gate_root1.json
```

Then compare those files with the published artifacts and verify:

```sh
shasum -a 256 -c SHA256SUMS
```

The recorded clean regeneration was byte-for-byte identical for both CNFs
and both JSON files.  A fail-closed mutation test changed the first
functional clause from `-925 1 0` to `-925 2 0`; the auditor rejected it at
clause index zero.  See the logs for exact output.
