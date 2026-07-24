# Formal certificate for the degree-5 local lemma

This directory contains a proof-producing SAT certificate for the statement:

> There do not exist five distinct triples and four distinct quadruples on
> \(Y=\{0,\ldots,8\}\) such that the triples have union \(Y\), one triple is
> \(012\), and the nine sets cover every edge of \(K_9\).

This is exactly the finite obstruction needed to rule out a point of degree
five in a nine-block \(C(10,4,2)\) cover.

## Why the CNF is equivalent to the finite lemma

The primary variables are:

- variables 1 through 84: the 84 triples, in lexicographic order;
- variables 85 through 210: the 126 quadruples, in lexicographic order.

The CNF asserts:

1. exactly five triple variables are true;
2. exactly four quadruple variables are true;
3. the variable for triple \(012\) is true;
4. for every vertex, at least one selected triple contains it;
5. for every edge, at least one selected triple or quadruple contains it.

Boolean selectors make the selected triples and quadruples distinct.  Fixing
\(012\) loses no solutions: choose any one of the five triples and apply a
permutation in \(S_9\) that maps it to \(012\).

Exact cardinalities use the equivalence

\[
s_{i,j}\ \longleftrightarrow\
s_{i-1,j}\lor(s_{i-1,j-1}\land x_i),
\]

where \(s_{i,j}\) means that at least \(j\) of the first \(i\) literals are
true.  The independent auditor exhaustively truth-table-checks every gate
template, verifies the recurrence topology, and checks that the final two
units assert “at least \(k\)” and “not at least \(k+1\).”

The CNF also contains one redundant proof-strengthening identity.  Five
triples and four quadruples have

\[
5\binom32+4\binom42=39
\]

edge incidences.  Covering all 36 edges therefore produces exactly three
excess incidences.  Consequently every edge has degree at most four and

\[
\sum_e \bigl([d_e\ge2]+[d_e\ge3]+[d_e\ge4]\bigr)=3.
\]

The generator encodes these threshold facts explicitly.  They remove no
model of the five-triple/four-quadruple problem.

For the covering-design application, delete a hypothetical degree-five point
\(x\).  Its five incident blocks become five distinct triples whose union is
all nine remaining points.  The other four blocks become four distinct
quadruples.  Pair coverage becomes edge coverage.  Conversely, any CNF model
would reconstruct such nine distinct blocks, so CNF unsatisfiability excludes
degree five.

The existing C++ verifier searches the same triple families and a *larger*
quadruple completion space (at most four quadruples, repetitions allowed).
Its independent UNSAT result is therefore a cross-check.  The DRAT/LRAT
certificate does not rely on that C++ search.

## Reproduce

Generate and audit:

```sh
python3 generate_degree5_cnf.py degree5.cnf degree5.map.json
python3 audit_degree5_cnf.py degree5.cnf degree5.map.json
```

Generate a textual DRAT proof from scratch with CaDiCaL 1.7.3:

```sh
cadical -q --no-binary degree5.cnf degree5.drat
```

CaDiCaL returns exit status 20 for UNSAT.  The repository stores the proof
compressed, so replay the published DRAT as follows:

```sh
mkdir -p /tmp/c12-degree5-replay
gzip -dc degree5.drat.gz > /tmp/c12-degree5-replay/degree5.drat
drat-trim degree5.cnf /tmp/c12-degree5-replay/degree5.drat
```

The decisive last line is:

```text
s VERIFIED
```

The already-exported LRAT is also stored compressed. Replay it independently
with both `lrat-check` and the CakeML-extracted `cake_lpr` checker:

```sh
zstd -dc degree5.lrat.zst > /tmp/c12-degree5-replay/degree5.lrat
lrat-check degree5.cnf /tmp/c12-degree5-replay/degree5.lrat
env CML_HEAP_SIZE=8192 CML_STACK_SIZE=2048 \
  cake_lpr degree5.cnf /tmp/c12-degree5-replay/degree5.lrat
```

The decisive lines are:

```text
c VERIFIED
s VERIFIED UNSAT
```

## Recorded verification

The independently audited CNF has 6,816 variables and 24,835 clauses.  Of
these, 210 are semantic selector variables and 6,606 are definitional
cardinality/threshold auxiliaries.

The deterministic proof-producing run was repeated.  Both runs emitted
byte-for-byte identical DRAT files with SHA-256
`43617c23de2403e3d04b3d675d6fd1ba8bae7bdf2c4046b94d330091cbe9eb2d`.
The captured repeat took 44.56 seconds wall time.

`drat-trim` reported:

```text
c 18645 of 24835 clauses in core
c 336028 of 555254 lemmas in core using 65224014 resolution steps
c 0 RAT lemmas in core; 368840 redundant literals in core lemmas
s VERIFIED
```

`lrat-check` independently reported:

```text
c parsed a formula with 6816 variables and 24835 clauses
c VERIFIED
```

The CakeML-extracted `cake_lpr` checker independently reported:

```text
s VERIFIED UNSAT
```

The raw logs are `degree5.solve.log`, `degree5.audit.log`,
`degree5.drat_check.log`, `degree5.lrat_check.log`, and
`degree5.cake_lpr_check.log`, and `degree5.cpp_check.log`.

Tool provenance:

- CaDiCaL 1.7.3 commit
  `38e073b389a877b0a0d3c91136d2443ab95fdeba`;
- upstream `drat-trim` commit
  `2e3b2dc0ecf938addbd779d42877b6ed69d9a985`;
- `cake_lpr` commit
  `a36874a8b750b43fe4b385b8ddbf5b033e46a3fa`.

The replay binaries were compared byte-for-byte with a clean build of that
upstream revision.  The `drat-trim` binary SHA-256 is
`42a69f9a17bcd58001676abf02d58992bd0ede58410a467dda07a350fec498c9`;
the `lrat-check` binary SHA-256 is
`cef0a912384b790afe205a75309990e5bd63b38c309b2867ef36eb8a0c58fe4c`.

See `SHA256SUMS` for every packaged artifact hash.  For publication, the
117 MB textual DRAT is stored as the 23 MB `degree5.drat.gz`; the 423 MB
LRAT is stored as the 86.6 MB `degree5.lrat.zst`.  The uncompressed proof
files are intentionally omitted.  `degree5.core.cnf.gz` is the exported
18,645-clause input core.  `check_c1042_degree5.cpp` is the independent
solver-free cross-check source.  `detect-secrets.json` records a
`detect-secrets` 1.5.0 scan of `certificates/local`, `data`, and `scripts`
with an empty result set.  The decompressed DRAT and LRAT streams were also
checked separately; their only alphabetic character is the format's deletion
marker `d`.
