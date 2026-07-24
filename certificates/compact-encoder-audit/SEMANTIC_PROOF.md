# Semantic audit of the compact k-modulo-totalizer base

## Scope and verdict

This note audits only the semantics and byte-level identity of the compact
cardinality encoding used in `global_base.cnf`. It does not rely on an UNSAT
solver result and does not run a solver campaign.

**Verdict: PASS.** A standard-library-only Python transcription of the pinned
upstream encoder reconstructs the production file byte for byte:

- 924 primary variables;
- 121,595 auxiliary variables;
- 122,519 variables in total;
- 356,407 clauses;
- full-file SHA-256
  `637d9326388f77f933f3d066cd762d8c0ac4b2df0d2260d688e031d55959e7f0`;
- clause-body SHA-256
  `6a1a2eb2843a4ddcf9138c5a85aaeccd2950b3e099e0ab8a26ce9fc815ab0cc5`.

The executable audit additionally checks 5,376 complete primary truth-table
rows for small AtMost, AtLeast, and Equals instances using its own DPLL
checker. It imports neither Python-SAT nor any SAT solver. As a separate
source-fidelity check, a logic-free C++ adapter is compiled against the pinned
official headers; 115 vectors comprising 123,220 clauses are byte-identical
to the pure-Python transcription. Those vectors include every production
radix/arity shape and the full 57,972-clause equality section.
The recorded final run used `python3 -S`, disabling all site packages.

## Pinned specification

The source specification is the official Python-SAT repository at commit
`7abb1d6fdafe1d75fe3e5cdfb48f7e07a8a76efd`, whose
`pysat/__init__.py` declares version `1.9.dev7`.

The principal source is `cardenc/mto.hh`:

- Git blob SHA-1:
  `eb52038ee5a6708555078e3836415d16c07a352e`;
- raw-file SHA-256:
  `fb5b7cc56c2ea3bc02c0a9004e4a2915c1a3440e9e749e369da78bef14b82626`.

`SOURCE_PIN.json` pins the exact hashes of `mto.hh`, `card.hh`, `common.hh`,
`clset.hh`, `pysat/card.py`, and `pysat/__init__.py`. The wrapper matters
because `CardEnc.equals` emits AtLeast first and AtMost second, and because
`card.hh` handles the degenerate bounds before dispatching to the
k-modulo-totalizer.

`source_reference_driver.cc` contains no encoding logic. It only invokes the
pinned header functions and serializes their returned clauses. Its comparison
manifest has SHA-256
`f3d5fa319a43347b79b471aa646d62a2ccd1569fdda4e84de4e228b35bb61eb7`.
The official implementation and the independent transcription agree on the
full equality-section SHA-256
`9a90ad6ce85edc53f9639b077534cfede27971974451b4676e414fbb0ad1ae9b`
and final section top ID 10,363.

## Definitions

All input literals below have fixed Boolean values. Auxiliary variables remain
existentially quantified.

For a unary vector
\[
Y=(Y_1,\ldots,Y_m),
\]
write
\[
\pi(Y)=\max\{j: Y_1=\cdots=Y_j=1\},
\]
with \(\pi(Y)=0\) when \(Y_1=0\). Thus \(\pi(Y)\) is the length of the true
prefix, not the largest true index. This distinction is important because the
one-directional totalizer clauses do not forbid irrelevant extra true bits.

For a modulo node of radix \(p\), upper vector \(U\), and lower vector \(L\),
define its decoded lower bound by
\[
D(U,L)=p\,\pi(U)+\pi(L).
\]
Here \(L\) has length \(p-1\). The upper vector can be truncated.

## Lemma 1: unary totalizer

For an untruncated unary totalizer with \(s\) true leaf inputs and output
\(Y\):

1. every satisfying auxiliary assignment has \(\pi(Y)\ge s\); and
2. there is a satisfying auxiliary assignment with
   \(Y_j=1\) exactly when \(j\le s\).

### Proof

Proceed by induction on the binary tree built by `to_TO`.

The one-input case identifies the output with the input, so both claims are
immediate. Suppose the left and right subtrees have \(a\) and \(b\) true
inputs. By induction, their true prefixes have lengths at least \(a\) and
\(b\). The merge `to_UA` emits

\[
A_i\Rightarrow Y_i,\qquad
B_j\Rightarrow Y_j,\qquad
A_i\wedge B_j\Rightarrow Y_{i+j}.
\]

For every \(t\le a+b\), choose \(i\le a\) and \(j\le b\), allowing either to
be zero, with \(i+j=t\). One of the displayed implications forces \(Y_t\).
Hence \(\pi(Y)\ge a+b\).

For existence, assign each internal output its exact subtree threshold:
\(Y_t=1\) iff that subtree contains at least \(t\) true leaves. Each
implication then has a true consequent whenever its antecedent is true. This
assignment satisfies every merge clause. ∎

## Lemma 2: one modulo merge never understates its children

Let a modulo merge have child vectors \((F,A)\) and \((G,B)\), parent vectors
\((H,R)\), radix \(p\), and carry variable \(c\). If its clauses are
satisfiable, then
\[
D(H,R)\ \ge\ D(F,A)+D(G,B).
\]
If the required true upper prefix exceeds the allocated, truncated upper
vector, the merge clauses are contradictory.

### Proof

Put
\[
f=\pi(F),\quad a=\pi(A),\quad
g=\pi(G),\quad b=\pi(B).
\]
The \(\phi_2\) clauses force the parent upper prefix through \(f+g\). For
example, for every \(t\le f+g\), choose \(i\le f\), \(j\le g\), with
\(i+j=t\). The appropriate one-child or two-child implication forces \(H_t\).
If \(c=1\), the carry variants force the prefix through \(f+g+1\).
Whenever one of these required indices exceeds the allocated upper length,
the source emits the same implication with false as consequent: a unit or
binary negative clause. Hence a satisfying merge cannot silently discard
upper overflow.

It remains to account for the lower parts.

**Case 1: \(a+b<p\).** For every \(t\le a+b\), choose
\(i\le a\), \(j\le b\), allowing zero, with \(i+j=t\). The corresponding
\(\phi_1\) clause forces \(R_t\lor c\). If \(c=0\), the parent lower prefix has
length at least \(a+b\). If \(c=1\), the parent upper prefix has length at
least \(f+g+1\). Either way,
\[
D(H,R)\ge p(f+g)+a+b.
\]

**Case 2: \(a+b=p\).** The clause whose lower indices sum to \(p\) forces
\(c=1\). Thus the upper prefix reaches \(f+g+1\), giving exactly the required
carry.

**Case 3: \(a+b>p\).** A pair of true lower-prefix bits with indices summing to
\(p\) exists, so \(c=1\) is forced. Moreover, for every
\(t\le a+b-p\), choose \(i\le a\), \(j\le b\) with \(i+j=p+t\). The
wraparound clause forces \(R_t\). Therefore the parent upper prefix reaches
\(f+g+1\) and its lower prefix reaches \(a+b-p\).

All three cases give the claimed inequality. ∎

## Lemma 3: the recursive truncated network does not undercount

If a modulo subtree contains \(s\) true input literals, then every satisfying
assignment to that subtree has decoded lower bound at least \(s\). If its
truncation makes that lower bound unrepresentable, the subtree clauses are
inconsistent.

### Proof

A recursive leaf has fewer than \(p\) inputs and is encoded by `to_TO`.
Lemma 1 gives the claim. At every internal node, apply the induction
hypothesis to the children and Lemma 2 to their merge. ∎

## Lemma 4: the comparator enforces the bound

Let \(k=pq+r\), \(0\le r<p\). Every assignment satisfying
`mto_comparator` has
\[
D(U,L)\le k.
\]

### Proof

The comparator sets every \(U_i\) with \(i>q\) to false, so
\(\pi(U)\le q\). If \(\pi(U)<q\), then
\[
D(U,L)\le p(q-1)+(p-1)<pq\le k.
\]
If \(\pi(U)=q>0\), then \(U_q=1\), and for every \(i>r\) the clause
\(\lnot U_q\lor\lnot L_i\) forces \(L_i=0\); hence \(\pi(L)\le r\).
When \(q=0\), the comparator directly sets every \(L_i\), \(i>r\), to false
and also forbids every upper bit. Thus again \(D(U,L)\le k\). ∎

## Theorem 1: AtMost soundness

The CNF produced by `kmto_encode_atmostN(X,k)` is satisfiable under a primary
assignment only if at most \(k\) input literals are true.

### Proof

If \(s\) inputs are true, Lemma 3 forces the root decoded lower bound to be at
least \(s\). Lemma 4 forces it to be at most \(k\). Hence \(s\le k\). If
truncation prevents the required prefix from being represented, Lemma 3
already gives a contradiction. ∎

## Theorem 2: AtMost completeness

If at most \(k\) input literals are true, the auxiliary variables have a
satisfying extension.

### Proof

At every unary leaf, assign the exact threshold vector from Lemma 1. At a
modulo merge, let the exact child counts be
\[
s_1=pq_1+r_1,\qquad s_2=pq_2+r_2.
\]
Set \(c=1\) iff \(r_1+r_2\ge p\). Set the parent upper vector to the exact
unary quotient prefix of
\(\lfloor(s_1+s_2)/p\rfloor\), and the parent lower vector to the exact unary
remainder prefix of \((s_1+s_2)\bmod p\).

Every \(\phi_1\) clause is then valid: a non-wrapping true antecedent either
has the required remainder threshold or the true carry; an exact-\(p\)
antecedent has the true carry; and a wrapping antecedent has the required
wrapped remainder threshold. Every \(\phi_2\) clause is valid because true
child quotient thresholds, with the carry when present, imply the
corresponding exact parent quotient threshold.

No truncation conflict occurs: each subtree count is at most the total count,
which is at most \(k\), so its exact quotient does not exceed
\(\lfloor k/p\rfloor\). Finally, the exact root quotient and remainder obey
the comparator because the total count is at most \(k\). ∎

## Corollary: AtLeast and Equals

The wrapper encodes
\[
\sum X_i\ge k
\]
as
\[
\sum \lnot X_i\le n-k.
\]
Theorems 1 and 2 therefore establish both soundness and completeness for
AtLeast. `CardEnc.equals` concatenates the AtLeast and AtMost encodings using
disjoint, consecutively allocated auxiliaries, so its existential projection
is exactly \(\sum X_i=k\).

The source special cases are also exact:

- AtMost \(0\) emits one negative unit per input;
- AtMost \(n-1\) emits the single clause containing all negated inputs;
- AtLeast \(1\) emits the single positive input clause;
- AtLeast \(n\) emits one positive unit per input;
- vacuous bounds emit no clauses.

## Production reconstruction

The production base uses one monotonically increasing variable pool.
Primaries are assigned IDs 1 through 924. The independent transcription
mirrors every `++top_id`, the source's iterative LIFO traversal, the wrapper's
AtLeast-before-AtMost order for equality, and the exact clause-literal order.

The reconstructed sections are:

| Section | Clauses | SHA-256 |
|---|---:|---|
| exactly 40 blocks | 57,972 | `9a90ad6ce85edc53f9639b077534cfede27971974451b4676e414fbb0ad1ae9b` |
| 66 pair ceilings | 141,960 | `2d300e47472c3aa8340555f1ffa0eb0abf7f22c4563fb18baaf43eeeb5362b40` |
| 220 triple ceilings | 155,980 | `bd56975a519fed6bce06eb8159f02417051c12b4f3a1fb61babf6e494153386c` |
| 495 literal coverage clauses | 495 | `381d8e308ae3cc608ab74288477f1506c882b6af2eb2b0be891f94bb44612538` |

`production_boundaries.json` records, for the exact constraint and every pair
and triple constraint, the input object, bound, zero-based half-open clause
interval, top ID before and after encoding, and subformula SHA-256. It also
records the final coverage interval. Its 288 entries have canonical JSON
SHA-256
`e8faba67dca00bd9fd889996c93667ad2742409bb4619d3c9d4352ce365471d8`.

The pretty-printed boundary file itself has SHA-256
`00a99825b80170c154231233705f3e2a67d54dc119ab11300527291f25abd239`.

## Reproduction

From the artifact directory:

```sh
python3 verify_frozen_audit.py
```

For a fresh source-pin replay from the repository root:

```sh
python3 -S certificates/compact-encoder-audit/audit_kmtotalizer.py \
  --source-repo .verification/pysat-upstream \
  --target certificates/compact-encoder-audit/results/reconstructed_global_base.cnf \
  --output-dir .verification/compact-encoder-audit \
  --small-max-arity 7
```

A successful run prints `result: PASS` and writes:

- `results/reconstructed_global_base.cnf`;
- `results/production_boundaries.json`;
- `results/AUDIT_REPORT.json`;
- a compiled official-source adapter and the exact pinned headers used to
  build it.

The audit fails on the first byte mismatch, any source-pinned production hash
mismatch, any section count or shape mismatch, any nonconsecutive or unused
auxiliary identifier, or any small semantic truth-table mismatch. A built-in
mutation test changes one byte and checks that the comparator identifies that
exact offset.
