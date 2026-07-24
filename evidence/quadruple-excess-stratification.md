# Quadruple-excess stratification by matching type

Date: 2026-07-24  
Scope: independent mathematical audit and bounded relaxation experiment  
Status: the identities below are proved; the CP-SAT result is diagnostic only

Assume a hypothetical 40-block \((12,6,4)\) cover after the perfect matching

\[
M=\{01,23,45,67,89,10\,11\}
\]

has been normalized.  Write \(r_Q\) for the number of selected blocks
containing a quadruple \(Q\), and put

\[
q_Q=r_Q-1.
\]

Quadruple coverage and the triple-degree ceiling give
\(1\le r_Q\le4\), so \(q_Q\in\{0,1,2,3\}\).

## 1. Audit of the local excess identity

For every triple \(T\),

\[
\sum_{Q\supset T}r_Q=3r_T.
\]

Indeed, each selected 6-block through \(T\) has exactly three points outside
\(T\), and hence supplies exactly three quadruple extensions of \(T\).
There are nine quadruples extending \(T\), so

\[
\sum_{Q\supset T}q_Q=3(r_T-3).
\]

Thus the sum is zero when \(r_T=3\) and three when \(r_T=4\).  In particular,
if \(q_Q>0\), all four triples contained in \(Q\) have degree four.

Equivalently, let \(K\) be the 140 degree-four triples: the 60 triples
containing an edge of \(M\), together with the 80 transversal triples in the
3-GDD \(H\).  Then the nonnegative weights \(q_Q\) form a weighted threefold
decomposition of \(K\) into tetrahedron boundaries:

\[
\sum_{Q\supset T}q_Q=
\begin{cases}
3,&T\in K,\\
0,&T\notin K.
\end{cases}
\]

The threshold formulation used by the residual strengthening is therefore
logically exact.  If \(u_{Q,j}\) denotes \(r_Q\ge j\), for
\(j=2,3,4\), then

\[
q_Q=u_{Q,2}+u_{Q,3}+u_{Q,4}.
\]

Full-equivalence counters for these thresholds, the implications
\(u_{Q,j}\Rightarrow h_T\) for \(T\subset Q\), an unconditional upper bound
of three on the 27 incident threshold atoms, and
\(h_T\Rightarrow\) a lower bound of three impose exactly the displayed
identity.  This checks the mathematics of the layer; byte-level correctness
of a particular CNF remains the job of its independent encoder auditor.

## 2. Exact stratification

Let \(m(Q)\in\{0,1,2\}\) be the number of matching edges fully contained in
\(Q\), and define

\[
E_m=\sum_{m(Q)=m}q_Q.
\]

There are respectively \(240,240,15\) quadruples of matching types
\(0,1,2\).  If a selected block has matching type \(d\), the numbers of its
15 contained quadruples of each matching type are:

| block type \(d\) | \(m(Q)=0\) | \(m(Q)=1\) | \(m(Q)=2\) | row sum |
|---:|---:|---:|---:|---:|
| 0 | 15 | 0 | 0 | 15 |
| 1 | 9 | 6 | 0 | 15 |
| 2 | 4 | 10 | 1 | 15 |
| 3 | 0 | 12 | 3 | 15 |

For example, after choosing the one full matching pair of a type-1
quadruple, the two remaining points must come from two distinct occupied
matching groups.  The choice of the full pair is also counted; this gives
10, not 5, in the \(d=2\) row and 12, not 4, in the \(d=3\) row.  The final
column provides an explicit double-count check against
\(\binom64=15\).

If \(n_d\) is the number of selected blocks of matching type \(d\), double
counting incidences \((B,Q)\) and then subtracting the one mandatory
incidence for every quadruple gives

\[
\begin{aligned}
E_0&=15n_0+9n_1+4n_2-240,\\
E_1&=6n_1+10n_2+12n_3-240,\\
E_2&=n_2+3n_3-15.
\end{aligned}
\]

Using

\[
n_0+n_1+n_2+n_3=40,\qquad
n_1+2n_2+3n_3=60,
\]

these simplify to

\[
\boxed{
E_0=20+n_0+n_3,\qquad
E_1=80-2(n_0+n_3),\qquad
E_2=5+n_0+n_3.
}
\]

As a second double-count check,

\[
E_0+E_1+E_2=105
=40\binom64-\binom{12}4,
\]

the known total quadruple excess.

These equalities are profile-specific implied constraints.  Once the
\(q\)-threshold atoms already exist, the smallest particularly useful one
is the exact type-2 sum: it has only \(15\cdot3=45\) threshold atoms and
target \(5+n_0+n_3\).

There is also a fixed-support refinement.  Let \(F\subseteq\binom{[6]}3\)
be the selected type-3 supports.  For two matching groups \(i,j\), let
\(f_{ij}\) be the number of members of \(F\) containing \(\{i,j\}\), and let
\(s_{ij}\) be the number of selected type-2 blocks whose two full matching
pairs are \(i,j\).  For
\(Q_{ij}=M_i\cup M_j\), every selected block through \(Q_{ij}\) is of one
of precisely those two forms.  Consequently,

\[
q_{Q_{ij}}=f_{ij}+s_{ij}-1\in\{0,1,2,3\},
\qquad
\sum_{i<j}q_{Q_{ij}}=E_2.
\]

This gives fifteen small local links between the fixed support, the
type-2 primary variables, and the existing excess thresholds.

## 3. Diagnostic feasibility experiment

The excess/3-GDD relaxation alone is not contradictory.  A fresh CP-SAT
model used:

- 160 Boolean variables \(h_T\), one for every transversal triple;
- 495 integer variables \(q_Q\in[0,3]\);
- for every nonmatching point-pair, exactly four of its eight transversal
  extensions in \(H\);
- the 220 exact boundary equations above; and
- the explicit support implications \(q_Q\le3h_T\) for every transversal
  face \(T\subset Q\).

The symmetry-breaking unit \(h_{\{0,2,4\}}=1\) loses no feasibility because
the matching normalizer is transitive on transversal triples and \(H\) is
nonempty.  OR-Tools CP-SAT 9.15.6755 returned `OPTIMAL` (a feasibility
status here) in 8.117 seconds, with 77,735 branches and 25,954 conflicts.
The model had

\[
|H|=80,\qquad \sum_Qq_Q=105,
\]

75 quadruples of excess one, 15 of excess two, none of excess three, and

\[
(E_0,E_1,E_2)=(30,60,15).
\]

This is an experimental solver result, not a checked certificate and not a
proof about the original block-selection problem.  Its purpose is only to
rule out the claim that the 3-GDD and tetrahedron-boundary equations alone
give an immediate hand contradiction.  The proved stratification identities
remain valid and can be used as redundant propagation in the certified
block-level campaign.
