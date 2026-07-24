# Claude Opus 5 independent mathematical exploration

Date: 2026-07-24  
Model requested: `claude-opus-5`  
Canonical model reported by Claude Code: `claude-opus-5`  
Effort: xhigh  
Outcome: **no complete contradiction; several exact reformulations**

This was a separate, deliberately unanchored research pass. Claude read the
manuscript and the core functional generator but was instructed not to read
the earlier Claude/Fable reviews. The original response exceeded Claude
Code's 64,000-token transport limit after about 256,000 output tokens. The
same cached session was resumed and compressed into a bounded summary.

## Proved consequences

Let \(M\) be the matching of pair degree ten in a hypothetical 40-cover.

1. The exact quadruple-excess budget is

   \[
   \sum_{Q\in\binom{[12]}4}(r_Q-1)
   =40\binom64-\binom{12}4
   =600-495=105.
   \]

2. For a nonmatching pair \(P\), the nine blocks containing \(P\), with
   \(P\) deleted, form a nine-block optimum \((10,4,2)\) covering. Its six
   degree-four points are exactly the six extensions \(z\) for which
   \(r_{P\cup\{z\}}=4\). Thus local links constrain more than the already
   used count of six high extensions; a classification of nine-block
   \((10,4,2)\) optima could provide a smaller finite branching object.

3. Let \(H\) be the 80 degree-four triples that contain no matching edge.
   Every nonmatching pair lies in exactly four members of \(H\). Therefore
   \(H\) is a group-divisible 2-design on six groups of size two, with block
   size three and cross-pair index four. In particular,

   \[
   |H|=80,\qquad
   d_H(P)=4\quad(P\notin M),\qquad
   d_H(x)=20\quad(x\in[12]).
   \]

   The last identity follows because the ten cross-pairs through \(x\)
   contribute \(10\cdot4\) incidences and every triple of \(H\) through
   \(x\) contains two such pairs.

4. Once \(H\) is fixed, every triple degree is an equality:

   \[
   \sum_{B\supseteq T}x_B=
   \begin{cases}
   4,&T\text{ contains a matching edge},\\
   3+\mathbf1_H(T),&T\text{ is transversal}.
   \end{cases}
   \]

   Together with the 66 pair equalities and \(\sum_Bx_B=40\), these form a
   pure 0/1 linear-equality **necessary system** for the block selection.
   Quadruple coverage is an additional condition and is not implied here.

The parity equations modulo two and three were checked symbolically but gave
no contradiction at this level.

## Proposed alternate certificate

The suggested alternate route is to enumerate the group-divisible designs
\(H\) up to the matching normalizer
\(S_6\ltimes(\mathbb Z/2\mathbb Z)^6\), add the local-link realizability
condition above, and then test the exact block equations for each canonical
\(H\). Equality-relaxation-infeasible cases could carry small rational Farkas
certificates. A surviving case would still need quadruple coverage and hence
SAT/ILP or a further certificate.

This is a concrete research direction, not part of the present proof. The
number of canonical \(H\) objects and the payoff of the LP stage were not
measured. The running exhaustive compact certificate remains the decisive
route.

## Discarded routes

- pair/triple parity modulo two: consistent;
- triple degrees modulo three: merely re-encode membership in \(H\);
- a direct Delsarte/LP bound: reproduces the lower bound 40 but not 41;
- block complementation: does not preserve the covering condition;
- block-intersection moments alone: too weak;
- counting that would force a type-3 block: false, since \(h=0\) survives the
  relaxation.

Claude explicitly reported that it had not found a hand contradiction and
had not detected an error in the existing reduction.
