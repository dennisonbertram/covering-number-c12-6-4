# Claude Opus 5 adversarial review 1

Date: 2026-07-24  
Model requested: `claude-opus-5`  
Canonical model reported by Claude Code: `claude-opus-5`  
Effort: xhigh  
Outcome at the reviewed snapshot: **GAP (global certificates pending)**

This was a separate high-effort adversarial review of the manuscript,
certificate architecture, and the proposed functional strengthening. The
Claude Code result metadata confirmed that the call used the canonical
`claude-opus-5` model rather than an alias or fallback.

## Mathematical assessment

The reviewer independently passed the human mathematical spine:

- the local \(C(10,4,2)=9\) argument, conditional only on replaying its
  already packaged finite certificate;
- the Schönheim lower bound of 40;
- regularity, pair degrees, and the perfect matching of pair excesses in a
  hypothetical 40-cover;
- the degree-three-or-four triple reduction;
- the matching-type counts and Burnside support-orbit count;
- the \(h=0\) and \(h=1\) tail reductions; and
- the logical validity of functional strengthenings A and B.

It found no human combinatorial error. Its overall verdict remained GAP
solely because the global leaf corpus and aggregate replay were incomplete at
the time of review.

## Hardening findings

1. Python proof auditors and generators used `assert` and therefore needed to
   refuse `python -O`; otherwise they could become fail-open.
2. One local-auditor comment overstated an arithmetic sanity loop as the
   semantic argument. The gate truth-table audit and recurrence induction are
   the actual justification.
3. The manuscript must either create a repository-wide SHA-256 manifest or
   narrow any claim that every source and artifact is covered.
4. Pending certificate tables and present-tense proof claims must agree.
5. Every refinement child must retain the full base and all ancestor
   constraints; every symmetry group must stabilize the complete ancestor
   state; every terminal node must identify and replay its own pinned CNF.
6. The release needs a fail-closed `verify_all.sh`.

Items 1, 2, and 5 were immediately incorporated into the working tree. The
remaining packaging items are release gates.

## Additional propagation idea

For a quadruple \(Q\), write \(r_Q\) for its block degree. Then
\(1\le r_Q\le4\), and the total quadruple excess is

\[
\sum_Q(r_Q-1)=40\binom64-\binom{12}4=600-495=105.
\]

Moreover, if \(r_T=3\) for a triple \(T\), then each of the nine quadruples
\(Q\supset T\) has \(r_Q=1\). The reviewer suggested a cheap implied
strengthening using degree-at-least-two quadruple indicators and the
implications

\[
(r_T\ge4)\ \lor\ \neg(r_Q\ge2)\qquad(T\subset Q),
\]

with the exact excess identity available as a stronger fallback. This idea
was forwarded to the functional-certificate campaign but is not treated as a
proof result unless its encoder and clauses are independently audited.
