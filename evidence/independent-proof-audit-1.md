# Independent mathematical and certificate-architecture audit 1

Date: 2026-07-24  
Outcome at the audited snapshot: **GAP (global certificates pending)**

An independent review agent audited `proof/proof.md` without editing it and
without duplicating the running solver campaigns.

## Mathematical findings

The reviewer independently passed:

- the eight-block contradiction in the proof of \(C(10,4,2)=9\);
- the degree-six reduction and the certified degree-five finite case;
- the corrected Schönheim lower-bound chain;
- point regularity and the pair-excess perfect matching;
- the conclusion that every triple has degree three or four;
- the matching-type class sizes \(64,480,360,20\);
- the Burnside calculation, all 21 support-orbit counts, and the total 2,136;
- both tail profile formulas;
- the transitivity assertions and the four \(h=1,a=0\) orbits of sizes
  \(96,96,144,144\);
- the semantics of the functional prefix-counter recurrence; and
- the nine-block local witness and 41-block global witness.

The reviewer concluded that the mathematical reduction is sound conditional
on completing and replaying the exhaustive global leaf certificates.

## Publication blockers found

1. The manuscript mixed future-tense pending certificate state with
   completed-proof language.
2. Adaptive refinements can make the final leaf-certificate count larger than
   the 2,159 top-level mathematical roots.
3. The in-progress support package contained temporary absolute paths and was
   not yet portable.
4. The exact \(2^{20}\) support-family partition should be distinguished from
   refined witness roots, which form an exhaustive but possibly overlapping
   cover.
5. The compact cross-check was described as completed before its last
   receipts and independent production-encoder justification existed.
6. The orbit-enumerator prose overstated how many masks receive a fresh
   720-image computation.

## Resolution

The Schönheim inequality was corrected during the audit. The manuscript now
distinguishes top-level roots from final proof leaves, requires an audited
parent-to-children refinement tree, states the overlap caveat, accurately
describes the enumerator, and keeps the compact route conditional. The global
claim remains explicitly pending until every leaf has passed both LRAT
checkers and the fail-closed aggregate audit.
