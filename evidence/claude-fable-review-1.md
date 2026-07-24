# Claude Fable adversarial review 1

Date: 2026-07-24  
Model: Claude Fable  
Effort: xhigh  
Role: adversarial combinatorics and formal-methods reviewer  
Outcome returned by reviewer: **GAP**

This is a faithful resolution record, not a claim that the first review
approved the result. The reviewer was asked to rederive the normalized
40-block reduction, the type-3 support-family orbit exhaustion, the \(h=0\)
and \(h=1\) tail splits, the CNF semantics, and the fail-closed audit
obligations.

## What the reviewer independently confirmed

The reviewer reported no mathematical error in the material it could read and
independently rederived:

- the point- and pair-degree equality case and its perfect matching;
- the compact base as a necessary-condition encoding of any 40-block cover;
- the type histogram \((64,480,360,20)\);
- the Burnside count of 2,136 \(S_6\)-orbits of subsets of the 20 type-3
  blocks;
- the 11 profiles
  \((a,20-2a,20+a,0)\), \(0\le a\le10\), for \(h=0\);
- the 11 profiles
  \((a,21-2a,18+a,1)\), \(0\le a\le10\), for \(h=1\);
- the four \(h=1\), \(a=0\) type-1 stabilizer orbits, of sizes
  \(96,96,144,144\); and
- the arithmetic \(2,134+11+14=2,159\) for the refined certificate
  partition.

For the 2,136 orbit count, the reviewer independently applied Burnside's
lemma to the 11 cycle types of \(S_6\). The fixed-family contributions summed
to 1,537,920, which divided by \(|S_6|=720\) gives 2,136.

## Why the outcome was GAP

The reviewer identified three material publication blockers.

1. Its Claude CLI sandbox could not read the campaign files under `/tmp`, so
   it could not inspect or execute the support-campaign generators and
   auditors. Those obligations therefore remained unverified in that review.
2. The manuscript described only the broad two-root reduction, not the
   2,159-certificate support partition that was becoming the actual proof
   route.
3. The compact PySAT encoding's production-size cardinality semantics were
   cross-checked by re-encoding with the same library and by small truth
   tables. The reviewer correctly observed that this does not exclude a
   size-dependent encoder bug. It recommended completing the independently
   generated functional-gate encoding or proving the production encoder
   semantics.

The reviewer also requested one small clarification in the local degree-six
argument: state explicitly why every remaining point occurs in an incident
triple.

## Resolution plan adopted

- The local clarification was added immediately.
- The completed campaign sources, manifests, results, and auditors will be
  vendored into this repository before final review, so the next Claude
  session can read and run them.
- The paper will state and prove the complete support-family and tail
  partition.
- The global claim will not rely only on the PySAT encoding. A second
  production encoding uses explicit functional prefix-counter equivalences,
  with every gate independently truth-table checked. Its exhaustive UNSAT
  certificate campaign and dual LRAT replay are required before the result is
  labeled complete.

The final review is recorded separately and must be read together with this
initial GAP outcome.
