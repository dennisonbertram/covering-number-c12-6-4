# Claude Fable strengthening review

Date: 2026-07-24  
Model: Claude Fable  
Effort: xhigh  
Question: are the proposed exact-pair and triple-lower threshold units
logically implied, and what other auditable constraints could help the hard
low-support roots?  
Outcome: **PASS**

Claude read `proof/proof.md`, `certificates/functional/README.md`, and the
functional generator. It independently checked the 270,144-gate count and
the four-clause equivalence used for each threshold recurrence.

## Passed strengthening

The reviewer passed the proposal to append 286 positive units on existing
functional-counter outputs:

- six matching-pair thresholds asserting degree at least 10;
- 60 nonmatching-pair thresholds asserting degree at least 9; and
- 220 triple thresholds asserting degree at least 3.

Its proof was:

1. Exactly 40 blocks have \(40\binom62=600\) pair incidences.
2. The 66 pair ceilings sum to
   \(6\cdot10+60\cdot9=600\).
3. Therefore every pair ceiling is attained.
4. For a triple \(T\), the nine quadruples \(T\cup\{z\}\) must be covered,
   while one block through \(T\) covers only three choices of \(z\).
   Therefore \(r_T\ge3\).
5. Full-equivalence prefix counters give each primary assignment a unique
   auxiliary extension, so the positive threshold literals have exactly
   these meanings.

Thus every model of the unstrengthened base already satisfies all 286 units.
The strengthened formula has exactly the same primary models.

The reviewer also explained why the units should improve propagation:
negative block decisions can now propagate backward through asserted lower
thresholds and force surviving block variables positive, while the old base
made the global pair-equality argument available to CDCL only indirectly.
It explicitly labeled this speedup as a prediction pending measurement.

## Additional passed consequences

The reviewer derived two stronger, still structurally auditable facts.

First, all 60 triples containing a matching pair have degree exactly four.
For a matching pair \(P\), its ten blocks contribute 40 incidences among the
ten triples \(P\cup\{z\}\). Each such triple has degree at most four, so all
ten attain four.

Second, for each nonmatching pair \(P\), exactly six of its ten containing
triples have degree four. Its nine blocks contribute 36 triple incidences,
and each of the ten triple degrees is either three or four. Hence exactly six
are four.

The first consequence needs only 60 further positive units on existing
triple threshold variables. The second can be encoded by 60 small
full-equivalence exact-six counters over existing degree-four threshold
literals.

Other lower-priority suggestions were exact point-degree counters, the global
count of 140 degree-four triples, and stabilizer-orbit witness refinements for
hard \(h=2\) profiles. No file was changed by Claude, and no performance claim
was treated as a proof result.
