# Claude Opus 5 fixed-link discovery pass

Date: 2026-07-24  
Model requested: `claude-opus-5`  
Canonical model reported by Claude Code: `claude-opus-5`  
Effort: xhigh  
Claude session: `9a225a89-faaa-4ac9-9c1d-370853f1dd64`  
Outcome: **decisive new reduction, subsequently rebuilt and certified**

This was a separate asynchronous research pass after an earlier Opus 5
exploration had found useful identities but no complete route. Claude was
asked to attack the remaining hard cases independently and to distinguish
proved statements, exhaustive-computation claims, measurements, and
conjectures.

## The proposed reduction

Claude observed that the entire global case split can be replaced by the
link of one fixed nonmatching pair. Normalize the six excess pairs as

```text
01 23 45 67 89 (10)(11)
```

and fix \(P=\{0,2\}\). In a hypothetical 40-block cover:

1. exactly nine blocks contain \(P\);
2. deleting \(P\) from those blocks gives an optimal nine-block
   \((10,4,2)\) covering;
3. points 1 and 3 have degree four in that link, because the global triples
   \(012\) and \(023\) contain matching edges; and
4. the stabilizer of the matching and \(P\) has order 768.

Claude's exploratory enumerator reported:

- 359,100 labelled nine-block \((10,4,2)\) coverings;
- 119,700 in which both specified partner points have degree four; and
- 266 orbits under the order-768 stabilizer.

Each orbit representative fixes all 210 possible global blocks through
\(P\): nine positive units and 201 negative units. Appending those units to
the already audited shared formula therefore gives only 266 roots, replacing
the much larger support-family campaign.

Claude then ran a first solver sweep and reported all 266 roots
unsatisfiable. It correctly labelled that sweep as experimental rather than
as proof, and recommended an independent re-enumeration plus replayable
certificates.

## Opus 5's final assessment

After the exploratory work, the same Claude session was resumed and asked
for a bounded final assessment without further tools. It judged the
266-root route mathematically sound conditional on two explicit gates:

1. the 359,100-cover classification must be independently re-enumerated and
   hashed, because Claude's own second implementation did not finish; and
2. the full proof corpus must be replayed, including the CakeML checker,
   which Claude had not run.

Claude also reported no gap in its adversarial re-derivation of the older
equality-case reduction. It distinguished its complete 266-root solver sweep
and 12-root proof sample as measurements, not certificates.

## Independent reconstruction and certification

Codex did not import Claude's exploratory enumeration as a trusted artifact.
The production proof package independently:

- enumerates the 359,100 links with a fail-closed canonical search;
- reconstructs the same set by a structurally different heavy/light
  decomposition;
- checks the 119,700 admissible links and the complete order-768 group;
- verifies that 266 disjoint orbits cover all 119,700 links;
- rebuilds every 210-unit root from its stored representative;
- regenerates every DIMACS file from the pinned shared base; and
- replays every one of the 266 UNSAT proofs with both the independent C
  `lrat-check` implementation and the CakeML-extracted `cake_lpr` checker.

Thus the mathematical idea came from the requested independent Opus 5 pass,
while every finite claim used in the proof was separately reconstructed,
hashed, and checked. No assertion by Claude or any other language model is
used as proof evidence.
