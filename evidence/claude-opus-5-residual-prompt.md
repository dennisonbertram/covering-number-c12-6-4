# Independent Opus 5 residual attack on C(12,6,4)

You are a separate mathematical research collaborator. Use the canonical
`claude-opus-5` model at xhigh effort. Work read-only: do not edit files,
kill processes, or change the running campaign.

The repository is (local path normalized for publication):

`<repository-root>`

The active exhaustive campaign is (local path normalized for publication):

`<temporary-workspace>/fixed_support_formal/compact_campaign`

The proposed theorem is `C(12,6,4)=41`. Read `proof/proof.md`, the compact
campaign generators/manifests, and the existing Opus notes under `evidence/`.
The human reduction is already heavily audited. The current bottleneck is
finishing a small residual set of hard symmetry-refined compact SAT leaves
and packaging a complete independently replayable certificate.

Independently attack the remaining problem. Prioritize:

1. A rigorous hand contradiction that could replace or sharply reduce SAT.
2. Exact implied equalities, dominance lemmas, canonical splits, or smaller
   encodings that are logically entailed and would make hard residual leaves
   terminate.
3. A structurally different finite certificate (for example through the
   3-GDD `H`, local `C(10,4,2)` links, LP/Farkas, exact cover, or modular
   reasoning) only if it is demonstrably smaller or more robust.
4. Adversarially identify any logical gap in the claimed global exhaustion
   or certificate topology.

Do actual calculations and inspect the live hard cases rather than giving
generic SAT advice. You may run bounded read-only analyses or create files
only under a fresh temporary directory if calculations are necessary, but
do not interfere with active processes.

Return a concise research memo with:

- any proved new lemma, with proof;
- exact commands or patch-level algorithmic changes for the best solver
  improvement;
- measurements on representative hard leaves if you ran experiments;
- a clear distinction among proved, experimentally supported, and conjectural
  claims;
- your canonical model name as reported by the runtime.

If no improvement is found, say so plainly and report what you ruled out.
