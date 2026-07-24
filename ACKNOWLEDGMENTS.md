# Acknowledgments and computational disclosure

Dennison Bertram directed this project and is responsible for publishing the
result.

OpenAI Codex assisted with problem selection, literature and public-search
work, mathematical exploration, finite-model implementation, independent
audits, proof-certificate orchestration, verification, and drafting.

Claude Fable was asked to perform an adversarial senior review of the complete
reduction and proof artifacts at xhigh effort. Its review outcome and any
repairs adopted from it are recorded in
`evidence/claude-fable-review-1.md` and
`evidence/claude-fable-strengthening-review.md`.

Claude Opus 5 was separately asked at xhigh effort for both an adversarial
certificate review and an independent search for new mathematical structure.
It proposed the decisive fixed-nonmatching-pair link partition that reduced
the global computation to 266 canonical cases. Codex then rebuilt and audited
that partition independently before using it. The exact canonical model
identity reported by Claude Code and the resulting review record are included
in `evidence/claude-opus-5-fixed-link-discovery.md`.

The 41-block upper-bound construction is from the La Jolla Covering
Repository and is credited in the proof and data files. CaDiCaL, PySAT,
drat-trim, and lrat-check are third-party open-source tools; exact versions
and source revisions are pinned in `toolchain/`.

No model's assertion of correctness is used as proof. The computational
claims are represented by deterministic source, pinned CNFs, hash manifests,
and independently replayable proof certificates.
