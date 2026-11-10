# The covering number \(C(12,6,4)\)

This repository contains a computer-assisted proof that

\[
C(12,6,4)=41.
\]

Here \(C(v,k,t)\) is the smallest number of \(k\)-subsets of a \(v\)-set
needed to cover every \(t\)-subset. At the start of this work, the maintained
public range was \(40\le C(12,6,4)\le41\).

## What is proved

The argument has three parts:

1. A local theorem proves \(C(10,4,2)=9\) and that every point in a
   nine-block optimum has degree three or four. One small finite case has
   both an exhaustive source-level verifier and independently replayed
   DRAT/LRAT certificates.
2. Any hypothetical 40-block \((12,6,4)\) cover is forced into a perfect
   matching equality case. The nine blocks through one fixed nonmatching
   pair form an optimal \(C(10,4,2)\) link in which two specified points have
   degree four.
3. There are 119,700 such labelled links. A structurally independent
   enumerator confirms that they form exactly 266 orbits under the
   order-768 matching-and-pair stabilizer. Every corresponding SAT root is
   unsatisfiable, and every LRAT certificate passes both the C and
   CakeML-extracted checkers. The 41-block upper-bound witness is checked
   directly.

The complete mathematical argument is in
[`proof/proof.md`](proof/proof.md), with a rendered version at
[`proof/proof.pdf`](proof/proof.pdf).

## Verification layers

The proof package separates four claims:

- **mathematical reduction:** the human-readable lemmas and exhaustive
  266-orbit fixed-link reduction;
- **encoding:** a byte-exact standard-library reconstruction and semantic
  proof of the compact production encoder, plus an independent
  full-equivalence functional-gate cross-check;
- **unsatisfiability:** DRAT replay followed by both C and CakeML-extracted
  LRAT replay; and
- **upper bound:** direct enumeration of all 495 quadruples against the
  41-block witness.

CP-SAT, Gurobi, and other exploratory computations are supporting evidence,
not proof.

The repository-resident verification entry point is:

```bash
./verify_all.sh
```

Without the two large release archives, this checks source and artifact
hashes, audits the CNFs, verifies the 41-block witness, reruns the independent
link classification, and then deliberately exits with status 2: structural
verification is not a proof-replay completion gate.

For the complete 266-case replay, download
`c12-fixed-link-drat.tar` and `c12-fixed-link-lrat.tar` from the
[`v1.0.0` proof release](https://github.com/dennisonbertram/covering-number-c12-6-4/releases/tag/v1.0.0),
then run:

```bash
export C1264_FIXED_LINK_DRAT_ARCHIVE=/absolute/path/c12-fixed-link-drat.tar
export C1264_FIXED_LINK_LRAT_ARCHIVE=/absolute/path/c12-fixed-link-lrat.tar
./verify_all.sh
```

Only this archive-backed run can print
`ALL RELEASE VERIFICATION GATES PASSED` and return status 0. See each
certificate directory for lower-level commands.

## Repository map

```text
proof/                  proof source and rendered note
data/                   checked 41-block construction
scripts/                deterministic verifiers and generators
certificates/local/     C(10,4,2) degree-five certificate
certificates/global/    audited compact base and earlier corroborating roots
certificates/functional/     independent functional-gate cross-check
certificates/compact-encoder-audit/
                            portable compact-encoder semantic audit
certificates/fixed-link-classification/
                            independent 359100/119700/266 partition audit
certificates/fixed-link-campaign/
                            production representatives and 266 exact roots
certificates/fixed-link-proof/
                            receipts, logs, archive indexes, public verifier
evidence/               prior-art, GitHub, web, and X search record
toolchain/              pinned checker source/build instructions
```

## Reproducibility and large files

DIMACS inputs, generators, auditors, logs, receipts, and SHA-256 manifests
live in the repository. The deterministic DRAT and LRAT archives are
published as release assets and pinned by both per-member and whole-archive
hashes. The release also includes the exact macOS Arm64 C and CakeML checker
binaries used for the frozen replay; the verifier enforces their byte
identities. No solver result is used without a successful independent replay.

## Cited by

- arXiv:2607.23766: Krug, "The covering number C(12, 6, 4) is 41".
- arXiv:2610.31696: Requeijo, "Links of minimum degree and exact covering
  numbers" (reference [2]).

## Novelty scope

At the publication-time refresh on 2026-07-24, the La Jolla Covering
Repository still displayed \(40\le C(12,6,4)\le41\). Six direct X recent
searches over an explicit seven-day window returned zero posts from both the
search and count endpoints, and refreshed indexed-web and GitHub searches
found no completed solution. The exact queries, timestamps, results, and
full-archive limitation are recorded in
[`evidence/x-publication-refresh-2026-07-24.md`](evidence/x-publication-refresh-2026-07-24.md)
and
[`evidence/publication-search-refresh-2026-07-24.md`](evidence/publication-search-refresh-2026-07-24.md).

This supports a novelty review; it does not prove universal priority or
replace external peer review.

## Assistance and review

The project was directed and published by Dennison Bertram. OpenAI Codex was
used for research, proof exploration, implementation, certificate
orchestration, auditing, and drafting. Claude Fable was asked to act as an
adversarial senior reviewer. Claude Opus 5 was separately asked for an
adversarial audit and independent mathematical ideas; that pass proposed the
decisive fixed-pair link split. Its bounded final assessment and the
independent reconstruction are recorded in
[`evidence/claude-opus-5-fixed-link-discovery.md`](evidence/claude-opus-5-fixed-link-discovery.md).
All machine-generated claims are exposed through source, logs, and
independently replayable certificates.

## License

Code is licensed under the MIT License. The proof note and prose are licensed
under Creative Commons Attribution 4.0; see `LICENSE-PAPER`.
