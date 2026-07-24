# v1.0.0 — Proof that \(C(12,6,4)=41\)

This release contains the complete computer-assisted proof, the checked
41-block construction, deterministic generators and auditors, 266
case receipts, and independently replayable DRAT/LRAT certificates.

The lower bound has three layers:

1. the equality case of a hypothetical 40-block cover forces six
   pair-degree excesses to form a perfect matching;
2. the link of one fixed nonmatching pair is one of exactly 266 canonical
   admissible nine-block \((10,4,2)\) links; and
3. all 266 resulting CNFs are UNSAT.

Every LRAT proof was replayed against its freshly reconstructed CNF by both
the independent C `lrat-check` program and the CakeML-extracted `cake_lpr`
checker.

## Release assets

| Asset | Bytes | SHA-256 |
|---|---:|---|
| `c12-fixed-link-drat.tar` | 924,200,960 | `67acd4729329ad4656b5a94e8a472b11a14a5c81fccaa468448f12957663af4a` |
| `c12-fixed-link-lrat.tar` | 221,736,960 | `c45ea9e621db38f4e25f290cb664352c0b80f1839ad475b422098b12fbbbd615` |
| `release-assets.json` | 166,716 | `8f43378cc80c8a055f51e4dccc486feb26ee7f94f29aec8404bb059fc98d725d` |
| `lrat-check-macos-arm64` | 36,040 | `ac89c8365eaf6548b6237e6e3ff630373582e60854695491a99108df3a7db0e5` |
| `cake_lpr-macos-arm64` | 546,984 | `9d26b48cb92a860568edea1b7febcebe98e265cc0e74e8c55faa0fac9e63eda7` |
| `proof.pdf` | 276,669 | `96847341922378b26bcefc4fef6f9d79e8d0e51b5a7db1dd00d1407f9b1b6c78` |

`RELEASE_SHA256SUMS.txt` contains these six asset identities in a directly
checkable format.

Stable logical identities:

- production classification:
  `d8b6d765c5b9f237633bd879f18b07daa98cfa1ed1b1f5d264d99e279a48fcd2`;
- 266-proof aggregate:
  `8735ea4aedb5d30fc1fa65ff289f4357bec14d354a993270a620254d30ff575a`;
- release-assets manifest:
  `499c345b3d48666b67b17df2dda79b6f7af5e7fa7c05668900eb9cd7b5bee2f6`.

This is a public computer-assisted proof and evidence package, not a claim
of completed journal peer review.
