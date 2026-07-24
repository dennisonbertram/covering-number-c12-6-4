# Fixed-link proof certificates

This component binds all 266 fixed-link CNFs to the production classification
manifest and to DRAT/LRAT release archives.  Every LRAT was accepted against
the same reconstructed CNF by both the small C `lrat-check` program and the
CakeML-extracted `cake_lpr` checker.

The two large deterministic archives are GitHub release assets, not Git
objects:

- `c12-fixed-link-drat.tar` (SHA-256
  `67acd4729329ad4656b5a94e8a472b11a14a5c81fccaa468448f12957663af4a`);
- `c12-fixed-link-lrat.tar` (SHA-256
  `c45ea9e621db38f4e25f290cb664352c0b80f1839ad475b422098b12fbbbd615`).

After downloading both assets and building the replay tools, run from the
repository root:

```sh
python3 -S certificates/fixed-link-proof/verify_public_release.py \
  --repo-root . \
  --release-assets certificates/fixed-link-proof/release-assets.json \
  --drat-archive PATH/c12-fixed-link-drat.tar \
  --lrat-archive PATH/c12-fixed-link-lrat.tar \
  --lrat-check .toolchain-build/lrat-check \
  --cake-lpr .toolchain-build/cake_lpr \
  --zstd /absolute/path/to/zstd
```

The verifier is fail-closed. It rejects optimized Python, unsafe or symlinked
paths, duplicate JSON keys and non-finite JSON constants, a missing/extra case
or file, any changed source/root/receipt/log/archive byte, and any failed C or
CakeML replay. It checksum-verifies the complete independent-classification
component, requires its exact final PASS line and stored representative list,
and accepts full replay only when the supplied checker binaries exactly match
the campaign-bound identities:

- `lrat-check`: 36,040 bytes, SHA-256
  `ac89c8365eaf6548b6237e6e3ff630373582e60854695491a99108df3a7db0e5`;
- `cake_lpr`: 546,984 bytes, SHA-256
  `9d26b48cb92a860568edea1b7febcebe98e265cc0e74e8c55faa0fac9e63eda7`.

The binaries may be built on Arm64 from the pinned source tree with
`toolchain/build-replay.sh`; the same exact binaries can also be distributed
beside the proof archives as `lrat-check-macos-arm64` and
`cake_lpr-macos-arm64`. After download, mark them executable and pass their
paths to `--lrat-check` and `--cake-lpr` in the command above. The filenames
are immaterial; the bytes are enforced. A marker-printing substitute or any
other changed executable is rejected before proof replay.

Stable logical identities:

- production fixed-link manifest:
  `d8b6d765c5b9f237633bd879f18b07daa98cfa1ed1b1f5d264d99e279a48fcd2`;
- 266-proof aggregate:
  `8735ea4aedb5d30fc1fa65ff289f4357bec14d354a993270a620254d30ff575a`;
- release-assets manifest:
  `499c345b3d48666b67b17df2dda79b6f7af5e7fa7c05668900eb9cd7b5bee2f6`.
