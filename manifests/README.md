# Release manifest policy

`release-components.json` is the repository-level release index. The Git
commit is the trust root; the index pins each completed component manifest by
SHA-256, and each component manifest pins the bytes it covers.

The index is deliberately fail closed:

- every component is explicitly `complete` or `pending`;
- a `complete` component must have a regular, non-symlink checksum manifest
  with the exact pinned digest;
- every checksum entry must resolve inside this repository and must be a
  regular, non-symlink file;
- duplicate paths, malformed hashes, path escapes, and unlisted required
  artifacts are errors;
- the exact required component-ID and manifest-path set is fixed in the
  verifier, so deleting a component cannot turn a pending release complete;
  and
- `release_state` can be `complete` only when no component is pending.

The decisive lower-bound certificate is split into three completed,
independently pinned components:

1. `fixed-link-classification` enumerates all admissible nine-block links and
   proves that they form exactly 266 matching-stabilizer orbits;
2. `fixed-link-campaign` binds one 210-unit root and reconstructed global CNF
   identity to each orbit; and
3. `fixed-link-proof` binds every reconstructed CNF to its DRAT/LRAT receipt,
   logs, and deterministic release-archive member.

Running `scripts/verify_all.sh` without the two large release archives checks
all in-repository structure and reruns the independent classification, then
deliberately exits with status 2. That is not a proof-replay completion gate.
For a complete dual-checker replay, set:

```sh
export C1264_FIXED_LINK_DRAT_ARCHIVE=/absolute/path/c12-fixed-link-drat.tar
export C1264_FIXED_LINK_LRAT_ARCHIVE=/absolute/path/c12-fixed-link-lrat.tar
./verify_all.sh
```

Only that archive-backed run can print
`ALL RELEASE VERIFICATION GATES PASSED` and return status 0.
