# Functional h=2 independent validation

This directory records a second, nonessential validation of one fixed-support
root used while developing the exhaustive compact certificate. It is not the
global proof corpus and must not be described as one.

The validated root is `ordinary_0002_h02_m00003`: one of the three support
orbits with exactly two selected type-3 blocks. Its orbit contains 90 of the
`2^20` labelled supports. The validation therefore covers exactly:

- `1/2159` top-level roots in the functional partition;
- `90/1048576` labelled functional supports;
- one of three h=2 support orbits, not the complete h=2 suite.

For this fixed root, the type-count identities force the twelve disjoint
profiles

`(n0,n1,n2,n3) = (a, 22-2a, 16+a, 2)`, for `a=0,...,11`.

All twelve profiles have independently checked UNSAT proofs. Profiles
`a=0,10,11` close directly after redundant strengthening A. Profiles
`a=1,...,9` close after redundant strengthening B and an exact
fixed-support-stabilizer orbit normalization. Each leaf was checked first as
binary DRAT and then as LRAT. The aggregate audit reconstructed all twelve CNFs
byte for byte, rehashed every CNF/DRAT/LRAT/log, verified both checker markers,
and reran five pinned mathematical and artifact auditors. The optional
quadruple-implication fallback was not invoked.

The raw evidence is intentionally absent from Git:

- CNFs: 262,678,992 bytes
- binary DRAT: 421,692,515 bytes
- LRAT: 1,184,394,893 bytes
- verification logs: 312,023 bytes

`certificate.json` is the immutable path-independent inventory for a release
asset named `functional_h2_validation_artifacts_v1.tar.zst`. Until that asset's
hash and byte count are filled in, the Git package proves only the inventory's
internal consistency; it does not let a fresh machine replay the large proofs.

Run the small check:

```bash
python3 evidence/functional_h2_validation/verify_portable_certificate.py
```

After extracting the release asset, rehash and replay both proof formats:

```bash
python3 evidence/functional_h2_validation/verify_portable_certificate.py \
  --artifact-root /path/to/extracted/bundle \
  --drat-trim /path/to/drat-trim \
  --lrat-check /path/to/lrat-check
```

The checker binaries are pinned by SHA-256 in `certificate.json`.
