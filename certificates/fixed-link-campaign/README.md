# Fixed-link classification campaign

This directory is a portable, pure-Python certificate for the fixed-link
classification used by the `C(12,6,4)` proof campaign.  It fixes the
nonmatching pair `P = {0,2}` and identifies the remaining local points with

```text
[1,3,4,5,6,7,8,9,10,11].
```

A link is a set of nine local 4-blocks covering every local pair.  The two
distinguished local points `0,1` are the partners `1,3` of the fixed pair.
The classification retains exactly the links in which both distinguished
points have degree four, then quotients by

```text
Gamma = S2 x (C2 wr S4),  |Gamma| = 768.
```

## Frozen results

- No eight-block local cover exists.  The auditor exhausts all 55 possible
  degree patterns (`one degree 5` or `two degrees 4`) and finds zero.
- There are exactly `359100` nine-block pair covers.
- Every such cover has degree multiset `3^4 4^6`.
- Exactly `119700` pass the distinguished-partner degree-four filter.
- The exact Gamma action partitions those links into `266` disjoint orbits.
- The orbit-size sum is `119700`; the stabilizer and orbit histograms satisfy
  orbit-stabilizer for every representative.
- `link_representatives.txt` stores the 266 canonical representatives in the
  same byte format as the independent conceptual classifier.  Its SHA-256 is
  `369a844c4590d435fc24f82424a0775d51ce326d243aaf740d025c52c81d652b`.
- `roots/` stores one exact 210-unit root per orbit: nine positive and 201
  negative units, ordered by the global primary variable for the 210
  6-blocks containing `P`.
- Every root and derived case hash is bound to the compact global base
  `637d9326388f77f933f3d066cd762d8c0ac4b2df0d2260d688e031d55959e7f0`.

The independent crosscheck also compared all 266 stored root files byte for
byte and all 266 derived case-CNF SHA-256 values with the separately generated
proof-run manifest.  It reconstructed the conceptual representative text and
conceptual case-hash manifest as well.  `results/CROSSCHECK_REPORT.json`
records that PASS.  The proof-run archive itself is intentionally external to
this portable classification component.

## Files

- `generate_fixed_link_classification.py` independently enumerates the local
  universes, constructs Gamma, classifies the orbits, and emits the frozen
  manifest, representative list, and roots.
- `audit_fixed_link_classification.py` re-enumerates the universes and group
  from first principles.  It rejects duplicate JSON keys, unsafe paths,
  symlinks, source drift, manifest drift, non-unique group elements, missing
  inverses, closure failures, orbit overlap, incomplete orbit union, altered
  representatives, altered roots, and changed case hashes.
- `crosscheck_fixed_link_classification.py` compares this component against an
  independent proof-run manifest and the conceptual classifier report.
- `manifest.json` contains every representative, lifted block, signed unit,
  orbit/stabilizer record, per-root hash, per-case hash, source hash, compact
  base binding, and a logical self-hash.
- `results/VALIDATION_REPORT.json` records the frozen audit, deterministic
  replay, all-case crosscheck, and deliberate fail-closed negative tests.
- `SHA256SUMS` binds every component file except `SHA256SUMS` itself.

All three programs use only the Python standard library and refuse optimized
Python (`python -O`), so checks cannot be disabled accidentally.

## Frozen audit

Run from the repository root:

```sh
python3 -S certificates/fixed-link-campaign/audit_fixed_link_classification.py \
  --artifact-dir certificates/fixed-link-campaign \
  --base certificates/global/compact_campaign/global_base.cnf \
  --report certificates/fixed-link-campaign/results/AUDIT_REPORT.json
```

The expected logical audit hash is
`1d9ae10ba0f624ee76eaed1ce2c189314ec8218052dea4da81c9509b39790f54`.
The expected logical manifest self-hash is
`d8b6d765c5b9f237633bd879f18b07daa98cfa1ed1b1f5d264d99e279a48fcd2`.

## Deterministic scratch regeneration

Copy the two proof programs into a new scratch directory before generation so
the generated manifest can bind and the auditor can verify the exact source
files:

```sh
artifact_dir="$(mktemp -d "${TMPDIR:-/tmp}/c12-link-replay.XXXXXX")"
cp certificates/fixed-link-campaign/generate_fixed_link_classification.py \
   certificates/fixed-link-campaign/audit_fixed_link_classification.py \
   "$artifact_dir/"
python3 -S "$artifact_dir/generate_fixed_link_classification.py" \
  --base certificates/global/compact_campaign/global_base.cnf \
  --output-dir "$artifact_dir"
python3 -S "$artifact_dir/audit_fixed_link_classification.py" \
  --artifact-dir "$artifact_dir" \
  --base certificates/global/compact_campaign/global_base.cnf
cmp "$artifact_dir/manifest.json" \
    certificates/fixed-link-campaign/manifest.json
cmp "$artifact_dir/link_representatives.txt" \
    certificates/fixed-link-campaign/link_representatives.txt
```

The generator emits the same manifest and all 266 roots deterministically.

## External all-case crosscheck

When the independent proof-run manifest and its roots are available:

```sh
python3 -S certificates/fixed-link-campaign/crosscheck_fixed_link_classification.py \
  --production-dir certificates/fixed-link-campaign \
  --proof-manifest /path/to/proof-run/manifest.json \
  --conceptual-report \
    certificates/fixed-link-classification/results/AUDIT_REPORT.json \
  --output certificates/fixed-link-campaign/results/CROSSCHECK_REPORT.json
```

The frozen conceptual case-manifest hash is
`3352f4cfa1009d09fda4e7af6c5a06b4fd6821fd5437f7a707b357d8c31dc8be`.
