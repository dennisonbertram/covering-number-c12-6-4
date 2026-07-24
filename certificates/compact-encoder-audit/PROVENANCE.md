# Compact-encoder audit provenance

The integrated files come from one completed independent audit run of the
compact Python-SAT k-modulo-totalizer encoding. The original artifact manifest
is preserved byte for byte as `SOURCE_ARTIFACT_SHA256SUMS`.

Stable original hashes:

```text
8403354713a64ba0189e6d72ca3b86f1636167bd8e7a1d34b78cc316e8b8cec3  audit_kmtotalizer.py
f24ae7bd8028a100625373f0f7a5f6ab39b65d5026555ae1b8917c72a833701a  results/AUDIT_REPORT.json
7ea0f285b6a2b5c3771ccbf5ddad42e1fd1898bc02158f13bce1b4599e4d420b  results/official_source_reference
637d9326388f77f933f3d066cd762d8c0ac4b2df0d2260d688e031d55959e7f0  results/reconstructed_global_base.cnf
00a99825b80170c154231233705f3e2a67d54dc119ab11300527291f25abd239  results/production_boundaries.json
```

The platform-specific compiled adapter is not distributed. The portable
verifier rebuilds it from `source_reference_driver.cc` and the pinned source
snapshot. The original run report contained machine-specific paths, so the
repository contains a path-free summary that records the original report hash.

The integrated `audit_kmtotalizer.py` differs from the source artifact only in
three release-hardening changes:

1. it refuses optimized `python -O` execution;
2. `--target` and `--source-repo` are explicit required inputs; and
3. generated output defaults under the repository's ignored `.verification`
   directory.

No encoder, semantic-checker, source-comparison, reconstruction, or hash logic
was changed. `SOURCE_PIN.json`, `source_reference_driver.cc`, the reconstructed
base, and the boundary file remain byte identical to the completed artifact.

The source snapshot was extracted from the official Python-SAT Git object at
commit `7abb1d6fdafe1d75fe3e5cdfb48f7e07a8a76efd`. Its individual files are
pinned by this directory's `SHA256SUMS`; the six files used as the source
specification are additionally pinned in `SOURCE_PIN.json`.
