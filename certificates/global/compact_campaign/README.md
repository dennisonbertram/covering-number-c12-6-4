# Portable compact campaign skeleton

This directory is the repository-local input for the standard-library-only
profile-leaf reconstruction audit. It contains:

- the one shared 356,407-clause compact base;
- all 2,136 fixed-support root-unit files;
- the frozen parent manifest and provenance-bound portable variants of the
  ordinary, h=0, and h=1 manifests, plus all four generators;
- one manifest-listed retained CNF per refined family, so Git preserves each
  `cases/` directory and the audit exercises its byte-for-byte file comparison.

The other 152 refined CNFs are deliberately not duplicated. The leaf audit
reconstructs all 155 extensions and full CNFs in memory and checks every final
size and SHA-256 against the frozen manifests.

The three suite manifests replace only staging-machine path fields with
`../global_base.cnf` (and `../manifest.json` for the ordinary parent link).
Each records the exact original frozen manifest/file SHA-256 under
`portable_provenance`; `build_portable_manifests.py` reproduces the transform.

From the repository root:

```sh
python3 -S certificates/compact-leaf-extension-audit/audit_leaf_extensions.py \
  --campaign-root certificates/global/compact_campaign \
  --report /tmp/c12-compact-leaf-audit.json
```

The logical audit SHA-256 must be
`3bd5008b2a345296385e7abc1356fc5bbb83a037305b93a7a966e7e8467370e5`.
The report also pins the accepted portable manifests under
`input_manifest_variants` and the independently recomputed ordinary, `h=0`,
and `h=1` coverage under `partition_exhaustion`.
