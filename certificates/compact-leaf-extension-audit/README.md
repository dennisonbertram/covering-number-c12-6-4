# Compact profile-leaf extension audit

`audit_leaf_extensions.py` closes the semantic link between the frozen compact
base and all profile-refinement CNFs. It uses only the Python standard library
and the hash-pinned pure-Python kmtotalizer transcription in the sibling
`compact-encoder-audit` certificate.

The audit reconstructs every `CardEnc.equals` section, including exact clause
order and auxiliary IDs, then authenticates the reconstructed extension and
complete-CNF size and SHA-256 for:

- 130 ordinary profile/stabilizer leaves;
- 11 h=0 leaves;
- 14 h=1 leaves.

All 155 complete CNFs are reconstructed in memory and checked by frozen size
and SHA-256. In addition, the portable campaign must retain one designated,
manifest-listed CNF from each family; those three files are compared byte for
byte and their required count is recorded in the report. Missing retained
files, unexpected case files, symlinked family trees, and a preloaded encoder
module cache all fail closed.

The same standard-library auditor also independently recomputes the full
refinement partition rather than trusting its descriptive metadata. It checks
the seven ordinary parent orbits, every feasible type profile, the
`C2^6`-by-support-stabilizer block orbits and canonical witnesses, uniqueness
of all 130 ordinary children, both `h=0` witness orbits, all four `h=1`
type-1 stabilizer orbits, and the exact links from the `h=0` and `h=1`
families to compact roots 0 and 1. The report exposes these checks under
`partition_exhaustion`.

Both the original frozen suite manifests and the portable, provenance-bound
manifests are accepted under distinct pinned hashes. The published report is
generated against the portable campaign and records the accepted identities
under `input_manifest_variants`.

Run:

```bash
python3 -S certificates/compact-leaf-extension-audit/audit_leaf_extensions.py \
  --campaign-root /path/to/compact_campaign
```

The report is written to `results/AUDIT_REPORT.json`.
