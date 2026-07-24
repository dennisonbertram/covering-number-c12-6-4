# Independent compact-encoder audit

This directory contains an independent semantic and byte-level audit of the
compact Python-SAT k-modulo-totalizer base used in the \(C(12,6,4)\)
calculation.

This is a portable integration of the completed audit artifact. It establishes
the semantics and byte identity of the compact **encoding base only**. It does
not establish UNSAT and must not be cited as completing the global theorem
without independently replayed global proof certificates.

The main auditor, `audit_kmtotalizer.py`, uses only the Python standard
library. It does not import Python-SAT. It:

1. verifies an exact official-source commit and six source-file hashes;
2. compiles a logic-free adapter against those pinned official headers;
3. compares 115 official C++ vectors (123,220 clauses) with the pure-Python
   transcription;
4. exhaustively checks 5,376 small primary assignments with its own DPLL
   checker;
5. reconstructs all 356,407 production clauses and all auxiliary IDs; and
6. requires byte-for-byte equality with the supplied `global_base.cnf`.

The result is **PASS**. The reconstructed production SHA-256 is
`637d9326388f77f933f3d066cd762d8c0ac4b2df0d2260d688e031d55959e7f0`.

See `SEMANTIC_PROOF.md` for the induction proof of the unary totalizer,
truncated modulo merge, comparator, and wrapper semantics.

## Offline replay

The frozen package includes the pinned official header snapshot, the exact
production base, and a standard-library verifier. It reconstructs the base,
repeats all 5,376 small existential checks, compiles the source-reference
adapter against the pinned headers, and compares all 115 official-source
vectors:

```sh
python3 certificates/compact-encoder-audit/verify_frozen_audit.py
```

The command writes only to an automatically removed scratch directory.

## Fresh source-pin replay

Clone the official source (or point to an existing clone), then run:

```sh
git clone https://github.com/pysathq/pysat.git .verification/pysat-upstream
python3 -S certificates/compact-encoder-audit/audit_kmtotalizer.py \
  --source-repo .verification/pysat-upstream \
  --target certificates/compact-encoder-audit/results/reconstructed_global_base.cnf \
  --output-dir .verification/compact-encoder-audit \
  --small-max-arity 7
```

The source repository need not be checked out: the audit reads the pinned
commit directly from its object database.

## Stable evidence

- production file:
  `637d9326388f77f933f3d066cd762d8c0ac4b2df0d2260d688e031d55959e7f0`;
- production body:
  `6a1a2eb2843a4ddcf9138c5a85aaeccd2950b3e099e0ab8a26ce9fc815ab0cc5`;
- pretty boundary manifest:
  `00a99825b80170c154231233705f3e2a67d54dc119ab11300527291f25abd239`;
- canonical boundary data:
  `e8faba67dca00bd9fd889996c93667ad2742409bb4619d3c9d4352ce365471d8`;
- exhaustive small clause vectors:
  `4593235969317bb0f45f657a38cea53c5753cffcebb713adddee3d3cde36e7e4`;
- official C++ comparison manifest:
  `f3d5fa319a43347b79b471aa646d62a2ccd1569fdda4e84de4e228b35bb61eb7`.

`results/AUDIT_REPORT.json` is a path-free portable summary of the completed
run. `PROVENANCE.md` pins the original machine-specific report and compiled
adapter hashes without publishing staging paths or a platform-specific binary.
`SOURCE_ARTIFACT_SHA256SUMS` is the original package manifest.
