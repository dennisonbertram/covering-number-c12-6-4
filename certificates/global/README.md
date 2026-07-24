# Shared global encoding and two-root corroboration

These two CNFs exhaust every hypothetical 40-block
\((12,6,4)\) covering after the perfect-matching normalization proved in
`proof/proof.md`. They are retained as an independent encoding and reduction
crosscheck. The decisive published lower-bound replay uses the finer
fixed-link classification and its 266 proof cases in
`../fixed-link-classification/`, `../fixed-link-campaign/`, and
`../fixed-link-proof/`.

## Shared encoding

There is one primary variable for each of the 924 six-subsets of 12 points.
The compact shared base asserts:

- exactly 40 selected blocks;
- pair degree at most 10 on
  \((0,1),(2,3),\ldots,(10,11)\);
- pair degree at most 9 on every other pair;
- triple degree at most four; and
- coverage of every quadruple.

The pair ceilings sum to 600, exactly the total pair incidence of 40
six-blocks, so they force the advertised pair equalities.

Root 0 selects the canonical type-0 block
`0 2 4 6 8 10`. Root 1 forbids all 64 type-0 blocks and selects the
canonical type-1 block `0 1 4 6 8 10`. The matching stabilizer is
transitive on each respective type, and the trace identities guarantee that
one of these roots applies.

## Pinned inputs

```text
ec71e1f3990beeb6889d8d0b359a8810fd2886e36cc0ce1725353231f1077f4e  root0.cnf
4aeada9818cf66895bc8dc7ffb341d4edba1f0ffc997a62e40c50d360161d96d  root1.cnf
20b1fbd9ff3037efe2f0cc0bd49f09fac56f23562cf2cc37fd95b36672343d66  root0.json
1d63b31c46389ef49152f3a2c963f1b70914560cba555000cc43d6efd06d43eb  root1.json
```

The shared 356,407-clause base has SHA-256
`6a1a2eb2843a4ddcf9138c5a85aaeccd2950b3e099e0ab8a26ce9fc815ab0cc5`.

## Regenerate and audit

From the repository root:

```bash
python3 scripts/generate_global_roots.py \
  --root 0 \
  --output /tmp/root0.cnf \
  --metadata /tmp/root0.json

python3 scripts/generate_global_roots.py \
  --root 1 \
  --output /tmp/root1.cnf \
  --metadata /tmp/root1.json

cmp /tmp/root0.cnf certificates/global/root0.cnf
cmp /tmp/root1.cnf certificates/global/root1.cnf
python3 scripts/audit_global_roots.py \
  --artifact-dir certificates/global
```

The decisive audit line is:

```text
"result": "COMPACT ROOT AUDIT PASSED"
```

The auditor does not import the generator. It independently reconstructs the
block list, cardinality specifications, kmtotalizer clauses, coverage
clauses, 221 matching-type profiles, and both symmetry orbits. It also
truth-table-checks the encoder on 2,048 complete small assignments.

## Decisive proof replay

The two coarse roots are not the release completion gate. The fixed-link
classification partitions the remaining search into exactly 266 cases, each
with a hash-bound LRAT accepted by both the C and CakeML checkers. See
`../fixed-link-proof/README.md` for the archive hashes and full public replay
command, or set both archive environment variables documented in
`../../manifests/README.md` and run `../../verify_all.sh`.
