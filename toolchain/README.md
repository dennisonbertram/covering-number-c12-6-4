# Proof-checking toolchain

The proof was generated and checked with these pinned revisions:

| Tool | Version/revision | Role |
|---|---|---|
| CaDiCaL | 1.7.3, `38e073b389a877b0a0d3c91136d2443ab95fdeba` | generate DRAT |
| drat-trim | `2e3b2dc0ecf938addbd779d42877b6ed69d9a985` | replay DRAT and export LRAT |
| lrat-check | same drat-trim revision | independently replay LRAT |
| cake_lpr | `a36874a8b750b43fe4b385b8ddbf5b033e46a3fa` | replay LRAT with a CakeML-extracted checker |
| PySAT | 1.9.dev7 | deterministic cardinality encoding |

The vendored `lrat-check.c` and `drat-trim-LICENSE` are byte-for-byte copies
from the pinned upstream drat-trim revision. Their SHA-256 values are:

```text
bf07c2ac96b9035da1ebcc578cb95e956a2b795629d613154cdb307f8a8f4a95  lrat-check.c
71ab2a9dc5a294ad8fba4ccb8c45aaa8a439596d314a2a046ac9b62266872a18  drat-trim-LICENSE
```

The `toolchain/cake_lpr/` directory contains the generated Armv8 assembly,
runtime shim, and license from the pinned upstream `cake_lpr` revision.  The
assembly is produced from a checker whose implementation and soundness
development are in CakeML.  The vendored source hashes are:

```text
95b64883edc0cb09feedbcb1ebec233e2490f5b458fdda9dc29c212ed916f00c  cake_lpr/cake_lpr_arm8.S
8e30d84fdcb2177aa5571d7fa6661a2fae5ecfd56baa0ce49c65f9233a9f87cb  cake_lpr/basis_ffi.c
eb1e4ff71900d55d384ff18afad5aae48417ce0fff25231565862c42b45e5dbc  cake_lpr/LICENSE
```

Run:

```bash
./toolchain/build.sh
```

This builds a local `lrat-check`, clones drat-trim and CaDiCaL from their
official GitHub repositories, checks out the pinned commits, and builds them
under `.toolchain-build/`. On Arm64, it also compiles the vendored
`cake_lpr` assembly and runtime shim. No generated binary is committed.

For theorem verification, LRAT replay is the decisive path. Each final LRAT
certificate is accepted by both the small C `lrat-check` implementation and
`cake_lpr`; this checker diversity is deliberate. CaDiCaL is needed only to
regenerate solver proofs, and drat-trim is needed only to replay DRAT or
convert it to LRAT.

For an offline verification replay that does not clone or fetch anything,
run:

```bash
./toolchain/build-replay.sh
```

This hash-checks and compiles the vendored C LRAT checker and, on Arm64, the
vendored CakeML-extracted checker. The release verifier uses this offline
path. On other architectures the global receipt audit must still require a
recorded CakeML replay of the exact LRAT hash for every leaf; skipping a local
CakeML build does not waive that release requirement.
