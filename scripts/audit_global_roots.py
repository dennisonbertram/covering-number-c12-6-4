#!/usr/bin/env python3
"""Fail-closed audit of the compact two-root C(12,6,4) CNFs.

This program does not import the generator.  It reconstructs the block
variables, high-level cardinality specifications, PySAT kmtotalizer clauses,
quadruple coverage clauses, root units, matching orbits, and type-count split
independently.  It also tests the cardinality encoder against complete small
truth tables.

Passing this audit establishes that the pinned DIMACS files encode the
advertised mathematical reduction.  It does not establish UNSAT; that requires
the separately replayed DRAT/LRAT certificates.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Sequence


POINTS = tuple(range(12))
MATCH = tuple((2 * i, 2 * i + 1) for i in range(6))
MATCH_SET = frozenset(MATCH)
BLOCKS = tuple(itertools.combinations(POINTS, 6))
BLOCK_SETS = tuple(frozenset(block) for block in BLOCKS)
BLOCK_INDEX = {block: index for index, block in enumerate(BLOCKS)}

PRIMARY = 924
TOTAL_VARS = 122_519
SECTION_COUNTS = (57_972, 141_960, 155_980, 495)
SECTION_ENDS = tuple(
    sum(SECTION_COUNTS[: index + 1])
    for index in range(len(SECTION_COUNTS))
)
BASE_CLAUSES = 356_407
BASE_SHA256 = (
    "6a1a2eb2843a4ddcf9138c5a85aaeccd2950b3e099e0ab8a26ce9fc815ab0cc5"
)
SECTION_SHA256 = (
    "9a90ad6ce85edc53f9639b077534cfede27971974451b4676e414fbb0ad1ae9b",
    "2d300e47472c3aa8340555f1ffa0eb0abf7f22c4563fb18baaf43eeeb5362b40",
    "bd56975a519fed6bce06eb8159f02417051c12b4f3a1fb61babf6e494153386c",
    "381d8e308ae3cc608ab74288477f1506c882b6af2eb2b0be891f94bb44612538",
)
SECTION_SHAPES = (
    {2: 6_888, 3: 30_276, 4: 20_808},
    {2: 42_696, 3: 88_836, 4: 10_428},
    {2: 64_020, 3: 91_960},
    {28: 495},
)
ROOTS = {
    0: {
        "cnf": "root0.cnf",
        "metadata": "root0.json",
        "canonical": (0, 2, 4, 6, 8, 10),
        "clauses": 356_408,
        "bytes": 7_067_141,
        "sha256": (
            "ec71e1f3990beeb6889d8d0b359a8810fd2886e36cc0ce1725353231f1077f4e"
        ),
        "root_units": 1,
    },
    1: {
        "cnf": "root1.cnf",
        "metadata": "root1.json",
        "canonical": (0, 1, 4, 6, 8, 10),
        "clauses": 356_472,
        "bytes": 7_067_589,
        "sha256": (
            "4aeada9818cf66895bc8dc7ffb341d4edba1f0ffc997a62e40c50d360161d96d"
        ),
        "root_units": 65,
    },
}
HEX = re.compile(r"[0-9a-f]{64}\Z")


class AuditError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise AuditError(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def strict_json(path: Path) -> Any:
    raw = path.read_bytes()

    def unique(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                fail(f"{path}: duplicate JSON key {key!r}")
            out[key] = value
        return out

    try:
        return json.loads(
            raw.decode(),
            object_pairs_hook=unique,
            parse_constant=lambda value: fail(
                f"{path}: invalid JSON constant {value}"
            ),
        )
    except AuditError:
        raise
    except Exception as error:
        fail(f"{path}: invalid JSON: {error}")


def kind(block: tuple[int, ...]) -> int:
    selected = frozenset(block)
    occupancies = tuple(len(selected & frozenset(pair)) for pair in MATCH)
    full = occupancies.count(2)
    empty = occupancies.count(0)
    if full != empty:
        fail(f"internal type identity failed for {block}")
    return full


KINDS = tuple(kind(block) for block in BLOCKS)
TYPE_HISTOGRAM = {str(d): KINDS.count(d) for d in range(4)}
TYPE0_VARS = tuple(i + 1 for i, d in enumerate(KINDS) if d == 0)


def matching_orbit(block: tuple[int, ...]) -> frozenset[tuple[int, ...]]:
    images = set()
    for pair_perm in itertools.permutations(range(6)):
        for flips in range(64):
            image = tuple(
                sorted(
                    2 * pair_perm[point // 2]
                    + (
                        (point & 1)
                        ^ ((flips >> (point // 2)) & 1)
                    )
                    for point in block
                )
            )
            images.add(image)
    return frozenset(images)


def audit_mathematics() -> dict[str, Any]:
    if len(BLOCKS) != PRIMARY:
        fail(f"expected 924 six-subsets, got {len(BLOCKS)}")
    if TYPE_HISTOGRAM != {"0": 64, "1": 480, "2": 360, "3": 20}:
        fail(f"unexpected type histogram {TYPE_HISTOGRAM}")

    orbit_sizes = {}
    for root in (0, 1):
        canonical = ROOTS[root]["canonical"]
        if kind(canonical) != root:
            fail(f"root {root}: canonical block has wrong type")
        orbit = matching_orbit(canonical)
        expected = frozenset(
            block for block, d in zip(BLOCKS, KINDS) if d == root
        )
        if orbit != expected:
            fail(f"root {root}: matching orbit is not the full type set")
        orbit_sizes[root] = len(orbit)

    profiles = []
    for n0 in range(41):
        for n1 in range(41 - n0):
            for n2 in range(41 - n0 - n1):
                n3 = 40 - n0 - n1 - n2
                if n1 + 2 * n2 + 3 * n3 == 60:
                    profiles.append((n0, n1, n2, n3))
    if len(profiles) != 221:
        fail(f"expected 221 matching-type profiles, got {len(profiles)}")
    missed = [
        profile
        for profile in profiles
        if not (profile[0] > 0 or profile[1] > 0)
    ]
    if missed:
        fail(f"two-root split misses profiles: {missed}")

    # Every encoded assignment has 40 blocks, hence 600 pair incidences.
    # The 66 pair ceilings also sum to 600.  Therefore satisfying all
    # ceilings forces every pair to attain its advertised target.
    target_sum = 6 * 10 + 60 * 9
    incidence_sum = 40 * math.comb(6, 2)
    if target_sum != incidence_sum:
        fail("pair-ceiling aggregate identity failed")

    # The normalization itself follows from the separately certified local
    # C(10,4,2)=9 lemma and Schönheim:
    # C(11,5,3) >= ceil(11/5 * 9) = 20.
    if math.ceil(11 * 9 / 5) != 20:
        fail("point-link lower-bound arithmetic failed")
    if 40 * 6 != 12 * 20:
        fail("point-degree equality arithmetic failed")
    if 40 * 15 - 66 * 9 != 6:
        fail("pair-excess arithmetic failed")
    if 5 * 20 - 11 * 9 != 1:
        fail("per-point excess arithmetic failed")

    # Quadruple coverage implies every triple has degree at least three:
    # its nine one-point extensions must be covered and one containing
    # six-block covers only three of them.
    if math.ceil(9 / 3) != 3:
        fail("triple lower-bound arithmetic failed")

    return {
        "type_histogram": TYPE_HISTOGRAM,
        "type_profiles": len(profiles),
        "root0_profiles": sum(profile[0] > 0 for profile in profiles),
        "root1_profiles": sum(profile[0] == 0 for profile in profiles),
        "root_orbit_sizes": orbit_sizes,
        "pair_target_sum": target_sum,
        "pair_incidence_sum": incidence_sum,
    }


def root_units(root: int) -> tuple[tuple[int, ...], ...]:
    canonical_var = BLOCK_INDEX[ROOTS[root]["canonical"]] + 1
    if root == 0:
        return ((canonical_var,),)
    return tuple((-variable,) for variable in TYPE0_VARS) + (
        (canonical_var,),
    )


def coverage_clauses() -> tuple[tuple[int, ...], ...]:
    result = []
    for quad in itertools.combinations(POINTS, 4):
        q = frozenset(quad)
        clause = tuple(
            index + 1
            for index, block_set in enumerate(BLOCK_SETS)
            if q <= block_set
        )
        if len(clause) != 28:
            fail(f"quad {quad}: expected 28 coverers, got {len(clause)}")
        result.append(clause)
    return tuple(result)


COVERAGE = coverage_clauses()


def specifications() -> tuple[tuple[str, int, tuple[int, ...]], ...]:
    specs: list[tuple[str, int, tuple[int, ...]]] = []
    specs.append(("equals", 40, tuple(range(1, PRIMARY + 1))))
    for edge in itertools.combinations(POINTS, 2):
        e = frozenset(edge)
        literals = tuple(
            index + 1
            for index, block_set in enumerate(BLOCK_SETS)
            if e <= block_set
        )
        if len(literals) != 210:
            fail(f"edge {edge}: expected 210 containing blocks")
        specs.append(
            ("atmost", 10 if edge in MATCH_SET else 9, literals)
        )
    for triple in itertools.combinations(POINTS, 3):
        t = frozenset(triple)
        literals = tuple(
            index + 1
            for index, block_set in enumerate(BLOCK_SETS)
            if t <= block_set
        )
        if len(literals) != 84:
            fail(f"triple {triple}: expected 84 containing blocks")
        specs.append(("atmost", 4, literals))
    if len(specs) != 1 + 66 + 220:
        fail(f"expected 287 cardinality specs, got {len(specs)}")
    return tuple(specs)


SPECS = specifications()
SPEC_SHA256 = sha(canonical_json(SPECS))


def parse_clause(raw: bytes, path: Path, line: int) -> tuple[int, ...]:
    try:
        values = tuple(int(token) for token in raw.split())
    except ValueError as error:
        fail(f"{path}:{line}: invalid DIMACS integer: {error}")
    if not values or values[-1] != 0 or 0 in values[:-1]:
        fail(f"{path}:{line}: clause lacks one terminating zero")
    clause = values[:-1]
    if not clause:
        fail(f"{path}:{line}: unexpected empty clause")
    variables = tuple(abs(literal) for literal in clause)
    if len(set(variables)) != len(variables):
        fail(f"{path}:{line}: duplicate/complementary variable")
    return clause


def audit_dimacs(path: Path, root: int) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        fail(f"{path}: expected regular non-symlink file")
    expected = ROOTS[root]
    units = root_units(root)
    full_hash = hashlib.sha256()
    base_hash = hashlib.sha256()
    section_hashes = [hashlib.sha256() for _ in SECTION_COUNTS]
    section_shapes = [Counter() for _ in SECTION_COUNTS]
    seen = bytearray(TOTAL_VARS + 1)
    header = None
    clause_index = 0

    with path.open("rb") as handle:
        for line_no, raw in enumerate(handle, start=1):
            full_hash.update(raw)
            stripped = raw.strip()
            if not stripped:
                fail(f"{path}:{line_no}: blank line")
            if stripped.startswith(b"c"):
                fail(f"{path}:{line_no}: unexpected comment")
            if stripped.startswith(b"p"):
                if header is not None or clause_index:
                    fail(f"{path}:{line_no}: duplicate/misplaced header")
                fields = stripped.split()
                if len(fields) != 4 or fields[:2] != [b"p", b"cnf"]:
                    fail(f"{path}:{line_no}: malformed header")
                header = (int(fields[2]), int(fields[3]))
                continue
            if header is None:
                fail(f"{path}:{line_no}: clause before header")

            clause = parse_clause(raw, path, line_no)
            for literal in clause:
                variable = abs(literal)
                if not 1 <= variable <= TOTAL_VARS:
                    fail(f"{path}:{line_no}: variable outside declared range")
                seen[variable] = 1

            if clause_index < BASE_CLAUSES:
                base_hash.update(raw)
                section = next(
                    index
                    for index, end in enumerate(SECTION_ENDS)
                    if clause_index < end
                )
                section_hashes[section].update(raw)
                section_shapes[section][len(clause)] += 1
                if section == 3:
                    offset = clause_index - SECTION_ENDS[2]
                    if clause != COVERAGE[offset]:
                        fail(f"{path}:{line_no}: quad clause {offset} mismatch")
                elif all(abs(literal) <= PRIMARY for literal in clause):
                    fail(
                        f"{path}:{line_no}: unexpected primary-only "
                        f"cardinality clause"
                    )
            else:
                offset = clause_index - BASE_CLAUSES
                if offset >= len(units) or clause != units[offset]:
                    fail(f"{path}:{line_no}: root unit {offset} mismatch")
            clause_index += 1

    if header != (TOTAL_VARS, expected["clauses"]):
        fail(f"{path}: header {header} is not pinned value")
    if clause_index != expected["clauses"]:
        fail(f"{path}: parsed {clause_index} clauses")
    if path.stat().st_size != expected["bytes"]:
        fail(f"{path}: byte size changed")
    if full_hash.hexdigest() != expected["sha256"]:
        fail(f"{path}: full SHA-256 changed")
    if base_hash.hexdigest() != BASE_SHA256:
        fail(f"{path}: shared base hash mismatch")
    for index in range(4):
        if section_hashes[index].hexdigest() != SECTION_SHA256[index]:
            fail(f"{path}: section {index} hash mismatch")
        if dict(section_shapes[index]) != SECTION_SHAPES[index]:
            fail(f"{path}: section {index} clause shapes changed")
    missing = [i for i in range(1, TOTAL_VARS + 1) if not seen[i]]
    if missing:
        fail(f"{path}: {len(missing)} declared variables unused")
    if sha(path.read_bytes()) != full_hash.hexdigest():
        fail(f"{path}: file changed during audit")
    return {
        "root": root,
        "variables": TOTAL_VARS,
        "clauses": clause_index,
        "bytes": path.stat().st_size,
        "sha256": full_hash.hexdigest(),
        "base_sha256": base_hash.hexdigest(),
        "root_units": len(units),
    }


def expected_metadata(root: int) -> dict[str, Any]:
    expected = ROOTS[root]
    return {
        "canonical_block": list(expected["canonical"]),
        "clauses": expected["clauses"],
        "cnf_bytes": expected["bytes"],
        "cnf_sha256": expected["sha256"],
        "primary_variables": PRIMARY,
        "root": root,
        "section_clause_counts": {
            "base": BASE_CLAUSES,
            "exact_block_count": SECTION_COUNTS[0],
            "pair_atmost": SECTION_COUNTS[1],
            "quad_coverage": SECTION_COUNTS[3],
            "root_units": expected["root_units"],
            "triple_atmost": SECTION_COUNTS[2],
        },
        "type_histogram": TYPE_HISTOGRAM,
        "variables": TOTAL_VARS,
    }


def reencode() -> dict[str, Any]:
    try:
        import pysat
        from pysat.card import CardEnc, EncType
        from pysat.formula import IDPool
        from pysat.solvers import Solver
    except ImportError as error:
        fail(f"PySAT unavailable: {error}")

    pool = IDPool()
    primaries = tuple(pool.id(("audit-block", block)) for block in BLOCKS)
    if primaries != tuple(range(1, PRIMARY + 1)):
        fail("independent primary IDs are not 1..924")

    section_hashers = [hashlib.sha256() for _ in range(4)]
    section_counts = [0, 0, 0, 0]
    section_shapes = [Counter() for _ in range(4)]
    for spec_index, (operation, bound, literals) in enumerate(SPECS):
        if spec_index == 0:
            section = 0
        elif spec_index <= 66:
            section = 1
        else:
            section = 2
        encoder = CardEnc.equals if operation == "equals" else CardEnc.atmost
        encoded = encoder(
            lits=list(literals),
            bound=bound,
            vpool=pool,
            encoding=EncType.kmtotalizer,
        )
        for clause in encoded.clauses:
            raw = (" ".join(map(str, clause)) + " 0\n").encode()
            section_hashers[section].update(raw)
            section_counts[section] += 1
            section_shapes[section][len(clause)] += 1

    for clause in COVERAGE:
        raw = (" ".join(map(str, clause)) + " 0\n").encode()
        section_hashers[3].update(raw)
        section_counts[3] += 1
        section_shapes[3][len(clause)] += 1

    if tuple(section_counts) != SECTION_COUNTS:
        fail(f"re-encoded section counts {section_counts} changed")
    if pool.top != TOTAL_VARS:
        fail(f"re-encoded variable top {pool.top} != {TOTAL_VARS}")
    for index in range(4):
        if section_hashers[index].hexdigest() != SECTION_SHA256[index]:
            fail(f"re-encoded section {index} hash mismatch")
        if dict(section_shapes[index]) != SECTION_SHAPES[index]:
            fail(f"re-encoded section {index} shapes changed")

    # Complete small-instance semantic truth tables for both operations.
    truth_cases = 0
    inputs = list(range(1, 8))
    for operation, encoder in (
        ("equals", CardEnc.equals),
        ("atmost", CardEnc.atmost),
    ):
        for bound in range(8):
            small_pool = IDPool(start_from=8)
            formula = encoder(
                lits=inputs,
                bound=bound,
                vpool=small_pool,
                encoding=EncType.kmtotalizer,
            )
            with Solver(bootstrap_with=formula.clauses) as solver:
                for mask in range(1 << len(inputs)):
                    assumptions = [
                        variable
                        if mask & (1 << (variable - 1))
                        else -variable
                        for variable in inputs
                    ]
                    actual = solver.solve(assumptions=assumptions)
                    count = bin(mask).count("1")
                    expected = (
                        count == bound
                        if operation == "equals"
                        else count <= bound
                    )
                    if actual != expected:
                        fail(
                            f"small truth table failed: {operation}, "
                            f"bound={bound}, mask={mask}"
                        )
                    truth_cases += 1

    return {
        "pysat_version": getattr(pysat, "__version__", "unknown"),
        "cardinality_specifications": len(SPECS),
        "spec_sha256": SPEC_SHA256,
        "section_counts": section_counts,
        "variables": pool.top,
        "small_truth_cases": truth_cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--artifact-dir",
        type=Path,
        default=Path(__file__).resolve().parent,
    )
    args = parser.parse_args()
    directory = args.artifact_dir.resolve()
    try:
        mathematics = audit_mathematics()
        dimacs = []
        for root in (0, 1):
            cnf = directory / ROOTS[root]["cnf"]
            metadata = directory / ROOTS[root]["metadata"]
            actual_metadata = strict_json(metadata)
            if canonical_json(actual_metadata) != canonical_json(
                expected_metadata(root)
            ):
                fail(f"{metadata}: metadata mismatch")
            dimacs.append(audit_dimacs(cnf, root))
        if dimacs[0]["base_sha256"] != dimacs[1]["base_sha256"]:
            fail("root bases differ")
        independent = reencode()
    except (AuditError, OSError, ValueError) as error:
        print(f"COMPACT ROOT AUDIT FAILED: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "result": "COMPACT ROOT AUDIT PASSED",
                "mathematics": mathematics,
                "dimacs": dimacs,
                "independent_reencoding": independent,
                "limitations": [
                    "UNSAT requires separately replayed proof certificates",
                    "triple ceilings use the separately certified local lemma",
                ],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
