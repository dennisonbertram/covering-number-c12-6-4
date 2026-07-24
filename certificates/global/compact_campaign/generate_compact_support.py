#!/usr/bin/env python3
"""Generate the compact exhaustive fixed-type-3-support SAT campaign.

This construction avoids all type-profile enumeration.  Relative to the
normalized degree-10 matching, a type-3 block is exactly the union of three
matched pairs and is therefore in bijection with one of the 20 triples of
pair indices.  Every hypothetical cover selects one subset of these 20
blocks.  Endpoint flips act trivially on this subset and S_6 permutes its
supports, so the S_6 orbits of all 2^20 support families are exhaustive.

For each canonical orbit representative this program fixes all 20 type-3
block variables while retaining the independently audited compact base:
exactly 40 blocks, normalized pair ceilings, triple upper bounds, and
literal quadruple coverage.  The 66 pair ceilings sum to the 600 pair
incidences of 40 six-blocks, so every ceiling is automatically tight.
No type-count/profile assumptions are used.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
import os
import platform
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

import pysat
from pysat.card import CardEnc, EncType
from pysat.formula import IDPool


MODEL_VERSION = "c12-fixed-type3-support-compact-formal-v2"
POINTS = tuple(range(12))
MATCHED_PAIRS = tuple((2 * index, 2 * index + 1) for index in range(6))
MATCHED_EDGES = frozenset(MATCHED_PAIRS)
BLOCKS = tuple(itertools.combinations(POINTS, 6))
BLOCK_SETS = tuple(frozenset(block) for block in BLOCKS)
BLOCK_INDEX = {block: index for index, block in enumerate(BLOCKS)}
SUPPORTS = tuple(itertools.combinations(range(6), 3))
SUPPORT_INDEX = {
    support: index for index, support in enumerate(SUPPORTS)
}
FULL_SUPPORT_MASK = (1 << len(SUPPORTS)) - 1

PRIMARY_VARIABLES = 924
TOTAL_VARIABLES = 122_519
EXACT_BLOCK_COUNT_CLAUSES = 57_972
PAIR_ATMOST_CLAUSES = 141_960
TRIPLE_ATMOST_CLAUSES = 155_980
CARDINALITY_CLAUSES = (
    EXACT_BLOCK_COUNT_CLAUSES
    + PAIR_ATMOST_CLAUSES
    + TRIPLE_ATMOST_CLAUSES
)
COVERAGE_CLAUSES = 495
BASE_CLAUSES = CARDINALITY_CLAUSES + COVERAGE_CLAUSES
CASE_ROOT_CLAUSES = 20
CASE_CLAUSES = BASE_CLAUSES + CASE_ROOT_CLAUSES
EXPECTED_BASE_BODY_SHA256 = (
    "6a1a2eb2843a4ddcf9138c5a85aaeccd2950b3e099e0ab8a26ce9fc815ab0cc5"
)
EXPECTED_SECTION_SHA256 = (
    "9a90ad6ce85edc53f9639b077534cfede27971974451b4676e414fbb0ad1ae9b",
    "2d300e47472c3aa8340555f1ffa0eb0abf7f22c4563fb18baaf43eeeb5362b40",
    "bd56975a519fed6bce06eb8159f02417051c12b4f3a1fb61babf6e494153386c",
    "381d8e308ae3cc608ab74288477f1506c882b6af2eb2b0be891f94bb44612538",
)
EXPECTED_ORBIT_COUNTS = (
    1,
    1,
    3,
    7,
    21,
    43,
    94,
    161,
    249,
    312,
    352,
    312,
    249,
    161,
    94,
    43,
    21,
    7,
    3,
    1,
    1,
)
EXPECTED_ORBITS = 2_136
EXPECTED_FAMILIES = 1 << 20


class GenerationError(RuntimeError):
    """A fatal mismatch while constructing the formal campaign."""


def fail(message: str) -> None:
    raise GenerationError(message)


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def atomic_write_bytes(path: Path, raw: bytes) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(raw)
    os.replace(temporary, path)


def atomic_write_json(path: Path, payload: Dict[str, Any]) -> None:
    raw = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    atomic_write_bytes(path, raw.encode())


def block_type(block: Tuple[int, ...]) -> int:
    block_set = frozenset(block)
    occupancies = tuple(
        len(block_set.intersection(pair)) for pair in MATCHED_PAIRS
    )
    if sum(occupancies) != 6:
        fail(f"invalid block occupancy for {block}")
    full = sum(value == 2 for value in occupancies)
    empty = sum(value == 0 for value in occupancies)
    if full != empty:
        fail(f"unbalanced matching occupancy for {block}")
    return full


BLOCK_TYPES = tuple(block_type(block) for block in BLOCKS)


def support_action(permutation: Tuple[int, ...]) -> Tuple[int, ...]:
    return tuple(
        SUPPORT_INDEX[
            tuple(sorted(permutation[index] for index in support))
        ]
        for support in SUPPORTS
    )


SUPPORT_ACTIONS = tuple(
    support_action(permutation)
    for permutation in itertools.permutations(range(6))
)


def permute_mask(mask: int, action: Tuple[int, ...]) -> int:
    image = 0
    for source, target in enumerate(action):
        if mask & (1 << source):
            image |= 1 << target
    return image


def enumerate_canonical_orbits() -> Tuple[Tuple[Tuple[int, int], ...], ...]:
    """Enumerate canonical mask/orbit-size pairs independently for every h."""
    all_by_h = []
    for h in range(21):
        seen = set()
        representatives: List[Tuple[int, int]] = []
        for chosen in itertools.combinations(range(20), h):
            mask = sum(1 << index for index in chosen)
            if mask in seen:
                continue
            images = {
                permute_mask(mask, action) for action in SUPPORT_ACTIONS
            }
            canonical = min(images)
            seen.update(images)
            representatives.append((canonical, len(images)))
        representatives.sort()
        expected = math.comb(20, h)
        if len(seen) != expected:
            fail(
                f"h={h}: enumerated {len(seen)} families, expected {expected}"
            )
        if sum(size for _, size in representatives) != expected:
            fail(f"h={h}: orbit sizes do not sum to {expected}")
        if len({mask for mask, _ in representatives}) != len(
            representatives
        ):
            fail(f"h={h}: duplicate canonical representatives")
        all_by_h.append(tuple(representatives))

    counts = tuple(len(orbits) for orbits in all_by_h)
    if counts != EXPECTED_ORBIT_COUNTS:
        fail(f"orbit counts {counts} != expected {EXPECTED_ORBIT_COUNTS}")
    if sum(counts) != EXPECTED_ORBITS:
        fail(f"total orbit count {sum(counts)} != {EXPECTED_ORBITS}")
    if sum(
        size
        for orbits in all_by_h
        for _, size in orbits
    ) != EXPECTED_FAMILIES:
        fail("all orbit sizes do not sum to 2^20")
    return tuple(all_by_h)


def type3_block_for_support(
    support: Tuple[int, ...]
) -> Tuple[int, ...]:
    return tuple(
        point
        for pair_index in support
        for point in MATCHED_PAIRS[pair_index]
    )


TYPE3_BLOCKS = tuple(
    type3_block_for_support(support) for support in SUPPORTS
)
TYPE3_VARIABLES = tuple(
    BLOCK_INDEX[block] + 1 for block in TYPE3_BLOCKS
)


def audit_type3_bijection() -> None:
    if len(BLOCKS) != PRIMARY_VARIABLES:
        fail(f"expected 924 blocks, got {len(BLOCKS)}")
    histogram = tuple(BLOCK_TYPES.count(kind) for kind in range(4))
    if histogram != (64, 480, 360, 20):
        fail(f"unexpected block-type histogram {histogram}")
    all_type3 = tuple(
        block
        for block, kind in zip(BLOCKS, BLOCK_TYPES)
        if kind == 3
    )
    if set(all_type3) != set(TYPE3_BLOCKS):
        fail("support triples are not exactly the 20 type-3 blocks")
    if len(set(TYPE3_VARIABLES)) != 20:
        fail("type-3 primary variables are not distinct")


def clause_raw(clause: Sequence[int]) -> bytes:
    return (" ".join(map(str, clause)) + " 0\n").encode()


def generate_base(work_dir: Path) -> Dict[str, Any]:
    """Independently rebuild the audited 356,407-clause compact base."""
    base_path = work_dir / "global_base.cnf"
    temporary = base_path.with_suffix(".cnf.tmp")
    variables_pool = IDPool()
    variables = tuple(
        variables_pool.id(("block", block)) for block in BLOCKS
    )
    if variables != tuple(range(1, PRIMARY_VARIABLES + 1)):
        fail("primary block variables are not exactly 1..924")

    base_header = (
        f"p cnf {TOTAL_VARIABLES} {BASE_CLAUSES}\n".encode()
    )
    case_header = (
        f"p cnf {TOTAL_VARIABLES} {CASE_CLAUSES}\n".encode()
    )
    base_file_hasher = hashlib.sha256()
    base_body_hasher = hashlib.sha256()
    section_hashers = [hashlib.sha256() for _ in range(4)]
    case_prefix_hasher = hashlib.sha256()
    base_file_hasher.update(base_header)
    case_prefix_hasher.update(case_header)

    section_counts = [0, 0, 0, 0]
    with temporary.open("wb") as output:
        output.write(base_header)

        def emit(encoded: Any, section: int) -> None:
            for clause in encoded.clauses:
                raw = clause_raw(clause)
                output.write(raw)
                base_file_hasher.update(raw)
                base_body_hasher.update(raw)
                section_hashers[section].update(raw)
                case_prefix_hasher.update(raw)
                section_counts[section] += 1

        # The exact hypothesis under test.
        emit(
            CardEnc.equals(
                lits=list(variables),
                bound=40,
                vpool=variables_pool,
                encoding=EncType.kmtotalizer,
            ),
            0,
        )

        # Pair ceilings.  Exact block count forces every one to be tight
        # because their targets sum to 40*C(6,2)=600.
        for edge in itertools.combinations(POINTS, 2):
            edge_set = frozenset(edge)
            literals = [
                variables[index]
                for index, block_set in enumerate(BLOCK_SETS)
                if edge_set <= block_set
            ]
            if len(literals) != math.comb(10, 4):
                fail(f"edge {edge}: expected 210 containing blocks")
            emit(
                CardEnc.atmost(
                    lits=literals,
                    bound=10 if edge in MATCHED_EDGES else 9,
                    vpool=variables_pool,
                    encoding=EncType.kmtotalizer,
                ),
                1,
            )

        # Triple lower bounds are implied by literal quadruple coverage.
        for triple in itertools.combinations(POINTS, 3):
            triple_set = frozenset(triple)
            literals = [
                variables[index]
                for index, block_set in enumerate(BLOCK_SETS)
                if triple_set <= block_set
            ]
            if len(literals) != math.comb(9, 3):
                fail(f"triple {triple}: expected 84 containing blocks")
            emit(
                CardEnc.atmost(
                    lits=literals,
                    bound=4,
                    vpool=variables_pool,
                    encoding=EncType.kmtotalizer,
                ),
                2,
            )

        for quad in itertools.combinations(POINTS, 4):
            quad_set = frozenset(quad)
            clause = [
                variables[index]
                for index, block_set in enumerate(BLOCK_SETS)
                if quad_set <= block_set
            ]
            if len(clause) != math.comb(8, 2):
                fail(f"quad {quad}: expected 28 containing blocks")
            raw = clause_raw(clause)
            output.write(raw)
            base_file_hasher.update(raw)
            base_body_hasher.update(raw)
            section_hashers[3].update(raw)
            case_prefix_hasher.update(raw)
            section_counts[3] += 1

    expected_section_counts = [
        EXACT_BLOCK_COUNT_CLAUSES,
        PAIR_ATMOST_CLAUSES,
        TRIPLE_ATMOST_CLAUSES,
        COVERAGE_CLAUSES,
    ]
    if section_counts != expected_section_counts:
        fail(
            f"generated section counts {section_counts}, "
            f"expected {expected_section_counts}"
        )
    if variables_pool.top != TOTAL_VARIABLES:
        fail(
            f"auxiliary pool top {variables_pool.top}, "
            f"expected {TOTAL_VARIABLES}"
        )
    for index, hasher in enumerate(section_hashers):
        if hasher.hexdigest() != EXPECTED_SECTION_SHA256[index]:
            fail(f"compact base section {index} differs from audited hash")
    if base_body_hasher.hexdigest() != EXPECTED_BASE_BODY_SHA256:
        fail("independent compact base body differs from audited compact base")

    os.replace(temporary, base_path)
    if file_sha256(base_path) != base_file_hasher.hexdigest():
        fail("global_base.cnf changed while being generated")
    return {
        "path": base_path.name,
        "bytes": base_path.stat().st_size,
        "sha256": base_file_hasher.hexdigest(),
        "body_sha256": base_body_hasher.hexdigest(),
        "section_clause_counts": {
            "exact_block_count": section_counts[0],
            "pair_atmost": section_counts[1],
            "triple_atmost": section_counts[2],
            "quad_coverage": section_counts[3],
        },
        "section_sha256": {
            "exact_block_count": section_hashers[0].hexdigest(),
            "pair_atmost": section_hashers[1].hexdigest(),
            "triple_atmost": section_hashers[2].hexdigest(),
            "quad_coverage": section_hashers[3].hexdigest(),
        },
        "variables": TOTAL_VARIABLES,
        "primary_variables": PRIMARY_VARIABLES,
        "clauses": BASE_CLAUSES,
        "case_header": case_header.decode().rstrip(),
        "_case_prefix_hasher": case_prefix_hasher,
    }


def selected_supports(mask: int) -> List[List[int]]:
    return [
        list(support)
        for index, support in enumerate(SUPPORTS)
        if mask & (1 << index)
    ]


def root_units(mask: int) -> Tuple[int, ...]:
    return tuple(
        variable if mask & (1 << index) else -variable
        for index, variable in enumerate(TYPE3_VARIABLES)
    )


def binary_metadata(path: Path) -> Dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        fail(f"required binary {path} is missing or a symlink")
    return {
        "path": path.name,
        "bytes": path.stat().st_size,
        "sha256": file_sha256(path),
    }


def build_campaign(work_dir: Path) -> Dict[str, Any]:
    started = time.monotonic()
    work_dir.mkdir(parents=True, exist_ok=True)
    roots_dir = work_dir / "roots"
    roots_dir.mkdir(parents=True, exist_ok=True)
    for subdirectory in ("cases", "proofs", "lrat", "results", "logs"):
        (work_dir / subdirectory).mkdir(parents=True, exist_ok=True)

    audit_type3_bijection()
    orbits_by_h = enumerate_canonical_orbits()
    base = generate_base(work_dir)
    case_prefix_hasher = base.pop("_case_prefix_hasher")

    entries = []
    case_index = 0
    for h, orbits in enumerate(orbits_by_h):
        for mask, orbit_size in orbits:
            if bin(mask).count("1") != h:
                fail(f"mask {mask} has wrong selected-support count")
            units = root_units(mask)
            root_raw = b"".join(clause_raw((literal,)) for literal in units)
            case_id = f"case_{case_index:04d}_h{h:02d}_m{mask:05x}"
            root_path = roots_dir / f"{case_id}.units"
            atomic_write_bytes(root_path, root_raw)
            root_sha = sha256_bytes(root_raw)
            if file_sha256(root_path) != root_sha:
                fail(f"{root_path}: root changed during generation")
            case_hasher = case_prefix_hasher.copy()
            case_hasher.update(root_raw)
            entries.append(
                {
                    "case_index": case_index,
                    "case_id": case_id,
                    "selected_support_count": h,
                    "representative_mask": mask,
                    "selected_supports": selected_supports(mask),
                    "orbit_size": orbit_size,
                    "root": str(root_path.relative_to(work_dir)),
                    "root_bytes": len(root_raw),
                    "root_sha256": root_sha,
                    "case_variables": TOTAL_VARIABLES,
                    "case_clauses": CASE_CLAUSES,
                    "case_cnf_sha256": case_hasher.hexdigest(),
                }
            )
            case_index += 1

    if len(entries) != EXPECTED_ORBITS:
        fail(f"generated {len(entries)} cases, expected {EXPECTED_ORBITS}")
    if sum(entry["orbit_size"] for entry in entries) != EXPECTED_FAMILIES:
        fail("manifest orbit sizes do not sum to 2^20")

    binaries = {
        name: binary_metadata(work_dir / name)
        for name in ("cadical", "drat-trim", "lrat-check")
    }
    runner_path = work_dir / "run_compact_support.py"
    if runner_path.is_symlink() or not runner_path.is_file():
        fail(f"required campaign runner {runner_path} is missing")
    core = {
        "model_version": MODEL_VERSION,
        "mathematical_exhaustion": {
            "type3_supports": len(SUPPORTS),
            "support_families": EXPECTED_FAMILIES,
            "acting_group": "S6 on normalized matched-pair indices",
            "acting_group_order": len(SUPPORT_ACTIONS),
            "endpoint_flips_act_trivially": True,
            "canonical_orbits": EXPECTED_ORBITS,
            "orbit_counts_h0_to_h20": list(EXPECTED_ORBIT_COUNTS),
            "orbit_size_sum": sum(
                entry["orbit_size"] for entry in entries
            ),
            "profile_enumeration_used": False,
            "type3_block_variables": list(TYPE3_VARIABLES),
        },
        "constraints": {
            "exact_block_count": 40,
            "matched_pair_degree_at_most": 10,
            "nonmatched_pair_degree_at_most": 9,
            "pair_ceiling_sum": 600,
            "forty_block_pair_incidence_sum": 600,
            "pair_ceilings_forced_tight": True,
            "triple_degree_at_most": 4,
            "triple_lower_bound_implied_by_quadruple_coverage": 3,
            "quadruple_coverage": True,
            "tight_pair_degrees_imply_point_degree": 20,
            "local_lemma_dependency": (
                "Every 9-block C(10,4,2) cover has point degree at most 4"
            ),
        },
        "base_cnf": base,
        "case_root_clauses": CASE_ROOT_CLAUSES,
        "case_count": len(entries),
        "entries": entries,
        "binaries": binaries,
        "runner": {
            "path": runner_path.name,
            "bytes": runner_path.stat().st_size,
            "sha256": file_sha256(runner_path),
        },
    }
    core_sha = sha256_bytes(canonical_json_bytes(core))
    manifest = {
        **core,
        "manifest_core_sha256": core_sha,
        "generator": {
            "path": Path(__file__).name,
            "sha256": file_sha256(Path(__file__)),
            "python": sys.version,
            "platform": platform.platform(),
            "pysat": getattr(pysat, "__version__", "unknown"),
        },
        "generation_wall_time": time.monotonic() - started,
    }
    manifest["manifest_sha256"] = sha256_bytes(
        canonical_json_bytes(
            {
                key: value
                for key, value in manifest.items()
                if key != "manifest_sha256"
            }
        )
    )
    atomic_write_json(work_dir / "manifest.json", manifest)
    return manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=Path(__file__).resolve().parent,
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        manifest = build_campaign(args.work_dir.resolve())
    except GenerationError as error:
        print(f"GENERATION FAILED: {error}", file=sys.stderr)
        return 1
    summary = {
        "result": "GENERATION PASSED",
        "model_version": manifest["model_version"],
        "cases": manifest["case_count"],
        "support_families": manifest["mathematical_exhaustion"][
            "support_families"
        ],
        "orbit_counts_h0_to_h20": manifest["mathematical_exhaustion"][
            "orbit_counts_h0_to_h20"
        ],
        "base_cnf_sha256": manifest["base_cnf"]["sha256"],
        "manifest_sha256": manifest["manifest_sha256"],
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
