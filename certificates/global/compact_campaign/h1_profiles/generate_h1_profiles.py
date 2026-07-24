#!/usr/bin/env python3
"""Generate the exhaustive 14-root profile refinement of canonical h=1."""

from __future__ import annotations

import hashlib
import itertools
import json
import os
import platform
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

import pysat
from pysat.card import CardEnc, EncType
from pysat.formula import IDPool


MODEL = "c12-compact-h1-profile-formal-v1"
POINTS = tuple(range(12))
MATCH = tuple((2 * index, 2 * index + 1) for index in range(6))
BLOCKS = tuple(itertools.combinations(POINTS, 6))
BLOCK_INDEX = {block: index for index, block in enumerate(BLOCKS)}
BASE_VARIABLES = 122_519
BASE_CLAUSES = 356_407
BASE_SHA = "637d9326388f77f933f3d066cd762d8c0ac4b2df0d2260d688e031d55959e7f0"
BASE_BODY_SHA = "6a1a2eb2843a4ddcf9138c5a85aaeccd2950b3e099e0ab8a26ce9fc815ab0cc5"
SELECTED_SUPPORT = frozenset((0, 1, 2))
TYPE0_CANONICAL = (0, 2, 4, 6, 8, 10)
TYPE1_CANONICALS = {
    "full_in_empty_in": (0, 1, 4, 6, 8, 10),
    "full_out_empty_out": (0, 2, 4, 6, 7, 10),
    "full_in_empty_out": (0, 1, 2, 4, 8, 10),
    "full_out_empty_in": (2, 4, 6, 7, 8, 10),
}


class GenerationError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise GenerationError(message)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def atomic_json(path: Path, payload: Dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)


def block_type(block: Tuple[int, ...]) -> int:
    selected = frozenset(block)
    occupancies = tuple(len(selected.intersection(pair)) for pair in MATCH)
    full = occupancies.count(2)
    if full != occupancies.count(0):
        fail(f"occupancy identity failed for {block}")
    return full


KINDS = tuple(block_type(block) for block in BLOCKS)
TYPE_VARS = tuple(
    tuple(index + 1 for index, value in enumerate(KINDS) if value == d)
    for d in range(4)
)
SUPPORTS = tuple(itertools.combinations(range(6), 3))
TYPE3_BLOCKS = tuple(
    tuple(point for pair_index in support for point in MATCH[pair_index])
    for support in SUPPORTS
)
TYPE3_VARS = tuple(BLOCK_INDEX[block] + 1 for block in TYPE3_BLOCKS)
H1_UNITS = tuple(
    variable if index == 0 else -variable
    for index, variable in enumerate(TYPE3_VARS)
)


def support_stabilizer_permutations() -> Tuple[Tuple[int, ...], ...]:
    result = []
    inside = tuple(sorted(SELECTED_SUPPORT))
    outside = tuple(index for index in range(6) if index not in SELECTED_SUPPORT)
    for inside_image in itertools.permutations(inside):
        for outside_image in itertools.permutations(outside):
            permutation = [0] * 6
            for source, target in zip(inside, inside_image):
                permutation[source] = target
            for source, target in zip(outside, outside_image):
                permutation[source] = target
            result.append(tuple(permutation))
    return tuple(result)


STABILIZER_PERMUTATIONS = support_stabilizer_permutations()


def stabilizer_orbit(block: Tuple[int, ...]) -> frozenset:
    images = set()
    for permutation in STABILIZER_PERMUTATIONS:
        for flips in range(64):
            images.add(
                tuple(
                    sorted(
                        2 * permutation[point // 2]
                        + ((point % 2) ^ ((flips >> (point // 2)) & 1))
                        for point in block
                    )
                )
            )
    return frozenset(images)


def type1_category(block: Tuple[int, ...]) -> str:
    selected = frozenset(block)
    full = next(index for index, pair in enumerate(MATCH) if len(selected.intersection(pair)) == 2)
    empty = next(index for index, pair in enumerate(MATCH) if len(selected.intersection(pair)) == 0)
    return (
        f"full_{'in' if full in SELECTED_SUPPORT else 'out'}_"
        f"empty_{'in' if empty in SELECTED_SUPPORT else 'out'}"
    )


def audit_exhaustion() -> Dict[str, Any]:
    if tuple(len(values) for values in TYPE_VARS) != (64, 480, 360, 20):
        fail("type histogram mismatch")
    profiles = []
    for n0 in range(41):
        for n1 in range(41 - n0):
            n2 = 39 - n0 - n1
            if n2 >= 0 and n1 + 2 * n2 + 3 == 60:
                profiles.append((n0, n1, n2, 1))
    expected = [(a, 21 - 2 * a, 18 + a, 1) for a in range(11)]
    if profiles != expected:
        fail(f"h1 profiles {profiles} != {expected}")
    type0_target = frozenset(
        block for block, value in zip(BLOCKS, KINDS) if value == 0
    )
    if stabilizer_orbit(TYPE0_CANONICAL) != type0_target:
        fail("fixed-support stabilizer is not transitive on type-0 blocks")
    category_sizes = {}
    covered = set()
    for name, canonical_block in TYPE1_CANONICALS.items():
        orbit = stabilizer_orbit(canonical_block)
        target = frozenset(
            block
            for block, value in zip(BLOCKS, KINDS)
            if value == 1 and type1_category(block) == name
        )
        if orbit != target:
            fail(f"type-1 stabilizer orbit {name} mismatch")
        category_sizes[name] = len(orbit)
        covered.update(orbit)
    if len(covered) != 480:
        fail("four type-1 stabilizer orbits do not exhaust type-1 blocks")
    return {
        "profiles": [list(values) for values in expected],
        "profile_count": 11,
        "refined_root_count": 14,
        "selected_type3_support": sorted(SELECTED_SUPPORT),
        "stabilizer_pair_permutations": len(STABILIZER_PERMUTATIONS),
        "stabilizer_with_endpoint_flips_order": len(STABILIZER_PERMUTATIONS) * 64,
        "type0_orbit_size": 64,
        "type1_category_orbit_sizes": category_sizes,
    }


def clause_raw(clause: Sequence[int]) -> bytes:
    return (" ".join(map(str, clause)) + " 0\n").encode()


def binary(path: Path) -> Dict[str, Any]:
    return {"path": path.name, "bytes": path.stat().st_size, "sha256": file_sha(path)}


def build() -> Dict[str, Any]:
    here = Path(__file__).resolve().parent
    base = here.parent / "global_base.cnf"
    if file_sha(base) != BASE_SHA:
        fail("compact base hash mismatch")
    base_raw = base.read_bytes()
    header, body = base_raw.split(b"\n", 1)
    if header != b"p cnf 122519 356407" or sha(body) != BASE_BODY_SHA:
        fail("compact base structure mismatch")
    runner = here / "run_h1_profiles.py"
    if not runner.is_file():
        fail("h1 runner missing")
    exhaustion = audit_exhaustion()
    root_specs = []
    for a in range(11):
        counts = (a, 21 - 2 * a, 18 + a, 1)
        if a:
            root_specs.append((a, "type0", counts, TYPE0_CANONICAL))
        else:
            for category, canonical_block in TYPE1_CANONICALS.items():
                root_specs.append((a, category, counts, canonical_block))
    entries: List[Dict[str, Any]] = []
    for case_index, (a, subcase, counts, canonical_block) in enumerate(root_specs):
        pool = IDPool(start_from=BASE_VARIABLES + 1)
        clauses: List[Tuple[int, ...]] = [(literal,) for literal in H1_UNITS]
        sections = {"fixed_type3_family": len(clauses)}
        for d in range(4):
            encoded = CardEnc.equals(
                lits=list(TYPE_VARS[d]),
                bound=counts[d],
                vpool=pool,
                encoding=EncType.kmtotalizer,
            )
            sections[f"exact_type{d}"] = len(encoded.clauses)
            clauses.extend(tuple(clause) for clause in encoded.clauses)
        canonical_variable = BLOCK_INDEX[canonical_block] + 1
        clauses.append((canonical_variable,))
        sections["symmetry_unit"] = 1
        extension = b"".join(clause_raw(clause) for clause in clauses)
        clause_count = BASE_CLAUSES + len(clauses)
        case_id = f"h1_a{a:02d}_{subcase}"
        raw = f"p cnf {pool.top} {clause_count}\n".encode() + body + extension
        case_path = here / "cases" / f"{case_id}.cnf"
        temporary = case_path.with_suffix(".cnf.tmp")
        temporary.write_bytes(raw)
        os.replace(temporary, case_path)
        entries.append(
            {
                "case_index": case_index,
                "case_id": case_id,
                "a": a,
                "subcase": subcase,
                "type_counts": {"n0": counts[0], "n1": counts[1], "n2": counts[2], "n3": 1},
                "canonical_block": list(canonical_block),
                "canonical_variable": canonical_variable,
                "variables": pool.top,
                "clauses": clause_count,
                "section_clause_counts": sections,
                "extension_bytes": len(extension),
                "extension_sha256": sha(extension),
                "cnf": f"cases/{case_id}.cnf",
                "cnf_bytes": len(raw),
                "cnf_sha256": sha(raw),
            }
        )
    core = {
        "model_version": MODEL,
        "base": {"path": str(base), "bytes": base.stat().st_size, "sha256": BASE_SHA, "body_sha256": BASE_BODY_SHA},
        "mathematical_exhaustion": exhaustion,
        "entries": entries,
        "case_count": len(entries),
        "binaries": {name: binary(here / name) for name in ("cadical", "drat-trim", "lrat-check")},
        "generator": {"path": Path(__file__).name, "sha256": file_sha(Path(__file__)), "python": sys.version, "platform": platform.platform(), "pysat": getattr(pysat, "__version__", "unknown")},
        "runner": {"path": runner.name, "bytes": runner.stat().st_size, "sha256": file_sha(runner)},
    }
    manifest = {**core, "core_sha256": sha(canonical(core))}
    manifest["manifest_sha256"] = sha(canonical(manifest))
    atomic_json(here / "manifest.json", manifest)
    return manifest


def main() -> int:
    try:
        manifest = build()
    except GenerationError as error:
        print(f"H1 GENERATION FAILED: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"result": "H1 GENERATION PASSED", "cases": manifest["case_count"], "manifest_sha256": manifest["manifest_sha256"], "exhaustion": manifest["mathematical_exhaustion"]}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
