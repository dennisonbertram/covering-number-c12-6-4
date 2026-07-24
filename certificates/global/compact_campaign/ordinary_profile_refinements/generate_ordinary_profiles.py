#!/usr/bin/env python3
"""Generate exact-profile/stabilizer refinements of hard ordinary roots.

Each parent is one fixed type-3 support-family root from the 2,136-case
compact campaign.  Its children exhaust every feasible matching-type
profile.  For a profile, a positive type-0 count supplies the witness;
otherwise the positive type-1 count does.  One child fixes a representative
of each witness-block orbit under the full parent stabilizer
    C2^6 semidirect Stab_S6(parent support family).
Thus any model of a parent is symmetry-equivalent to a model of a child.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
import platform
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple

import pysat
from pysat.card import CardEnc, EncType
from pysat.formula import IDPool


MODEL = "c12-compact-ordinary-profile-refinement-formal-v1"
PARENT_MODEL = "c12-fixed-type3-support-compact-formal-v2"
POINTS = tuple(range(12))
PAIRS = tuple((2 * index, 2 * index + 1) for index in range(6))
BLOCKS = tuple(itertools.combinations(POINTS, 6))
BLOCK_INDEX = {block: index for index, block in enumerate(BLOCKS)}
SUPPORTS = tuple(itertools.combinations(range(6), 3))
SUPPORT_INDEX = {support: index for index, support in enumerate(SUPPORTS)}
PAIR_PERMUTATIONS = tuple(itertools.permutations(range(6)))
BASE_VARIABLES = 122_519
BASE_CLAUSES = 356_407
BASE_SHA256 = (
    "637d9326388f77f933f3d066cd762d8c0ac4b2df0d2260d688e031d55959e7f0"
)
BASE_BODY_SHA256 = (
    "6a1a2eb2843a4ddcf9138c5a85aaeccd2950b3e099e0ab8a26ce9fc815ab0cc5"
)


class GenerationError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise GenerationError(message)


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def atomic_json(path: Path, value: Dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)


def strict_json(path: Path) -> Any:
    def unique(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                fail(f"{path}: duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        return json.loads(
            path.read_text(),
            object_pairs_hook=unique,
            parse_constant=lambda value: fail(
                f"{path}: non-standard JSON constant {value}"
            ),
        )
    except GenerationError:
        raise
    except Exception as error:
        fail(f"{path}: invalid JSON: {error}")


def validate_self_hash(
    payload: Dict[str, Any], key: str, location: str
) -> None:
    recorded = payload.get(key)
    core = {name: value for name, value in payload.items() if name != key}
    actual = sha(canonical(core))
    if recorded != actual:
        fail(f"{location}: {key} mismatch ({recorded} != {actual})")


def block_type(block: Tuple[int, ...]) -> int:
    selected = frozenset(block)
    occupancies = tuple(len(selected.intersection(pair)) for pair in PAIRS)
    full = occupancies.count(2)
    empty = occupancies.count(0)
    if full != empty:
        fail(f"unbalanced block occupancy {block}")
    return full


BLOCK_TYPES = tuple(block_type(block) for block in BLOCKS)
TYPE_VARIABLES = tuple(
    tuple(index + 1 for index, kind in enumerate(BLOCK_TYPES) if kind == d)
    for d in range(4)
)


def support_action(permutation: Tuple[int, ...]) -> Tuple[int, ...]:
    return tuple(
        SUPPORT_INDEX[
            tuple(sorted(permutation[index] for index in support))
        ]
        for support in SUPPORTS
    )


def permute_mask(mask: int, action: Tuple[int, ...]) -> int:
    image = 0
    for source, target in enumerate(action):
        if mask & (1 << source):
            image |= 1 << target
    return image


def stabilizer(mask: int) -> Tuple[Tuple[int, ...], ...]:
    result = []
    for permutation in PAIR_PERMUTATIONS:
        if permute_mask(mask, support_action(permutation)) == mask:
            result.append(permutation)
    if not result or tuple(range(6)) not in result:
        fail(f"invalid stabilizer for support mask {mask}")
    return tuple(result)


def point_image(
    point: int, permutation: Tuple[int, ...], flips: int
) -> int:
    source_pair, endpoint = divmod(point, 2)
    return 2 * permutation[source_pair] + (
        endpoint ^ ((flips >> source_pair) & 1)
    )


def block_image(
    block: Tuple[int, ...], permutation: Tuple[int, ...], flips: int
) -> Tuple[int, ...]:
    return tuple(
        sorted(point_image(point, permutation, flips) for point in block)
    )


def witness_orbits(
    kind: int, permutations: Sequence[Tuple[int, ...]]
) -> Tuple[Tuple[Tuple[int, ...], ...], ...]:
    remaining = {
        block for block, block_kind in zip(BLOCKS, BLOCK_TYPES)
        if block_kind == kind
    }
    orbits: List[Tuple[Tuple[int, ...], ...]] = []
    while remaining:
        representative = min(remaining)
        orbit = {
            block_image(representative, permutation, flips)
            for permutation in permutations
            for flips in range(64)
        }
        if any(BLOCK_TYPES[BLOCK_INDEX[image]] != kind for image in orbit):
            fail("witness orbit changed matching type")
        if not orbit.issubset(remaining):
            overlap = orbit.difference(remaining)
            if overlap:
                fail("witness orbit enumeration overlapped prior orbit")
        ordered = tuple(sorted(orbit))
        orbits.append(ordered)
        remaining.difference_update(orbit)
    union = {block for orbit in orbits for block in orbit}
    expected = {
        block for block, block_kind in zip(BLOCKS, BLOCK_TYPES)
        if block_kind == kind
    }
    if union != expected or sum(map(len, orbits)) != len(expected):
        fail(f"witness orbits do not partition type {kind}")
    return tuple(sorted(orbits, key=lambda orbit: orbit[0]))


def feasible_profiles(h: int) -> Tuple[Tuple[int, int, int, int], ...]:
    profiles = []
    for n0 in range(41):
        for n1 in range(41 - n0):
            n2 = 40 - h - n0 - n1
            if n2 < 0:
                continue
            if n1 + 2 * n2 + 3 * h == 60:
                profiles.append((n0, n1, n2, h))
    if not profiles:
        fail(f"no feasible type profiles for h={h}")
    for profile in profiles:
        if sum(profile) != 40:
            fail(f"profile block-count identity failed: {profile}")
        if sum(kind * count for kind, count in enumerate(profile)) != 60:
            fail(f"profile matching-pair identity failed: {profile}")
    return tuple(profiles)


def clause_raw(clause: Iterable[int]) -> bytes:
    return (" ".join(map(str, clause)) + " 0\n").encode()


def read_base_body(base: Path) -> bytes:
    raw = base.read_bytes()
    header, body = raw.split(b"\n", 1)
    if header != b"p cnf 122519 356407":
        fail(f"{base}: unexpected DIMACS header")
    if sha(body) != BASE_BODY_SHA256:
        fail(f"{base}: body SHA-256 mismatch")
    return body


def binary(path: Path) -> Dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        fail(f"{path}: missing or symlinked required binary")
    return {
        "path": path.name,
        "bytes": path.stat().st_size,
        "sha256": file_sha(path),
    }


def parse_indices(text: str) -> Tuple[int, ...]:
    indexes = set()
    for piece in text.split(","):
        piece = piece.strip()
        if not piece:
            continue
        if "-" in piece:
            left, right = piece.split("-", 1)
            start, end = int(left), int(right)
            if end < start:
                fail(f"descending range {piece}")
            indexes.update(range(start, end + 1))
        else:
            indexes.add(int(piece))
    if not indexes:
        fail("at least one parent index is required")
    if min(indexes) < 2 or max(indexes) >= 2136:
        fail("ordinary parent indices must lie in 2..2135")
    return tuple(sorted(indexes))


def load_parent(here: Path) -> Tuple[Path, Dict[str, Any]]:
    path = here.parent / "manifest.json"
    parent = strict_json(path)
    if not isinstance(parent, dict):
        fail(f"{path}: expected object")
    validate_self_hash(parent, "manifest_sha256", str(path))
    if parent.get("model_version") != PARENT_MODEL:
        fail(f"{path}: parent model mismatch")
    if parent.get("case_count") != 2136:
        fail(f"{path}: parent case count mismatch")
    entries = parent.get("entries")
    if not isinstance(entries, list) or len(entries) != 2136:
        fail(f"{path}: parent entries mismatch")
    for index, entry in enumerate(entries):
        if entry.get("case_index") != index:
            fail(f"{path}: parent entry order mismatch at {index}")
    return path, parent


def build(indexes: Tuple[int, ...]) -> Dict[str, Any]:
    here = Path(__file__).resolve().parent
    parent_path, parent = load_parent(here)
    base = here.parent / "global_base.cnf"
    if base.is_symlink() or not base.is_file() or file_sha(base) != BASE_SHA256:
        fail(f"{base}: compact base identity mismatch")
    base_body = read_base_body(base)
    runner = here / "run_ordinary_profiles.py"
    if runner.is_symlink() or not runner.is_file():
        fail(f"{runner}: required runner missing")

    entries: List[Dict[str, Any]] = []
    parent_coverages: List[Dict[str, Any]] = []
    for parent_index in indexes:
        parent_entry = parent["entries"][parent_index]
        h = parent_entry["selected_support_count"]
        if not 2 <= h <= 19:
            fail(f"parent {parent_index}: not an ordinary h=2..19 root")
        mask = parent_entry["representative_mask"]
        selected = tuple(
            SUPPORTS[index]
            for index in range(20)
            if mask & (1 << index)
        )
        if tuple(tuple(value) for value in parent_entry["selected_supports"]) != selected:
            fail(f"parent {parent_index}: selected support mismatch")
        root_path = here.parent / parent_entry["root"]
        root_raw = root_path.read_bytes()
        if len(root_raw) != parent_entry["root_bytes"]:
            fail(f"{root_path}: root byte-size mismatch")
        if sha(root_raw) != parent_entry["root_sha256"]:
            fail(f"{root_path}: root SHA-256 mismatch")
        root_lines = tuple(line for line in root_raw.splitlines() if line)
        if len(root_lines) != 20:
            fail(f"{root_path}: expected 20 unit clauses")

        permutations = stabilizer(mask)
        type0_orbits = witness_orbits(0, permutations)
        type1_orbits = witness_orbits(1, permutations)
        profiles = feasible_profiles(h)
        profile_coverages = []
        parent_child_start = len(entries)
        for profile_index, counts in enumerate(profiles):
            witness_kind = 0 if counts[0] > 0 else 1
            if counts[witness_kind] <= 0:
                fail(f"parent {parent_index}: witness count is not positive")
            orbits = type0_orbits if witness_kind == 0 else type1_orbits
            child_indexes = []
            for witness_orbit_index, orbit in enumerate(orbits):
                witness_block = orbit[0]
                witness_variable = BLOCK_INDEX[witness_block] + 1
                pool = IDPool(start_from=BASE_VARIABLES + 1)
                cardinality: List[Tuple[int, ...]] = []
                section_counts: Dict[str, int] = {
                    "fixed_type3_support": len(root_lines)
                }
                for kind in range(3):
                    encoded = CardEnc.equals(
                        lits=list(TYPE_VARIABLES[kind]),
                        bound=counts[kind],
                        vpool=pool,
                        encoding=EncType.kmtotalizer,
                    )
                    section_counts[f"exact_type{kind}"] = len(encoded.clauses)
                    cardinality.extend(
                        tuple(clause) for clause in encoded.clauses
                    )
                section_counts["witness_unit"] = 1
                cardinality_raw = b"".join(
                    clause_raw(clause) for clause in cardinality
                )
                witness_raw = clause_raw((witness_variable,))
                extension_raw = root_raw + cardinality_raw + witness_raw
                clause_count = (
                    BASE_CLAUSES + len(root_lines)
                    + len(cardinality) + 1
                )
                header = f"p cnf {pool.top} {clause_count}\n".encode()
                case_raw = header + base_body + extension_raw
                case_id = (
                    f"parent_{parent_index:04d}_h{h:02d}_"
                    f"p{profile_index:02d}_k{witness_kind}_"
                    f"w{witness_orbit_index:02d}_v{witness_variable:03d}"
                )
                case_path = here / "cases" / f"{case_id}.cnf"
                temporary = case_path.with_suffix(".cnf.tmp")
                temporary.write_bytes(case_raw)
                os.replace(temporary, case_path)
                child_index = len(entries)
                child_indexes.append(child_index)
                entries.append(
                    {
                        "child_index": child_index,
                        "case_id": case_id,
                        "parent_index": parent_index,
                        "parent_case_id": parent_entry["case_id"],
                        "parent_case_cnf_sha256": parent_entry[
                            "case_cnf_sha256"
                        ],
                        "parent_root_sha256": parent_entry["root_sha256"],
                        "parent_support_mask": mask,
                        "parent_support_count": h,
                        "parent_orbit_size": parent_entry["orbit_size"],
                        "profile_index": profile_index,
                        "type_counts": {
                            "n0": counts[0],
                            "n1": counts[1],
                            "n2": counts[2],
                            "n3": counts[3],
                        },
                        "witness_kind": witness_kind,
                        "witness_orbit_index": witness_orbit_index,
                        "witness_orbit_size": len(orbit),
                        "witness_block": list(witness_block),
                        "witness_variable": witness_variable,
                        "pair_permutation_stabilizer_order": len(permutations),
                        "full_stabilizer_order": 64 * len(permutations),
                        "variables": pool.top,
                        "clauses": clause_count,
                        "section_clause_counts": section_counts,
                        "extension_bytes": len(extension_raw),
                        "extension_sha256": sha(extension_raw),
                        "cnf": str(case_path.relative_to(here)),
                        "cnf_bytes": len(case_raw),
                        "cnf_sha256": sha(case_raw),
                    }
                )
            profile_coverages.append(
                {
                    "profile_index": profile_index,
                    "type_counts": {
                        "n0": counts[0],
                        "n1": counts[1],
                        "n2": counts[2],
                        "n3": counts[3],
                    },
                    "witness_kind": witness_kind,
                    "witness_count": counts[witness_kind],
                    "witness_orbit_count": len(orbits),
                    "witness_orbit_sizes": [len(orbit) for orbit in orbits],
                    "child_indexes": child_indexes,
                }
            )
        parent_child_end = len(entries)
        parent_coverages.append(
            {
                "parent_index": parent_index,
                "parent_case_id": parent_entry["case_id"],
                "parent_case_cnf_sha256": parent_entry["case_cnf_sha256"],
                "parent_root_sha256": parent_entry["root_sha256"],
                "parent_support_mask": mask,
                "parent_support_count": h,
                "parent_orbit_size": parent_entry["orbit_size"],
                "pair_permutation_stabilizer_order": len(permutations),
                "full_stabilizer_order": 64 * len(permutations),
                "feasible_profiles": [list(profile) for profile in profiles],
                "profile_count": len(profiles),
                "profile_coverages": profile_coverages,
                "child_index_start": parent_child_start,
                "child_index_end_exclusive": parent_child_end,
                "child_count": parent_child_end - parent_child_start,
            }
        )

    core = {
        "model_version": MODEL,
        "parent_campaign": {
            "path": str(parent_path),
            "model_version": PARENT_MODEL,
            "manifest_sha256": parent["manifest_sha256"],
            "case_count": parent["case_count"],
        },
        "base": {
            "path": str(base),
            "bytes": base.stat().st_size,
            "sha256": BASE_SHA256,
            "body_sha256": BASE_BODY_SHA256,
            "variables": BASE_VARIABLES,
            "clauses": BASE_CLAUSES,
        },
        "mathematical_exhaustion": {
            "refined_parent_indices": list(indexes),
            "parent_count": len(indexes),
            "type_histogram": [len(values) for values in TYPE_VARIABLES],
            "block_count_identity": "n0+n1+n2+n3=40",
            "matching_pair_identity": "n1+2*n2+3*n3=60",
            "symmetry_group": (
                "C2^6 semidirect stabilizer in S6 of the fixed "
                "type-3 support family"
            ),
            "coverage_rule": (
                "for each feasible profile choose type0 if n0>0 else "
                "type1; every selected witness is equivalent to one "
                "canonical representative, one child per witness orbit"
            ),
            "parent_coverages": parent_coverages,
        },
        "entries": entries,
        "case_count": len(entries),
        "binaries": {
            name: binary(here / name)
            for name in ("cadical", "drat-trim", "lrat-check")
        },
        "generator": {
            "path": Path(__file__).name,
            "bytes": Path(__file__).stat().st_size,
            "sha256": file_sha(Path(__file__)),
            "python": sys.version,
            "platform": platform.platform(),
            "pysat": getattr(pysat, "__version__", "unknown"),
        },
        "runner": {
            "path": runner.name,
            "bytes": runner.stat().st_size,
            "sha256": file_sha(runner),
        },
    }
    manifest = {**core, "core_sha256": sha(canonical(core))}
    manifest["manifest_sha256"] = sha(canonical(manifest))
    atomic_json(here / "manifest.json", manifest)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--indices",
        required=True,
        help="comma/range list of unresolved ordinary parent indices",
    )
    args = parser.parse_args()
    try:
        indexes = parse_indices(args.indices)
        manifest = build(indexes)
    except GenerationError as error:
        print(f"ORDINARY PROFILE GENERATION FAILED: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "result": "ORDINARY PROFILE GENERATION PASSED",
                "parents": manifest["mathematical_exhaustion"][
                    "refined_parent_indices"
                ],
                "cases": manifest["case_count"],
                "manifest_sha256": manifest["manifest_sha256"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
