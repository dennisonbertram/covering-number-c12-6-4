#!/usr/bin/env python3
"""Generate the exhaustive 11-profile refinement of the h=0 support root."""

from __future__ import annotations

import hashlib
import itertools
import json
import math
import os
import platform
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

import pysat
from pysat.card import CardEnc, EncType
from pysat.formula import IDPool


MODEL = "c12-compact-h0-profile-formal-v1"
POINTS = tuple(range(12))
MATCHED_PAIRS = tuple((2 * index, 2 * index + 1) for index in range(6))
BLOCKS = tuple(itertools.combinations(POINTS, 6))
BLOCK_SETS = tuple(frozenset(block) for block in BLOCKS)
BLOCK_INDEX = {block: index for index, block in enumerate(BLOCKS)}
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


def block_type(block: Tuple[int, ...]) -> int:
    selected = frozenset(block)
    occupancies = tuple(
        len(selected.intersection(pair)) for pair in MATCHED_PAIRS
    )
    full = occupancies.count(2)
    empty = occupancies.count(0)
    if full != empty:
        fail(f"matching occupancy failed for {block}")
    return full


BLOCK_TYPES = tuple(block_type(block) for block in BLOCKS)
TYPE_VARIABLES = tuple(
    tuple(index + 1 for index, kind in enumerate(BLOCK_TYPES) if kind == d)
    for d in range(4)
)
TYPE3_NEGATIVE_UNITS = tuple(-variable for variable in TYPE_VARIABLES[3])
TYPE0_CANONICAL = (0, 2, 4, 6, 8, 10)
TYPE1_CANONICAL = (0, 1, 4, 6, 8, 10)


def matching_orbit(block: Tuple[int, ...]) -> frozenset:
    images = set()
    for permutation in itertools.permutations(range(6)):
        for flips in range(64):
            images.add(
                tuple(
                    sorted(
                        2 * permutation[point // 2]
                        + (
                            (point % 2)
                            ^ ((flips >> (point // 2)) & 1)
                        )
                        for point in block
                    )
                )
            )
    return frozenset(images)


def audit_exhaustion() -> Dict[str, Any]:
    histogram = tuple(len(values) for values in TYPE_VARIABLES)
    if histogram != (64, 480, 360, 20):
        fail(f"unexpected type histogram {histogram}")
    solutions = []
    for n0 in range(41):
        for n1 in range(41 - n0):
            n2 = 40 - n0 - n1
            if n1 + 2 * n2 == 60:
                solutions.append((n0, n1, n2, 0))
    expected = [(a, 20 - 2 * a, 20 + a, 0) for a in range(11)]
    if solutions != expected:
        fail(f"h0 profile solutions {solutions} != {expected}")
    for kind, canonical_block in (
        (0, TYPE0_CANONICAL),
        (1, TYPE1_CANONICAL),
    ):
        orbit = matching_orbit(canonical_block)
        target = frozenset(
            block
            for block, block_kind in zip(BLOCKS, BLOCK_TYPES)
            if block_kind == kind
        )
        if orbit != target:
            fail(f"matching stabilizer is not transitive on type {kind}")
    return {
        "profiles": [list(values) for values in expected],
        "profile_count": len(expected),
        "type_histogram": list(histogram),
        "type0_orbit_size": len(matching_orbit(TYPE0_CANONICAL)),
        "type1_orbit_size": len(matching_orbit(TYPE1_CANONICAL)),
        "a_positive_normalization": "selected canonical type-0 block",
        "a_zero_normalization": (
            "n0=0 and selected canonical type-1 block"
        ),
    }


def clause_raw(clause: Sequence[int]) -> bytes:
    return (" ".join(map(str, clause)) + " 0\n").encode()


def read_base_body(base: Path) -> bytes:
    raw = base.read_bytes()
    header, body = raw.split(b"\n", 1)
    if header != b"p cnf 122519 356407":
        fail(f"{base}: unexpected header")
    if sha(body) != BASE_BODY_SHA256:
        fail(f"{base}: body hash mismatch")
    return body


def binary(path: Path) -> Dict[str, Any]:
    return {
        "path": path.name,
        "bytes": path.stat().st_size,
        "sha256": file_sha(path),
    }


def build() -> Dict[str, Any]:
    here = Path(__file__).resolve().parent
    base = here.parent / "global_base.cnf"
    if file_sha(base) != BASE_SHA256:
        fail(f"{base}: compact base SHA-256 mismatch")
    base_body = read_base_body(base)
    exhaustion = audit_exhaustion()
    runner = here / "run_h0_profiles.py"
    if runner.is_symlink() or not runner.is_file():
        fail(f"{runner}: required runner missing")
    entries: List[Dict[str, Any]] = []
    for a in range(11):
        counts = (a, 20 - 2 * a, 20 + a, 0)
        pool = IDPool(start_from=BASE_VARIABLES + 1)
        extension: List[Tuple[int, ...]] = [
            (literal,) for literal in TYPE3_NEGATIVE_UNITS
        ]
        section_counts = {"fixed_type3_zero": len(extension)}
        for kind in range(3):
            encoded = CardEnc.equals(
                lits=list(TYPE_VARIABLES[kind]),
                bound=counts[kind],
                vpool=pool,
                encoding=EncType.kmtotalizer,
            )
            section_counts[f"exact_type{kind}"] = len(encoded.clauses)
            extension.extend(tuple(clause) for clause in encoded.clauses)
        canonical_block = TYPE1_CANONICAL if a == 0 else TYPE0_CANONICAL
        canonical_kind = 1 if a == 0 else 0
        canonical_variable = BLOCK_INDEX[canonical_block] + 1
        extension.append((canonical_variable,))
        section_counts["symmetry_unit"] = 1
        extension_raw = b"".join(clause_raw(clause) for clause in extension)
        clause_count = BASE_CLAUSES + len(extension)
        header = f"p cnf {pool.top} {clause_count}\n".encode()
        case_raw = header + base_body + extension_raw
        case_id = f"h0_profile_a{a:02d}"
        case_path = here / "cases" / f"{case_id}.cnf"
        temporary = case_path.with_suffix(".cnf.tmp")
        temporary.write_bytes(case_raw)
        os.replace(temporary, case_path)
        entries.append(
            {
                "profile_index": a,
                "case_id": case_id,
                "type_counts": {
                    "n0": counts[0],
                    "n1": counts[1],
                    "n2": counts[2],
                    "n3": counts[3],
                },
                "canonical_kind": canonical_kind,
                "canonical_block": list(canonical_block),
                "canonical_variable": canonical_variable,
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

    core = {
        "model_version": MODEL,
        "base": {
            "path": str(base),
            "bytes": base.stat().st_size,
            "sha256": BASE_SHA256,
            "body_sha256": BASE_BODY_SHA256,
            "variables": BASE_VARIABLES,
            "clauses": BASE_CLAUSES,
        },
        "mathematical_exhaustion": exhaustion,
        "entries": entries,
        "case_count": len(entries),
        "binaries": {
            name: binary(here / name)
            for name in ("cadical", "drat-trim", "lrat-check")
        },
        "generator": {
            "path": Path(__file__).name,
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
    try:
        manifest = build()
    except GenerationError as error:
        print(f"H0 PROFILE GENERATION FAILED: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "result": "H0 PROFILE GENERATION PASSED",
                "cases": manifest["case_count"],
                "manifest_sha256": manifest["manifest_sha256"],
                "profiles": manifest["mathematical_exhaustion"]["profiles"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
