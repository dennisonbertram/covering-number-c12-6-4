#!/usr/bin/env python3
"""Stdlib-only reconstruction audit of all compact profile-leaf extensions.

This auditor does not import Python-SAT.  It loads the sibling, hash-pinned
standard-library transcription of python-sat 1.9.dev7's
``cardenc/mto.hh`` and uses it to reproduce every
``CardEnc.equals(..., EncType.kmtotalizer)`` call in the frozen ordinary,
h=0, and h=1 profile campaigns.  It checks exact clause order, auxiliary
identifier boundaries, section counts and hashes, extension bytes and hashes,
and complete CNF bytes and hashes for all 155 leaves.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import itertools
import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Sequence


if not __debug__:
    raise RuntimeError(
        "this proof auditor refuses Python -O because checks must remain enabled"
    )


HERE = Path(__file__).resolve().parent
ENCODER_ROOT = HERE.parent / "compact-encoder-audit"
ENCODER_PATH = ENCODER_ROOT / "audit_kmtotalizer.py"
ENCODER_SHA256 = (
    "cd22aedc14c9ea87ac1c4aba3a27d3cbc663f8159d12e4b609822229ebeb749d"
)
FROZEN_VERIFY_PATH = ENCODER_ROOT / "verify_frozen_audit.py"
FROZEN_VERIFY_SHA256 = (
    "2730761ade25ddb0b4669cb0332690f7bad18a504c4a06ba648da95f542b4c14"
)
FROZEN_REPORT_PATH = ENCODER_ROOT / "results" / "AUDIT_REPORT.json"
FROZEN_REPORT_SHA256 = (
    "0b945bcc35c9f70f871527103e91970312a650837291254412105c64c85c7fb9"
)

COMPACT_MANIFEST_SHA256 = (
    "4b3ea887dcb05312b6ee82d10988bc5b0faf9d61c9a1fec292114559ff259835"
)
ORDINARY_MANIFEST_SHA256 = (
    "f5066fcf1b978b5e967cf921d0d3dbeb7ad97c4f10d707cbc06cdb89bd179c0e"
)
H0_MANIFEST_SHA256 = (
    "fad8acff6636457a1227f1c99ba94ba50e341084bad8bc7f74426bba779fa1e9"
)
H1_MANIFEST_SHA256 = (
    "58a262664267ba87cf8c7c37ec7e7739c094beb3a7409189c7268dff4f09c3b8"
)
PORTABLE_MANIFEST_IDENTITIES = {
    "ordinary_profile_refinements": {
        "manifest_sha256": (
            "d9ebde00298e19140eb9b97e09cf2eba94732397ceffdd071c1c71d603e818ef"
        ),
        "source_manifest_sha256": ORDINARY_MANIFEST_SHA256,
        "source_manifest_file_sha256": (
            "7521a231ba85249d2afaf05a77995ecd424a5d29a8136ea2e141b387e68426f4"
        ),
        "sanitized_fields": {
            "base.path": "../global_base.cnf",
            "parent_campaign.path": "../manifest.json",
        },
    },
    "h0_profiles": {
        "manifest_sha256": (
            "b308bffee53b5cae60f34f522b60f02a3b26ebaeac2346a17ee48cfe2ed47775"
        ),
        "source_manifest_sha256": H0_MANIFEST_SHA256,
        "source_manifest_file_sha256": (
            "009026d3ed3c27b3ffbf518f645016581bab848b5a5a21ffbaa60f25916f1d20"
        ),
        "sanitized_fields": {"base.path": "../global_base.cnf"},
    },
    "h1_profiles": {
        "manifest_sha256": (
            "d09ec1f0ad3be72c5843d9955de5fdcd8bbec2f30aa4cc53ea6d85a22a827d27"
        ),
        "source_manifest_sha256": H1_MANIFEST_SHA256,
        "source_manifest_file_sha256": (
            "4a697492d0dd293584ea164fa1ea27ab93cb69895781b3e6138aa1667caa9bd8"
        ),
        "sanitized_fields": {"base.path": "../global_base.cnf"},
    },
}
BASE_SHA256 = (
    "637d9326388f77f933f3d066cd762d8c0ac4b2df0d2260d688e031d55959e7f0"
)
BASE_BODY_SHA256 = (
    "6a1a2eb2843a4ddcf9138c5a85aaeccd2950b3e099e0ab8a26ce9fc815ab0cc5"
)
BASE_VARIABLES = 122_519
BASE_CLAUSES = 356_407

POINTS = tuple(range(12))
MATCHING = tuple((2 * index, 2 * index + 1) for index in range(6))
BLOCKS = tuple(itertools.combinations(POINTS, 6))
BLOCK_INDEX = {block: index for index, block in enumerate(BLOCKS)}
SUPPORTS = tuple(itertools.combinations(range(6), 3))
SUPPORT_INDEX = {
    support: index for index, support in enumerate(SUPPORTS)
}
PAIR_PERMUTATIONS = tuple(itertools.permutations(range(6)))
TYPE0_CANONICAL = (0, 2, 4, 6, 8, 10)
TYPE1_CANONICAL = (0, 1, 4, 6, 8, 10)
H1_SELECTED_SUPPORT = frozenset((0, 1, 2))
H1_TYPE1_ROOTS = (
    ("full_in_empty_in", (0, 1, 4, 6, 8, 10)),
    ("full_out_empty_out", (0, 2, 4, 6, 7, 10)),
    ("full_in_empty_out", (0, 1, 2, 4, 8, 10)),
    ("full_out_empty_in", (2, 4, 6, 7, 8, 10)),
)
REPORT_PATH = HERE / "results" / "AUDIT_REPORT.json"
REQUIRED_RETAINED_CNFS = {
    "ordinary_profile_refinements": (
        "cases/parent_0003_h02_p00_k1_w00_v036.cnf"
    ),
    "h0_profiles": "cases/h0_profile_a00.cnf",
    "h1_profiles": "cases/h1_a00_full_in_empty_in.cnf",
}


class AuditError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise AuditError(message)


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        fail(f"{path}: regular non-symlink file required")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def strict_json(path: Path) -> dict[str, Any]:
    def unique(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                fail(f"{path}: duplicate JSON key {key!r}")
            result[key] = value
        return result

    if path.is_symlink() or not path.is_file():
        fail(f"{path}: regular non-symlink JSON required")
    try:
        result = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique,
            parse_constant=lambda token: fail(
                f"{path}: invalid JSON constant {token}"
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"{path}: invalid JSON: {error}")
    if not isinstance(result, dict):
        fail(f"{path}: top-level object required")
    return result


def validate_hash(
    payload: dict[str, Any], key: str, expected: str | None = None
) -> str:
    claimed = payload.get(key)
    actual = sha(
        canonical({name: value for name, value in payload.items() if name != key})
    )
    if not isinstance(claimed, str) or claimed != actual:
        fail(f"{key}: self-hash mismatch")
    if expected is not None and claimed != expected:
        fail(f"{key}: pinned hash mismatch")
    return claimed


def validate_manifest(
    path: Path,
    suite: str,
    expected_hash: str,
    expected_model: str,
    expected_count: int,
) -> tuple[dict[str, Any], dict[str, str]]:
    manifest = strict_json(path)
    validate_hash(manifest, "manifest_sha256")
    portable = PORTABLE_MANIFEST_IDENTITIES[suite]
    if manifest["manifest_sha256"] == expected_hash:
        if "portable_provenance" in manifest:
            fail(f"{path}: frozen source manifest has portable provenance")
        variant = {
            "kind": "frozen_source",
            "manifest_sha256": expected_hash,
            "source_manifest_sha256": expected_hash,
        }
    elif manifest["manifest_sha256"] == portable["manifest_sha256"]:
        expected_provenance = {
            "model_version": "c12-portable-suite-manifest-v1",
            "source_manifest_file_sha256": portable[
                "source_manifest_file_sha256"
            ],
            "source_manifest_sha256": portable[
                "source_manifest_sha256"
            ],
            "sanitized_fields": portable["sanitized_fields"],
        }
        if manifest.get("portable_provenance") != expected_provenance:
            fail(f"{path}: portable provenance mismatch")
        if manifest.get("base", {}).get("path") != "../global_base.cnf":
            fail(f"{path}: portable base path mismatch")
        if (
            suite == "ordinary_profile_refinements"
            and manifest.get("parent_campaign", {}).get("path")
            != "../manifest.json"
        ):
            fail(f"{path}: portable parent path mismatch")
        variant = {
            "kind": "portable_provenance_bound",
            "manifest_sha256": portable["manifest_sha256"],
            "source_manifest_sha256": expected_hash,
        }
    else:
        fail(f"{path}: neither source nor portable manifest hash matches")
    core = {
        key: value
        for key, value in manifest.items()
        if key not in ("core_sha256", "manifest_sha256")
    }
    if (
        manifest.get("core_sha256") != sha(canonical(core))
        or manifest.get("model_version") != expected_model
        or manifest.get("case_count") != expected_count
        or not isinstance(manifest.get("entries"), list)
        or len(manifest["entries"]) != expected_count
    ):
        fail(f"{path}: core/model/case-count mismatch")
    generator = path.parent / manifest["generator"]["path"]
    if (
        generator.is_symlink()
        or not generator.is_file()
        or file_sha(generator) != manifest["generator"]["sha256"]
        or manifest["generator"].get("pysat") != "1.9.dev7"
    ):
        fail(f"{path}: frozen generator identity mismatch")
    return manifest, variant


def checked_relative(root: Path, relative: Any, label: str) -> Path:
    if not isinstance(relative, str):
        fail(f"{label}: path must be a string")
    path = Path(relative)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        fail(f"{label}: unsafe path")
    candidate = root / path
    root_resolved = root.resolve()
    resolved = candidate.resolve()
    if os.path.commonpath((str(root_resolved), str(resolved))) != str(
        root_resolved
    ):
        fail(f"{label}: path escapes campaign family root")
    cursor = candidate
    while cursor != root:
        if cursor.is_symlink():
            fail(f"{label}: symlink rejected")
        cursor = cursor.parent
    if not candidate.is_file():
        fail(f"{label}: file missing")
    return candidate


def block_kind(block: tuple[int, ...]) -> int:
    selected = frozenset(block)
    occupancy = tuple(
        len(selected.intersection(pair)) for pair in MATCHING
    )
    full = occupancy.count(2)
    if full != occupancy.count(0):
        fail(f"{block}: matching occupancy identity failed")
    return full


KINDS = tuple(block_kind(block) for block in BLOCKS)
TYPE_VARIABLES = tuple(
    tuple(index + 1 for index, kind in enumerate(KINDS) if kind == target)
    for target in range(4)
)
TYPE3_VARIABLES = tuple(
    BLOCK_INDEX[
        tuple(
            point
            for pair_index in support
            for point in MATCHING[pair_index]
        )
    ]
    + 1
    for support in SUPPORTS
)


def clause_raw(clause: Sequence[int]) -> bytes:
    return (" ".join(map(str, clause)) + " 0\n").encode()


def load_transcription() -> Any:
    if (
        ENCODER_PATH.is_symlink()
        or not ENCODER_PATH.is_file()
        or file_sha(ENCODER_PATH) != ENCODER_SHA256
    ):
        fail("pinned stdlib kmtotalizer transcription identity mismatch")
    module_name = "c1264_pinned_kmtotalizer_transcription"
    if module_name in sys.modules:
        fail("pinned transcription module name was already loaded")
    specification = importlib.util.spec_from_file_location(
        module_name, ENCODER_PATH
    )
    if specification is None or specification.loader is None:
        fail("cannot construct pinned-transcription import specification")
    module = importlib.util.module_from_spec(specification)
    sys.modules[module_name] = module
    specification.loader.exec_module(module)
    module_file = Path(getattr(module, "__file__", "")).resolve()
    if (
        module_file != ENCODER_PATH.resolve()
        or module.SOURCE_COMMIT
        != "7abb1d6fdafe1d75fe3e5cdfb48f7e07a8a76efd"
        or module.SOURCE_VERSION != "1.9.dev7"
        or module.EXPECTED_FULL_SHA256 != BASE_SHA256
    ):
        fail("pinned transcription provenance constants mismatch")
    return module


def run_frozen_encoder_audit() -> dict[str, Any]:
    if (
        FROZEN_VERIFY_PATH.is_symlink()
        or not FROZEN_VERIFY_PATH.is_file()
        or file_sha(FROZEN_VERIFY_PATH) != FROZEN_VERIFY_SHA256
        or file_sha(FROZEN_REPORT_PATH) != FROZEN_REPORT_SHA256
    ):
        fail("frozen semantic-audit identity mismatch")
    completed = subprocess.run(
        (sys.executable, "-S", str(FROZEN_VERIFY_PATH)),
        cwd=ENCODER_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=60,
    )
    marker = "COMPACT ENCODER FROZEN AUDIT: PASS"
    if completed.returncode != 0 or marker not in completed.stdout:
        fail(
            "frozen semantic audit failed: "
            f"{completed.stderr[-1000:]}"
        )
    return {
        "transcription_path": "../compact-encoder-audit/audit_kmtotalizer.py",
        "transcription_sha256": ENCODER_SHA256,
        "verify_path": "../compact-encoder-audit/verify_frozen_audit.py",
        "verify_sha256": FROZEN_VERIFY_SHA256,
        "report_sha256": FROZEN_REPORT_SHA256,
        "stdout_sha256": sha(completed.stdout.encode()),
        "success_marker": marker,
    }


def read_base(campaign_root: Path) -> tuple[bytes, bytes]:
    path = campaign_root / "global_base.cnf"
    if (
        path.is_symlink()
        or not path.is_file()
        or file_sha(path) != BASE_SHA256
    ):
        fail("compact global base identity mismatch")
    raw = path.read_bytes()
    header, body = raw.split(b"\n", 1)
    if (
        header != b"p cnf 122519 356407"
        or sha(body) != BASE_BODY_SHA256
        or len(body.splitlines()) != BASE_CLAUSES
    ):
        fail("compact global base header/body mismatch")
    return raw, body


def independent_root_units(
    compact_manifest: dict[str, Any],
    campaign_root: Path,
    parent_index: int,
) -> bytes:
    parent = compact_manifest["entries"][parent_index]
    mask = parent["representative_mask"]
    expected = b"".join(
        clause_raw(
            (
                variable if mask & (1 << support_index) else -variable,
            )
        )
        for support_index, variable in enumerate(TYPE3_VARIABLES)
    )
    path = checked_relative(campaign_root, parent["root"], "parent root")
    actual = path.read_bytes()
    if (
        len(actual) != parent["root_bytes"]
        or sha(actual) != parent["root_sha256"]
        or actual != expected
    ):
        fail(f"parent {parent_index}: fixed-support units mismatch")
    return expected


def verify_profile_counts(counts: dict[str, Any], label: str) -> None:
    expected_keys = {"n0", "n1", "n2", "n3"}
    if (
        not isinstance(counts, dict)
        or set(counts) != expected_keys
        or any(
            not isinstance(counts[key], int) or counts[key] < 0
            for key in expected_keys
        )
        or sum(counts.values()) != 40
        or counts["n1"] + 2 * counts["n2"] + 3 * counts["n3"] != 60
    ):
        fail(f"{label}: exact type profile identities failed")


def feasible_profiles(h: int) -> tuple[tuple[int, int, int, int], ...]:
    answer = []
    for n0 in range(41):
        for n1 in range(41 - n0):
            n2 = 40 - h - n0 - n1
            if n2 >= 0 and n1 + 2 * n2 + 3 * h == 60:
                answer.append((n0, n1, n2, h))
    if not answer:
        fail(f"h={h}: no feasible type profiles")
    for profile in answer:
        if (
            sum(profile) != 40
            or sum(
                kind * count for kind, count in enumerate(profile)
            )
            != 60
        ):
            fail(f"h={h}: profile identity failed for {profile}")
    return tuple(answer)


def support_action(permutation: tuple[int, ...]) -> tuple[int, ...]:
    return tuple(
        SUPPORT_INDEX[
            tuple(sorted(permutation[index] for index in support))
        ]
        for support in SUPPORTS
    )


def permute_support_mask(mask: int, action: tuple[int, ...]) -> int:
    image = 0
    for source, target in enumerate(action):
        if mask & (1 << source):
            image |= 1 << target
    return image


def support_stabilizer(mask: int) -> tuple[tuple[int, ...], ...]:
    answer = tuple(
        permutation
        for permutation in PAIR_PERMUTATIONS
        if permute_support_mask(mask, support_action(permutation)) == mask
    )
    if not answer or tuple(range(6)) not in answer:
        fail(f"support mask {mask}: invalid pair-permutation stabilizer")
    return answer


def point_image(
    point: int, permutation: tuple[int, ...], flips: int
) -> int:
    pair_index, endpoint = divmod(point, 2)
    return 2 * permutation[pair_index] + (
        endpoint ^ ((flips >> pair_index) & 1)
    )


def block_image(
    block: tuple[int, ...],
    permutation: tuple[int, ...],
    flips: int,
) -> tuple[int, ...]:
    return tuple(
        sorted(
            point_image(point, permutation, flips) for point in block
        )
    )


def block_orbits(
    kind: int, stabilizer: Sequence[tuple[int, ...]]
) -> tuple[tuple[tuple[int, ...], ...], ...]:
    target = {
        block
        for block, block_kind_value in zip(BLOCKS, KINDS)
        if block_kind_value == kind
    }
    unseen = set(target)
    answer = []
    while unseen:
        representative = min(unseen)
        orbit = {
            block_image(representative, permutation, flips)
            for permutation in stabilizer
            for flips in range(64)
        }
        if not orbit.issubset(unseen):
            fail(f"type-{kind} witness orbits overlap or leave type")
        answer.append(tuple(sorted(orbit)))
        unseen.difference_update(orbit)
    flattened = [block for orbit in answer for block in orbit]
    if len(flattened) != len(set(flattened)) or set(flattened) != target:
        fail(f"type-{kind} witness orbits do not partition the type")
    return tuple(sorted(answer, key=lambda orbit: orbit[0]))


def require_entry_fields(
    entry: dict[str, Any], expected: dict[str, Any], label: str
) -> None:
    for key, value in expected.items():
        if canonical(entry.get(key)) != canonical(value):
            fail(f"{label}.{key}: independent partition mismatch")


def verify_ordinary_partition(
    campaign_root: Path,
    compact_manifest: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    parent_indexes = (3, 4, 9, 10, 11, 31, 32)
    entries = manifest["entries"]
    expected_coverages = []
    entry_index = 0
    profile_total = 0
    witness_orbit_total = 0
    for parent_index in parent_indexes:
        parent = compact_manifest["entries"][parent_index]
        h = parent["selected_support_count"]
        mask = parent["representative_mask"]
        if (
            not 2 <= h <= 19
            or bin(mask).count("1") != h
            or tuple(map(tuple, parent["selected_supports"]))
            != tuple(
                SUPPORTS[index]
                for index in range(20)
                if mask & (1 << index)
            )
        ):
            fail(f"parent {parent_index}: support identity mismatch")
        independent_root_units(
            compact_manifest, campaign_root, parent_index
        )
        stabilizer = support_stabilizer(mask)
        orbits_by_kind = {
            0: block_orbits(0, stabilizer),
            1: block_orbits(1, stabilizer),
        }
        profiles = feasible_profiles(h)
        profile_total += len(profiles)
        profile_coverages = []
        child_start = entry_index
        for profile_index, profile in enumerate(profiles):
            counts = {
                "n0": profile[0],
                "n1": profile[1],
                "n2": profile[2],
                "n3": profile[3],
            }
            witness_kind = 0 if profile[0] > 0 else 1
            orbits = orbits_by_kind[witness_kind]
            witness_orbit_total += len(orbits)
            child_indexes = []
            for witness_orbit_index, orbit in enumerate(orbits):
                if entry_index >= len(entries):
                    fail("ordinary partition has too few entries")
                witness_block = orbit[0]
                witness_variable = BLOCK_INDEX[witness_block] + 1
                case_id = (
                    f"parent_{parent_index:04d}_h{h:02d}_"
                    f"p{profile_index:02d}_k{witness_kind}_"
                    f"w{witness_orbit_index:02d}_v{witness_variable:03d}"
                )
                require_entry_fields(
                    entries[entry_index],
                    {
                        "child_index": entry_index,
                        "case_id": case_id,
                        "parent_index": parent_index,
                        "parent_case_id": parent["case_id"],
                        "parent_case_cnf_sha256": parent[
                            "case_cnf_sha256"
                        ],
                        "parent_root_sha256": parent["root_sha256"],
                        "parent_support_mask": mask,
                        "parent_support_count": h,
                        "parent_orbit_size": parent["orbit_size"],
                        "profile_index": profile_index,
                        "type_counts": counts,
                        "witness_kind": witness_kind,
                        "witness_orbit_index": witness_orbit_index,
                        "witness_orbit_size": len(orbit),
                        "witness_block": list(witness_block),
                        "witness_variable": witness_variable,
                        "pair_permutation_stabilizer_order": len(
                            stabilizer
                        ),
                        "full_stabilizer_order": 64 * len(stabilizer),
                    },
                    case_id,
                )
                child_indexes.append(entry_index)
                entry_index += 1
            profile_coverages.append(
                {
                    "profile_index": profile_index,
                    "type_counts": counts,
                    "witness_kind": witness_kind,
                    "witness_count": profile[witness_kind],
                    "witness_orbit_count": len(orbits),
                    "witness_orbit_sizes": [
                        len(orbit) for orbit in orbits
                    ],
                    "child_indexes": child_indexes,
                }
            )
        child_end = entry_index
        expected_coverages.append(
            {
                "parent_index": parent_index,
                "parent_case_id": parent["case_id"],
                "parent_case_cnf_sha256": parent[
                    "case_cnf_sha256"
                ],
                "parent_root_sha256": parent["root_sha256"],
                "parent_support_mask": mask,
                "parent_support_count": h,
                "parent_orbit_size": parent["orbit_size"],
                "pair_permutation_stabilizer_order": len(stabilizer),
                "full_stabilizer_order": 64 * len(stabilizer),
                "feasible_profiles": [list(profile) for profile in profiles],
                "profile_count": len(profiles),
                "profile_coverages": profile_coverages,
                "child_index_start": child_start,
                "child_index_end_exclusive": child_end,
                "child_count": child_end - child_start,
            }
        )
    if entry_index != 130 or entry_index != len(entries):
        fail("ordinary partition does not contain exactly 130 children")
    if (
        len({entry["case_id"] for entry in entries}) != 130
        or len({entry["cnf"] for entry in entries}) != 130
        or len({entry["cnf_sha256"] for entry in entries}) != 130
    ):
        fail("ordinary partition case/CNF identities are not unique")
    expected_exhaustion = {
        "refined_parent_indices": list(parent_indexes),
        "parent_count": len(parent_indexes),
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
        "parent_coverages": expected_coverages,
    }
    if canonical(manifest.get("mathematical_exhaustion")) != canonical(
        expected_exhaustion
    ):
        fail("ordinary mathematical-exhaustion metadata mismatch")
    return {
        "parent_orbits": 7,
        "feasible_profiles": profile_total,
        "stabilizer_witness_orbits": witness_orbit_total,
        "children": entry_index,
        "unique_case_ids": 130,
        "unique_cnf_paths": 130,
        "unique_cnf_sha256": 130,
    }


def verify_h0_partition(
    campaign_root: Path,
    compact_manifest: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    parent = compact_manifest["entries"][0]
    require_entry_fields(
        parent,
        {
            "case_index": 0,
            "representative_mask": 0,
            "selected_support_count": 0,
            "selected_supports": [],
            "orbit_size": 1,
        },
        "h0 compact parent",
    )
    independent_root_units(compact_manifest, campaign_root, 0)
    profiles = feasible_profiles(0)
    if profiles != tuple(
        (a, 20 - 2 * a, 20 + a, 0) for a in range(11)
    ):
        fail("h0 feasible-profile exhaustion mismatch")
    full_group = PAIR_PERMUTATIONS
    type0_orbits = block_orbits(0, full_group)
    type1_orbits = block_orbits(1, full_group)
    if (
        len(type0_orbits) != 1
        or len(type0_orbits[0]) != 64
        or type0_orbits[0][0] != TYPE0_CANONICAL
        or len(type1_orbits) != 1
        or len(type1_orbits[0]) != 480
        or TYPE1_CANONICAL not in type1_orbits[0]
    ):
        fail("h0 matching-group type-orbit exhaustion mismatch")
    expected_exhaustion = {
        "profiles": [list(profile) for profile in profiles],
        "profile_count": 11,
        "type_histogram": [len(values) for values in TYPE_VARIABLES],
        "type0_orbit_size": 64,
        "type1_orbit_size": 480,
        "a_positive_normalization": "selected canonical type-0 block",
        "a_zero_normalization": (
            "n0=0 and selected canonical type-1 block"
        ),
    }
    if canonical(manifest.get("mathematical_exhaustion")) != canonical(
        expected_exhaustion
    ):
        fail("h0 mathematical-exhaustion metadata mismatch")
    entries = manifest["entries"]
    for a, profile in enumerate(profiles):
        canonical_block = (
            TYPE1_CANONICAL if a == 0 else TYPE0_CANONICAL
        )
        canonical_kind = 1 if a == 0 else 0
        require_entry_fields(
            entries[a],
            {
                "profile_index": a,
                "case_id": f"h0_profile_a{a:02d}",
                "type_counts": {
                    f"n{kind}": profile[kind] for kind in range(4)
                },
                "canonical_kind": canonical_kind,
                "canonical_block": list(canonical_block),
                "canonical_variable": BLOCK_INDEX[canonical_block] + 1,
                "cnf": f"cases/h0_profile_a{a:02d}.cnf",
            },
            f"h0 profile {a}",
        )
    if (
        len({entry["case_id"] for entry in entries}) != 11
        or len({entry["cnf"] for entry in entries}) != 11
        or len({entry["cnf_sha256"] for entry in entries}) != 11
        or len(
            {
                canonical(entry["type_counts"])
                for entry in entries
            }
        )
        != 11
    ):
        fail("h0 profile/case/CNF identities are not unique")
    return {
        "linked_parent_index": 0,
        "linked_parent_case_id": parent["case_id"],
        "linked_parent_root_sha256": parent["root_sha256"],
        "feasible_profiles": 11,
        "matching_type_orbits": 2,
        "roots": 11,
        "unique_profiles": 11,
        "unique_case_ids": 11,
        "unique_cnf_sha256": 11,
    }


def h1_type1_category(block: tuple[int, ...]) -> str:
    selected = frozenset(block)
    full = [
        index
        for index, pair in enumerate(MATCHING)
        if len(selected.intersection(pair)) == 2
    ]
    empty = [
        index
        for index, pair in enumerate(MATCHING)
        if len(selected.intersection(pair)) == 0
    ]
    if len(full) != 1 or len(empty) != 1:
        fail(f"{block}: not a type-1 block")
    return (
        f"full_{'in' if full[0] in H1_SELECTED_SUPPORT else 'out'}_"
        f"empty_{'in' if empty[0] in H1_SELECTED_SUPPORT else 'out'}"
    )


def verify_h1_partition(
    campaign_root: Path,
    compact_manifest: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    parent = compact_manifest["entries"][1]
    require_entry_fields(
        parent,
        {
            "case_index": 1,
            "representative_mask": 1,
            "selected_support_count": 1,
            "selected_supports": [sorted(H1_SELECTED_SUPPORT)],
            "orbit_size": 20,
        },
        "h1 compact parent",
    )
    independent_root_units(compact_manifest, campaign_root, 1)
    profiles = feasible_profiles(1)
    if profiles != tuple(
        (a, 21 - 2 * a, 18 + a, 1) for a in range(11)
    ):
        fail("h1 feasible-profile exhaustion mismatch")
    selected_mask = 1
    stabilizer = support_stabilizer(selected_mask)
    if len(stabilizer) != 36:
        fail("h1 selected-support stabilizer order mismatch")
    type0_orbits = block_orbits(0, stabilizer)
    if len(type0_orbits) != 1 or set(type0_orbits[0]) != {
        block
        for block, kind in zip(BLOCKS, KINDS)
        if kind == 0
    }:
        fail("h1 type-0 orbit exhaustion mismatch")
    category_sizes = {}
    type1_union: set[tuple[int, ...]] = set()
    for category, representative in H1_TYPE1_ROOTS:
        orbit = {
            block_image(representative, permutation, flips)
            for permutation in stabilizer
            for flips in range(64)
        }
        target = {
            block
            for block, kind in zip(BLOCKS, KINDS)
            if kind == 1 and h1_type1_category(block) == category
        }
        if orbit != target or type1_union.intersection(orbit):
            fail(f"h1 type-1 orbit mismatch for {category}")
        type1_union.update(orbit)
        category_sizes[category] = len(orbit)
    if type1_union != {
        block for block, kind in zip(BLOCKS, KINDS) if kind == 1
    }:
        fail("h1 type-1 category orbits do not exhaust type 1")
    expected_exhaustion = {
        "profiles": [list(profile) for profile in profiles],
        "profile_count": 11,
        "refined_root_count": 14,
        "selected_type3_support": sorted(H1_SELECTED_SUPPORT),
        "stabilizer_pair_permutations": 36,
        "stabilizer_with_endpoint_flips_order": 2_304,
        "type0_orbit_size": 64,
        "type1_category_orbit_sizes": category_sizes,
    }
    if canonical(manifest.get("mathematical_exhaustion")) != canonical(
        expected_exhaustion
    ):
        fail("h1 mathematical-exhaustion metadata mismatch")
    root_specs = []
    for a, profile in enumerate(profiles):
        if a == 0:
            for subcase, representative in H1_TYPE1_ROOTS:
                root_specs.append(
                    (a, subcase, profile, representative)
                )
        else:
            root_specs.append((a, "type0", profile, TYPE0_CANONICAL))
    entries = manifest["entries"]
    for case_index, (
        a,
        subcase,
        profile,
        representative,
    ) in enumerate(root_specs):
        case_id = f"h1_a{a:02d}_{subcase}"
        require_entry_fields(
            entries[case_index],
            {
                "case_index": case_index,
                "case_id": case_id,
                "a": a,
                "subcase": subcase,
                "type_counts": {
                    f"n{kind}": profile[kind] for kind in range(4)
                },
                "canonical_block": list(representative),
                "canonical_variable": BLOCK_INDEX[representative] + 1,
                "cnf": f"cases/{case_id}.cnf",
            },
            f"h1 root {case_index}",
        )
    if (
        len(entries) != 14
        or len({entry["case_id"] for entry in entries}) != 14
        or len({entry["cnf"] for entry in entries}) != 14
        or len({entry["cnf_sha256"] for entry in entries}) != 14
    ):
        fail("h1 root/case/CNF identities are not unique")
    return {
        "linked_parent_index": 1,
        "linked_parent_case_id": parent["case_id"],
        "linked_parent_root_sha256": parent["root_sha256"],
        "feasible_profiles": 11,
        "type0_stabilizer_orbits": 1,
        "type1_stabilizer_orbits": 4,
        "roots": 14,
        "unique_case_ids": 14,
        "unique_cnf_sha256": 14,
    }


def encode_section(
    kmt: Any,
    top: Any,
    kind: int,
    bound: int,
    section_name: str,
    unique: Counter[tuple[int, int]],
) -> tuple[bytes, dict[str, Any]]:
    inputs = TYPE_VARIABLES[kind]
    before = top.value
    clauses, parts = kmt.encode_equals(inputs, bound, top)
    raw = b"".join(clause_raw(clause) for clause in clauses)
    if (
        parts["top_before"] != before
        or parts["top_after_atmost"] != top.value
        or len(clauses) != parts["atleast_clauses"] + parts["atmost_clauses"]
    ):
        fail(f"{section_name}: encoder boundary accounting failed")
    unique[(len(inputs), bound)] += 1
    return raw, {
        "section": section_name,
        "kind": kind,
        "arity": len(inputs),
        "bound": bound,
        "top_before": before,
        "top_after_atleast": parts["top_after_atleast"],
        "top_after_atmost": top.value,
        "auxiliary_variables": top.value - before,
        "atleast_clauses": parts["atleast_clauses"],
        "atmost_clauses": parts["atmost_clauses"],
        "clauses": len(clauses),
        "bytes": len(raw),
        "sha256": sha(raw),
    }


def audit_case_file(
    family_root: Path,
    entry: dict[str, Any],
    base_body: bytes,
    extension: bytes,
    final_top: int,
    extension_clauses: int,
    required_retained: bool,
) -> bool:
    relative = entry["cnf"]
    if not isinstance(relative, str):
        fail("profile CNF path must be a string")
    relative_path = Path(relative)
    if (
        relative_path.is_absolute()
        or not relative_path.parts
        or any(part in ("", ".", "..") for part in relative_path.parts)
    ):
        fail("profile CNF path is unsafe")
    case_path = family_root / relative_path
    root_resolved = family_root.resolve()
    resolved = case_path.resolve()
    if os.path.commonpath((str(root_resolved), str(resolved))) != str(
        root_resolved
    ):
        fail("profile CNF path escapes family root")
    expected_clauses = BASE_CLAUSES + extension_clauses
    expected = (
        f"p cnf {final_top} {expected_clauses}\n".encode()
        + base_body
        + extension
    )
    if (
        final_top != entry["variables"]
        or expected_clauses != entry["clauses"]
        or len(extension) != entry["extension_bytes"]
        or sha(extension) != entry["extension_sha256"]
        or len(expected) != entry["cnf_bytes"]
        or sha(expected) != entry["cnf_sha256"]
    ):
        fail(f"{entry['case_id']}: extension/full-CNF reconstruction mismatch")
    # Solved leaves may have their reproducible CNF pruned after proof
    # compression.  When the frozen file remains, compare every byte; when it
    # does not, the independently reconstructed bytes must still match both
    # frozen byte count and frozen SHA-256 above.
    if case_path.exists():
        if case_path.is_symlink() or not case_path.is_file():
            fail(f"{entry['case_id']}: profile CNF is not a regular file")
        if case_path.read_bytes() != expected:
            fail(f"{entry['case_id']}: available profile CNF bytes differ")
        return True
    if required_retained:
        fail(f"{entry['case_id']}: designated retained profile CNF missing")
    return False


def audit_ordinary(
    kmt: Any,
    campaign_root: Path,
    compact_manifest: dict[str, Any],
    manifest: dict[str, Any],
    base_body: bytes,
    unique: Counter[tuple[int, int]],
) -> list[dict[str, Any]]:
    root = campaign_root / "ordinary_profile_refinements"
    records = []
    for index, entry in enumerate(manifest["entries"]):
        if entry.get("child_index") != index:
            fail(f"ordinary entry {index}: child index/order mismatch")
        counts = entry["type_counts"]
        verify_profile_counts(counts, entry["case_id"])
        if counts["n3"] != entry["parent_support_count"]:
            fail(f"{entry['case_id']}: parent support/profile mismatch")
        fixed = independent_root_units(
            compact_manifest, campaign_root, entry["parent_index"]
        )
        top = kmt.Top(BASE_VARIABLES)
        extension_parts = [fixed]
        sections = []
        expected_section_counts = {"fixed_type3_support": 20}
        for kind in range(3):
            name = f"exact_type{kind}"
            raw, record = encode_section(
                kmt, top, kind, counts[f"n{kind}"], name, unique
            )
            extension_parts.append(raw)
            sections.append(record)
            expected_section_counts[name] = record["clauses"]
        witness = entry["witness_variable"]
        if (
            BLOCK_INDEX[tuple(entry["witness_block"])] + 1 != witness
            or KINDS[witness - 1] != entry["witness_kind"]
        ):
            fail(f"{entry['case_id']}: witness block-variable mismatch")
        extension_parts.append(clause_raw((witness,)))
        expected_section_counts["witness_unit"] = 1
        if expected_section_counts != entry["section_clause_counts"]:
            fail(f"{entry['case_id']}: section clause-count mismatch")
        extension = b"".join(extension_parts)
        audit_case_file(
            root,
            entry,
            base_body,
            extension,
            top.value,
            sum(expected_section_counts.values()),
            entry["cnf"]
            == REQUIRED_RETAINED_CNFS["ordinary_profile_refinements"],
        )
        records.append(
            {
                "case_index": index,
                "case_id": entry["case_id"],
                "parent_index": entry["parent_index"],
                "profile_index": entry["profile_index"],
                "type_counts": counts,
                "sections": sections,
                "final_top_id": top.value,
                "extension_bytes": len(extension),
                "extension_sha256": sha(extension),
                "cnf_sha256": entry["cnf_sha256"],
            }
        )
    return records


def audit_h0(
    kmt: Any,
    campaign_root: Path,
    compact_manifest: dict[str, Any],
    manifest: dict[str, Any],
    base_body: bytes,
    unique: Counter[tuple[int, int]],
) -> list[dict[str, Any]]:
    root = campaign_root / "h0_profiles"
    fixed = independent_root_units(compact_manifest, campaign_root, 0)
    records = []
    for index, entry in enumerate(manifest["entries"]):
        if entry.get("profile_index") != index:
            fail(f"h0 entry {index}: profile order mismatch")
        counts = entry["type_counts"]
        verify_profile_counts(counts, entry["case_id"])
        if counts["n3"] != 0:
            fail(f"{entry['case_id']}: h0 profile has nonzero n3")
        top = kmt.Top(BASE_VARIABLES)
        extension_parts = [fixed]
        sections = []
        expected_section_counts = {"fixed_type3_zero": 20}
        for kind in range(3):
            name = f"exact_type{kind}"
            raw, record = encode_section(
                kmt, top, kind, counts[f"n{kind}"], name, unique
            )
            extension_parts.append(raw)
            sections.append(record)
            expected_section_counts[name] = record["clauses"]
        witness = entry["canonical_variable"]
        if (
            BLOCK_INDEX[tuple(entry["canonical_block"])] + 1 != witness
            or KINDS[witness - 1] != entry["canonical_kind"]
        ):
            fail(f"{entry['case_id']}: canonical block-variable mismatch")
        extension_parts.append(clause_raw((witness,)))
        expected_section_counts["symmetry_unit"] = 1
        if expected_section_counts != entry["section_clause_counts"]:
            fail(f"{entry['case_id']}: section clause-count mismatch")
        extension = b"".join(extension_parts)
        audit_case_file(
            root,
            entry,
            base_body,
            extension,
            top.value,
            sum(expected_section_counts.values()),
            entry["cnf"] == REQUIRED_RETAINED_CNFS["h0_profiles"],
        )
        records.append(
            {
                "case_index": index,
                "case_id": entry["case_id"],
                "profile_index": index,
                "type_counts": counts,
                "sections": sections,
                "final_top_id": top.value,
                "extension_bytes": len(extension),
                "extension_sha256": sha(extension),
                "cnf_sha256": entry["cnf_sha256"],
            }
        )
    return records


def audit_h1(
    kmt: Any,
    campaign_root: Path,
    compact_manifest: dict[str, Any],
    manifest: dict[str, Any],
    base_body: bytes,
    unique: Counter[tuple[int, int]],
) -> list[dict[str, Any]]:
    root = campaign_root / "h1_profiles"
    fixed = independent_root_units(compact_manifest, campaign_root, 1)
    records = []
    for index, entry in enumerate(manifest["entries"]):
        if entry.get("case_index") != index:
            fail(f"h1 entry {index}: case order mismatch")
        counts = entry["type_counts"]
        verify_profile_counts(counts, entry["case_id"])
        if counts["n3"] != 1:
            fail(f"{entry['case_id']}: h1 profile does not have n3=1")
        top = kmt.Top(BASE_VARIABLES)
        extension_parts = [fixed]
        sections = []
        expected_section_counts = {"fixed_type3_family": 20}
        for kind in range(4):
            name = f"exact_type{kind}"
            raw, record = encode_section(
                kmt, top, kind, counts[f"n{kind}"], name, unique
            )
            extension_parts.append(raw)
            sections.append(record)
            expected_section_counts[name] = record["clauses"]
        witness = entry["canonical_variable"]
        if BLOCK_INDEX[tuple(entry["canonical_block"])] + 1 != witness:
            fail(f"{entry['case_id']}: canonical block-variable mismatch")
        extension_parts.append(clause_raw((witness,)))
        expected_section_counts["symmetry_unit"] = 1
        if expected_section_counts != entry["section_clause_counts"]:
            fail(f"{entry['case_id']}: section clause-count mismatch")
        extension = b"".join(extension_parts)
        audit_case_file(
            root,
            entry,
            base_body,
            extension,
            top.value,
            sum(expected_section_counts.values()),
            entry["cnf"] == REQUIRED_RETAINED_CNFS["h1_profiles"],
        )
        records.append(
            {
                "case_index": index,
                "case_id": entry["case_id"],
                "a": entry["a"],
                "subcase": entry["subcase"],
                "type_counts": counts,
                "sections": sections,
                "final_top_id": top.value,
                "extension_bytes": len(extension),
                "extension_sha256": sha(extension),
                "cnf_sha256": entry["cnf_sha256"],
            }
        )
    return records


def check_case_tree(
    family_root: Path,
    manifest: dict[str, Any],
    label: str,
    required_retained: str,
) -> None:
    expected = {entry["cnf"] for entry in manifest["entries"]}
    actual = set()
    case_root = family_root / "cases"
    if case_root.is_symlink() or not case_root.is_dir():
        fail(f"{label}: cases directory missing or symlinked")
    for path in case_root.rglob("*"):
        if path.is_symlink():
            fail(f"{label}: symlink under cases tree")
        if path.is_file():
            actual.add(str(path.relative_to(family_root)))
    if not actual <= expected:
        fail(
            f"{label}: cases tree has unexpected files: "
            f"{sorted(actual - expected)[:5]}"
        )
    if required_retained not in actual:
        fail(f"{label}: designated retained CNF is missing")


def require_real_family(campaign_root: Path, name: str) -> Path:
    family = campaign_root / name
    if family.is_symlink() or not family.is_dir():
        fail(f"{family}: real non-symlink family directory required")
    try:
        family.resolve().relative_to(campaign_root.resolve())
    except ValueError:
        fail(f"{family}: family directory escapes campaign root")
    cursor = family
    while cursor != campaign_root:
        if cursor.is_symlink():
            fail(f"{family}: symlinked path component rejected")
        cursor = cursor.parent
    return family


def canonical_unique_specs(
    kmt: Any, occurrences: Counter[tuple[int, int]]
) -> list[dict[str, Any]]:
    records = []
    for (arity, bound), count in sorted(occurrences.items()):
        # Type arities uniquely identify their lexicographically ordered inputs.
        try:
            kind = [len(values) for values in TYPE_VARIABLES].index(arity)
        except ValueError:
            fail(f"unexpected equality arity {arity}")
        top = kmt.Top(BASE_VARIABLES)
        clauses, parts = kmt.encode_equals(
            TYPE_VARIABLES[kind], bound, top
        )
        raw = b"".join(clause_raw(clause) for clause in clauses)
        records.append(
            {
                "arity": arity,
                "bound": bound,
                "occurrences": count,
                "canonical_top_before": BASE_VARIABLES,
                "canonical_top_after_atleast": parts[
                    "top_after_atleast"
                ],
                "canonical_top_after_atmost": top.value,
                "auxiliary_variables": top.value - BASE_VARIABLES,
                "atleast_clauses": parts["atleast_clauses"],
                "atmost_clauses": parts["atmost_clauses"],
                "clauses": len(clauses),
                "bytes": len(raw),
                "sha256": sha(raw),
            }
        )
    return records


def audit(campaign_root: Path) -> dict[str, Any]:
    if campaign_root.is_symlink() or not campaign_root.is_dir():
        fail("campaign root must be a regular directory")
    kmt = load_transcription()
    frozen_audit = run_frozen_encoder_audit()
    compact_manifest = strict_json(campaign_root / "manifest.json")
    validate_hash(
        compact_manifest, "manifest_sha256", COMPACT_MANIFEST_SHA256
    )
    if (
        compact_manifest.get("case_count") != 2136
        or compact_manifest.get("model_version")
        != "c12-fixed-type3-support-compact-formal-v2"
    ):
        fail("compact parent manifest model/count mismatch")
    _, base_body = read_base(campaign_root)
    ordinary_root = require_real_family(
        campaign_root, "ordinary_profile_refinements"
    )
    h0_root = require_real_family(campaign_root, "h0_profiles")
    h1_root = require_real_family(campaign_root, "h1_profiles")

    ordinary, ordinary_variant = validate_manifest(
        ordinary_root / "manifest.json",
        "ordinary_profile_refinements",
        ORDINARY_MANIFEST_SHA256,
        "c12-compact-ordinary-profile-refinement-formal-v1",
        130,
    )
    h0, h0_variant = validate_manifest(
        h0_root / "manifest.json",
        "h0_profiles",
        H0_MANIFEST_SHA256,
        "c12-compact-h0-profile-formal-v1",
        11,
    )
    h1, h1_variant = validate_manifest(
        h1_root / "manifest.json",
        "h1_profiles",
        H1_MANIFEST_SHA256,
        "c12-compact-h1-profile-formal-v1",
        14,
    )
    for manifest in (ordinary, h0, h1):
        base = manifest.get("base", {})
        if (
            base.get("sha256") != BASE_SHA256
            or base.get("body_sha256") != BASE_BODY_SHA256
        ):
            fail("profile manifest base linkage mismatch")
    if ordinary.get("parent_campaign", {}).get("manifest_sha256") != (
        COMPACT_MANIFEST_SHA256
    ):
        fail("ordinary parent campaign linkage mismatch")

    partition_exhaustion = {
        "ordinary": verify_ordinary_partition(
            campaign_root, compact_manifest, ordinary
        ),
        "h0": verify_h0_partition(
            campaign_root, compact_manifest, h0
        ),
        "h1": verify_h1_partition(
            campaign_root, compact_manifest, h1
        ),
    }

    occurrences: Counter[tuple[int, int]] = Counter()
    ordinary_records = audit_ordinary(
        kmt,
        campaign_root,
        compact_manifest,
        ordinary,
        base_body,
        occurrences,
    )
    h0_records = audit_h0(
        kmt,
        campaign_root,
        compact_manifest,
        h0,
        base_body,
        occurrences,
    )
    h1_records = audit_h1(
        kmt,
        campaign_root,
        compact_manifest,
        h1,
        base_body,
        occurrences,
    )
    check_case_tree(
        ordinary_root,
        ordinary,
        "ordinary",
        REQUIRED_RETAINED_CNFS["ordinary_profile_refinements"],
    )
    check_case_tree(
        h0_root,
        h0,
        "h0",
        REQUIRED_RETAINED_CNFS["h0_profiles"],
    )
    check_case_tree(
        h1_root,
        h1,
        "h1",
        REQUIRED_RETAINED_CNFS["h1_profiles"],
    )

    section_count = sum(
        len(record["sections"])
        for record in ordinary_records + h0_records + h1_records
    )
    if (
        len(ordinary_records) != 130
        or len(h0_records) != 11
        or len(h1_records) != 14
        or section_count != 479
        or sum(occurrences.values()) != 479
    ):
        fail("aggregate leaf/section coverage mismatch")
    unique_specs = canonical_unique_specs(kmt, occurrences)
    report: dict[str, Any] = {
        "result": "COMPACT LEAF EXTENSION AUDIT PASSED",
        "audit_model": "c12-compact-leaf-kmtotalizer-reconstruction-v1",
        "stdlib_only": True,
        "python_sat_imported": False,
        "encoder": frozen_audit,
        "input_manifest_variants": {
            "ordinary_profile_refinements": ordinary_variant,
            "h0_profiles": h0_variant,
            "h1_profiles": h1_variant,
        },
        "partition_exhaustion": partition_exhaustion,
        "campaign": {
            "compact_manifest_sha256": COMPACT_MANIFEST_SHA256,
            "ordinary_manifest_sha256": ORDINARY_MANIFEST_SHA256,
            "h0_manifest_sha256": H0_MANIFEST_SHA256,
            "h1_manifest_sha256": H1_MANIFEST_SHA256,
            "base_sha256": BASE_SHA256,
            "base_body_sha256": BASE_BODY_SHA256,
        },
        "coverage": {
            "ordinary_leaves": len(ordinary_records),
            "h0_leaves": len(h0_records),
            "h1_leaves": len(h1_records),
            "total_leaves": (
                len(ordinary_records) + len(h0_records) + len(h1_records)
            ),
            "equals_sections": section_count,
            "unique_arity_bound_pairs": len(unique_specs),
            "extensions_byte_exactly_reconstructed": 155,
            "full_cnfs_reconstructed_with_manifest_size_and_hash_match": 155,
            "available_full_cnf_files_compared_byte_for_byte": True,
            "required_retained_full_cnf_files_compared_byte_for_byte": 3,
            "final_top_ids_checked": 155,
            "case_trees_have_no_unexpected_files": True,
        },
        "type_variable_arities": [len(values) for values in TYPE_VARIABLES],
        "unique_equals_specifications": unique_specs,
        "families": {
            "ordinary": ordinary_records,
            "h0": h0_records,
            "h1": h1_records,
        },
    }
    report["audit_sha256"] = sha(canonical(report))
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign-root", type=Path, required=True)
    parser.add_argument("--report", type=Path, default=REPORT_PATH)
    arguments = parser.parse_args()
    try:
        report = audit(arguments.campaign_root)
        output = arguments.report.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_suffix(output.suffix + ".tmp")
        temporary.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, output)
    except (
        AuditError,
        OSError,
        KeyError,
        TypeError,
        ValueError,
        subprocess.SubprocessError,
    ) as error:
        print(f"COMPACT LEAF EXTENSION AUDIT FAILED: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "result": report["result"],
                "audit_sha256": report["audit_sha256"],
                "coverage": report["coverage"],
                "unique_equals_specifications": report[
                    "unique_equals_specifications"
                ],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
