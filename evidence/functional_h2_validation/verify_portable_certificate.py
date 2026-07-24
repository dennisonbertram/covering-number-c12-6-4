#!/usr/bin/env python3
"""Fail-closed verifier for the portable functional h=2 certificate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence


HERE = Path(__file__).resolve().parent
CERTIFICATE = HERE / "certificate.json"
EXPECTED_MODEL = "c1264-functional-h2-portable-validation-v1"
DRAT_TRIM_SHA256 = (
    "42a69f9a17bcd58001676abf02d58992bd0ede58410a467dda07a350fec498c9"
)
LRAT_CHECK_SHA256 = (
    "cef0a912384b790afe205a75309990e5bd63b38c309b2867ef36eb8a0c58fe4c"
)


class VerifyError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise VerifyError(message)


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha(path: Path) -> str:
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
                fail(f"{path}: duplicate key {key!r}")
            result[key] = value
        return result

    if path.is_symlink() or not path.is_file():
        fail(f"{path}: regular non-symlink JSON required")
    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=unique,
        parse_constant=lambda token: fail(f"invalid JSON constant {token}"),
    )
    if not isinstance(value, dict):
        fail(f"{path}: top-level JSON object required")
    return value


def expected_counts(index: int) -> dict[str, int]:
    return {"n0": index, "n1": 22 - 2 * index, "n2": 16 + index, "n3": 2}


def safe_artifact(root: Path, record: dict[str, Any], label: str) -> Path:
    relative = record.get("path")
    if not isinstance(relative, str):
        fail(f"{label}: path missing")
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
        fail(f"{label}: path escapes artifact root")
    cursor = candidate
    while cursor != root:
        if cursor.is_symlink():
            fail(f"{label}: symlink rejected")
        cursor = cursor.parent
    if not candidate.is_file():
        fail(f"{label}: artifact missing")
    if (
        candidate.stat().st_size != record.get("bytes")
        or file_sha(candidate) != record.get("sha256")
    ):
        fail(f"{label}: byte count or hash mismatch")
    return candidate


def checked_tool(path: Path, expected: str, label: str) -> Path:
    if path.is_symlink() or not path.is_file() or file_sha(path) != expected:
        fail(f"{label}: binary hash mismatch")
    return path


def run_checker(command: list[str], marker: str, label: str) -> None:
    completed = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if completed.returncode != 0 or marker not in completed.stdout:
        fail(
            f"{label}: replay failed rc={completed.returncode}: "
            f"{completed.stdout[-1000:]}"
        )


def verify(
    artifact_root: Path | None,
    lrat_check: Path | None,
    drat_trim: Path | None,
) -> dict[str, Any]:
    payload = strict_json(CERTIFICATE)
    claimed = payload.get("certificate_sha256")
    actual = sha(
        canonical(
            {
                key: value
                for key, value in payload.items()
                if key != "certificate_sha256"
            }
        )
    )
    if claimed != actual or payload.get("model_version") != EXPECTED_MODEL:
        fail("certificate self-hash/model mismatch")
    scope = payload.get("scope", {})
    coverage = payload.get("coverage", {})
    if (
        scope.get("top_level_root_fraction") != "1/2159"
        or scope.get("labeled_support_fraction") != "90/1048576"
        or scope.get("entire_h2_suite_covered") is not False
        or coverage.get("profile_indices") != list(range(12))
        or coverage.get("verified_unsat_leaf_count") != 12
        or coverage.get("missing_profiles") != []
        or coverage.get("collective_support_orbit_weight") != 90
        or coverage.get("weight_counted_exactly_once") is not True
        or payload.get("source_aggregate", {}).get("q_fallback_invoked") is not False
    ):
        fail("certificate scope/coverage mismatch")
    profiles = payload.get("profiles")
    if not isinstance(profiles, list) or len(profiles) != 12:
        fail("profile list mismatch")
    if [item.get("profile_index") for item in profiles] != list(range(12)):
        fail("profile indices are incomplete or out of order")
    if [item.get("type_counts") for item in profiles] != [
        expected_counts(index) for index in range(12)
    ]:
        fail("exact profile equations mismatch")
    if [item.get("route") for item in profiles] != [
        "A",
        *(["symmetry_AB_type0"] * 9),
        "A",
        "A",
    ]:
        fail("leaf route selection mismatch")

    rehashed = 0
    lrat_replayed = 0
    drat_replayed = 0
    if artifact_root is not None:
        root = artifact_root.resolve()
        if root.is_symlink() or not root.is_dir():
            fail("artifact root must be a regular directory")
        checked_lrat = (
            checked_tool(lrat_check.resolve(), LRAT_CHECK_SHA256, "lrat-check")
            if lrat_check is not None
            else None
        )
        checked_drat = (
            checked_tool(drat_trim.resolve(), DRAT_TRIM_SHA256, "drat-trim")
            if drat_trim is not None
            else None
        )
        for profile in profiles:
            index = profile["profile_index"]
            case = safe_artifact(root, profile["case"], f"profile {index} case")
            proof = safe_artifact(
                root, profile["binary_drat"], f"profile {index} DRAT"
            )
            lrat = safe_artifact(root, profile["lrat"], f"profile {index} LRAT")
            safe_artifact(
                root,
                profile["verification_log"],
                f"profile {index} verification log",
            )
            receipt_record = profile["receipt"]
            receipt_path = safe_artifact(
                root,
                {
                    "path": receipt_record["path"],
                    "bytes": receipt_record["bytes"],
                    "sha256": receipt_record["file_sha256"],
                },
                f"profile {index} receipt",
            )
            receipt = strict_json(receipt_path)
            receipt_hash = sha(
                canonical(
                    {
                        key: value
                        for key, value in receipt.items()
                        if key != "result_sha256"
                    }
                )
            )
            if receipt_hash != receipt_record["logical_sha256"]:
                fail(f"profile {index}: receipt logical hash mismatch")
            rehashed += 5
            if checked_lrat is not None:
                run_checker(
                    [str(checked_lrat), str(case), str(lrat)],
                    "c VERIFIED",
                    f"profile {index} LRAT",
                )
                lrat_replayed += 1
            if checked_drat is not None:
                run_checker(
                    [str(checked_drat), str(case), str(proof), "-i"],
                    "s VERIFIED",
                    f"profile {index} DRAT",
                )
                drat_replayed += 1
    elif lrat_check is not None or drat_trim is not None:
        fail("proof checker arguments require --artifact-root")

    return {
        "result": "PORTABLE FUNCTIONAL H2 CERTIFICATE VERIFIED",
        "certificate_sha256": claimed,
        "profiles": 12,
        "top_level_root_fraction": "1/2159",
        "support_orbit_weight": 90,
        "artifacts_rehashed": rehashed,
        "lrat_proofs_replayed": lrat_replayed,
        "drat_proofs_replayed": drat_replayed,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-root", type=Path)
    parser.add_argument("--lrat-check", type=Path)
    parser.add_argument("--drat-trim", type=Path)
    arguments = parser.parse_args()
    try:
        result = verify(
            arguments.artifact_root, arguments.lrat_check, arguments.drat_trim
        )
    except (VerifyError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"PORTABLE FUNCTIONAL H2 CERTIFICATE FAILED: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
