#!/usr/bin/env python3
"""Build the path-independent publication certificate from audited inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Sequence


class BuildError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise BuildError(message)


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
                fail(f"{path}: duplicate JSON key {key!r}")
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
        fail(f"{path}: top-level object required")
    return value


def validate_hash(payload: dict[str, Any], key: str) -> str:
    claimed = payload.get(key)
    actual = sha(
        canonical({name: value for name, value in payload.items() if name != key})
    )
    if not isinstance(claimed, str) or claimed != actual:
        fail(f"{key}: source self-hash mismatch")
    return claimed


def portable_artifact(record: dict[str, Any]) -> dict[str, Any]:
    path = record.get("path")
    if (
        not isinstance(path, str)
        or Path(path).is_absolute()
        or any(part in ("", ".", "..") for part in Path(path).parts)
    ):
        fail(f"unsafe source artifact path: {path!r}")
    return {
        "path": path,
        "bytes": record["bytes"],
        "sha256": record["sha256"],
    }


def portable_receipt(
    record: dict[str, Any], formal_root: Path
) -> dict[str, Any]:
    path_value = record.get("path")
    path_part = Path(path_value) if isinstance(path_value, str) else Path()
    if (
        not isinstance(path_value, str)
        or path_part.is_absolute()
        or not path_part.parts
        or any(part in ("", ".", "..") for part in path_part.parts)
    ):
        fail(f"unsafe source receipt path: {path_value!r}")
    path = formal_root / path_part
    root = formal_root.resolve()
    resolved = path.resolve()
    if os.path.commonpath((str(root), str(resolved))) != str(root):
        fail("source receipt escapes formal root")
    if path.is_symlink() or not path.is_file():
        fail(f"source receipt missing: {path_value}")
    if file_sha(path) != record["file_sha256"]:
        fail(f"source receipt hash mismatch: {path_value}")
    return {
        "path": path_value,
        "bytes": path.stat().st_size,
        "file_sha256": record["file_sha256"],
        "logical_sha256": record["result_sha256"],
    }


def build(source: Path, audit_path: Path) -> dict[str, Any]:
    certificate = strict_json(source)
    audit = strict_json(audit_path)
    certificate_hash = validate_hash(certificate, "certificate_sha256")
    audit_hash = validate_hash(audit, "audit_sha256")
    if (
        audit.get("result") != "H2 AGGREGATE CERTIFICATE AUDIT PASSED"
        or audit.get("certificate_sha256") != certificate_hash
        or certificate.get("scope", {}).get("top_level_root_fraction") != "1/2159"
        or certificate.get("coverage", {}).get("missing_profiles") != []
        or certificate.get("coverage", {}).get("verified_unsat_leaf_count") != 12
    ):
        fail("source certificate/audit linkage or scope mismatch")

    formal_root = source.parent.parent
    profiles = []
    for leaf in certificate["leaves"]:
        index = leaf["profile_index"]
        if index not in range(12):
            fail("invalid profile index")
        profiles.append(
            {
                "profile_index": index,
                "type_counts": leaf["type_counts"],
                "route": leaf["source"],
                "case_id": leaf["case_id"],
                "receipt": portable_receipt(leaf["receipt"], formal_root),
                "case": portable_artifact(leaf["case"]),
                "binary_drat": portable_artifact(leaf["proof"]),
                "lrat": portable_artifact(leaf["lrat"]),
                "verification_log": portable_artifact(leaf["log"]),
            }
        )
    profiles.sort(key=lambda item: item["profile_index"])
    if [item["profile_index"] for item in profiles] != list(range(12)):
        fail("profile coverage is not exact")

    totals = {
        artifact: sum(item[artifact]["bytes"] for item in profiles)
        for artifact in ("case", "binary_drat", "lrat", "verification_log")
    }
    portable: dict[str, Any] = {
        "model_version": "c1264-functional-h2-portable-validation-v1",
        "status": (
            "nonessential independent validation; the compact exhaustive "
            "certificate is the theorem-critical corpus"
        ),
        "scope": certificate["scope"],
        "coverage": certificate["coverage"],
        "source_aggregate": {
            "logical_certificate_sha256": certificate_hash,
            "certificate_file_sha256": file_sha(source),
            "logical_audit_sha256": audit_hash,
            "audit_file_sha256": file_sha(audit_path),
            "audit_result": audit["result"],
            "profiles_reconstructed": audit["profiles_reconstructed"],
            "virtual_cases_byte_exactly_reconstructed": audit[
                "virtual_cases_byte_exactly_reconstructed"
            ],
            "drat_artifacts_rehashed": audit["drat_artifacts_rehashed"],
            "lrat_artifacts_rehashed": audit["lrat_artifacts_rehashed"],
            "dual_checker_markers_verified": audit[
                "dual_checker_markers_verified"
            ],
            "q_fallback_invoked": audit["q_fallback_invoked"],
        },
        "logical_manifest_chain": [
            {
                "label": item["label"],
                "logical_sha256": item["sha256"],
                "file_sha256": item["file_sha256"],
            }
            for item in certificate["manifests"]
        ],
        "toolchain": certificate["toolchain"],
        "pinned_auditors": audit["pinned_auditors"],
        "release_asset": {
            "bundle_name": "functional_h2_validation_artifacts_v1.tar.zst",
            "bundle_sha256": None,
            "bundle_bytes": None,
            "content_paths_are_relative_to_extracted_bundle_root": True,
            "git_policy": "raw CNF/DRAT/LRAT artifacts are not committed",
            "artifact_totals": totals,
        },
        "profiles": profiles,
    }
    portable["certificate_sha256"] = sha(canonical(portable))
    return portable


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-certificate", type=Path, required=True)
    parser.add_argument("--source-audit", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).parent)
    arguments = parser.parse_args()
    portable = build(
        arguments.source_certificate.resolve(), arguments.source_audit.resolve()
    )
    output = arguments.output_dir.resolve() / "certificate.json"
    temporary = output.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(portable, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(temporary, output)
    print(f"PORTABLE H2 CERTIFICATE BUILT {portable['certificate_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
