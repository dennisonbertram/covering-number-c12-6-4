#!/usr/bin/env python3
"""One-command fail-closed audit of the global proof receipts.

The default mode requires the final compact formal partition (model v3) and
authenticates its linkage to the stdlib-only leaf-extension reconstruction.
Use --leaf-only while the large LRAT/formal package is still being assembled.
Use --verify-lrats after restoring the release assets to invoke the complete
portable LRAT verifier as well.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence


HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parent.parent
SKELETON = HERE / "compact_campaign"
LEAF_ROOT = HERE.parent / "compact-leaf-extension-audit"
COMPACT_ROOT = HERE.parent / "compact-crosscheck"
LEAF_SCRIPT_SHA256 = (
    "0d05e7b6d60cdeeb34cb5b2cd8f727e8858d9319945d7f70816566049833b24c"
)
LEAF_COMPONENT_SUMS_SHA256 = (
    "8ab2826ec3e250aeb9c62b403b5f8282ecb19adb691b93738a62c920956d0a03"
)
SKELETON_SUMS_SHA256 = (
    "4e9303638785b2005a015b362ef6341c19c12cd8dec4a56db7261fb72ea8d7a0"
)
LEAF_REPORT_FILE_SHA256 = (
    "961b86ced63ec47ce2e9b65c7d36ceaaa97055718a576b727d14df3796f065ba"
)
LEAF_AUDIT_SHA256 = (
    "3bd5008b2a345296385e7abc1356fc5bbb83a037305b93a7a966e7e8467370e5"
)
FORMAL_MODEL = "c12-fixed-support-formal-partition-v3"
EXPECTED_CERTIFICATES = 2_282
EXPECTED_COVERAGE = {
    "ordinary_leaves": 130,
    "h0_leaves": 11,
    "h1_leaves": 14,
    "total_leaves": 155,
    "equals_sections": 479,
    "unique_arity_bound_pairs": 58,
    "extensions_byte_exactly_reconstructed": 155,
    "full_cnfs_reconstructed_with_manifest_size_and_hash_match": 155,
    "available_full_cnf_files_compared_byte_for_byte": True,
    "required_retained_full_cnf_files_compared_byte_for_byte": 3,
    "final_top_ids_checked": 155,
    "case_trees_have_no_unexpected_files": True,
}
EXPECTED_MANIFEST_VARIANTS = {
    "ordinary_profile_refinements": {
        "kind": "portable_provenance_bound",
        "manifest_sha256": (
            "d9ebde00298e19140eb9b97e09cf2eba94732397ceffdd071c1c71d603e818ef"
        ),
        "source_manifest_sha256": (
            "f5066fcf1b978b5e967cf921d0d3dbeb7ad97c4f10d707cbc06cdb89bd179c0e"
        ),
    },
    "h0_profiles": {
        "kind": "portable_provenance_bound",
        "manifest_sha256": (
            "b308bffee53b5cae60f34f522b60f02a3b26ebaeac2346a17ee48cfe2ed47775"
        ),
        "source_manifest_sha256": (
            "fad8acff6636457a1227f1c99ba94ba50e341084bad8bc7f74426bba779fa1e9"
        ),
    },
    "h1_profiles": {
        "kind": "portable_provenance_bound",
        "manifest_sha256": (
            "d09ec1f0ad3be72c5843d9955de5fdcd8bbec2f30aa4cc53ea6d85a22a827d27"
        ),
        "source_manifest_sha256": (
            "58a262664267ba87cf8c7c37ec7e7739c094beb3a7409189c7268dff4f09c3b8"
        ),
    },
}
EXPECTED_PARTITION_EXHAUSTION = {
    "ordinary": {
        "parent_orbits": 7,
        "feasible_profiles": 86,
        "stabilizer_witness_orbits": 130,
        "children": 130,
        "unique_case_ids": 130,
        "unique_cnf_paths": 130,
        "unique_cnf_sha256": 130,
    },
    "h0": {
        "linked_parent_index": 0,
        "linked_parent_case_id": "case_0000_h00_m00000",
        "linked_parent_root_sha256": (
            "2d07d3a8760f3b906ae5f5f8d564e0a043ab19b6928cd7d91e304888276dbf86"
        ),
        "feasible_profiles": 11,
        "matching_type_orbits": 2,
        "roots": 11,
        "unique_profiles": 11,
        "unique_case_ids": 11,
        "unique_cnf_sha256": 11,
    },
    "h1": {
        "linked_parent_index": 1,
        "linked_parent_case_id": "case_0001_h01_m00001",
        "linked_parent_root_sha256": (
            "42dd3edd6adb8208602f4dbe6f0fa5e9c80c3b10f494760dba077b6a6af7cf0c"
        ),
        "feasible_profiles": 11,
        "type0_stabilizer_orbits": 1,
        "type1_stabilizer_orbits": 4,
        "roots": 14,
        "unique_case_ids": 14,
        "unique_cnf_sha256": 14,
    },
}
EXPECTED_LEAF_CNF_INDEX = {
    "record_count": 155,
    "sha256": (
        "5b7c46262436400a637e7fa775860a5bd61687df19b36e98e688413bedf8c612"
    ),
    "by_suite": {
        "ordinary_profiles": 130,
        "h0": 11,
        "h1": 14,
    },
}


class ReceiptError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise ReceiptError(message)


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

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique,
            parse_constant=lambda token: fail(
                f"{path}: invalid JSON constant {token}"
            ),
        )
    except ReceiptError:
        raise
    except Exception as error:
        fail(f"{path}: invalid JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{path}: top-level object required")
    return value


def validate_self_hash(
    value: dict[str, Any], key: str, location: str
) -> None:
    core = {name: item for name, item in value.items() if name != key}
    if value.get(key) != sha(canonical(core)):
        fail(f"{location}: {key} mismatch")


def safe_relative(root: Path, relative: str) -> Path:
    if not isinstance(relative, str):
        fail("checksum path must be a string")
    lexical = Path(relative)
    if (
        lexical.is_absolute()
        or not lexical.parts
        or any(part in ("", ".", "..") for part in lexical.parts)
    ):
        fail(f"unsafe checksum path {relative!r}")
    candidate = root / lexical
    try:
        candidate.resolve().relative_to(root.resolve())
    except ValueError:
        fail(f"checksum path escapes component: {relative!r}")
    cursor = candidate
    while cursor != root:
        if cursor.is_symlink():
            fail(f"checksum path contains symlink: {relative!r}")
        cursor = cursor.parent
    return candidate


def audit_checksum_index(
    root: Path, expected_index_sha: str, expected_entries: int | None = None
) -> int:
    index = root / "SHA256SUMS"
    if file_sha(index) != expected_index_sha:
        fail(f"{index}: checksum-index SHA-256 mismatch")
    expected_paths = set()
    for line_number, line in enumerate(
        index.read_text(encoding="utf-8").splitlines(), start=1
    ):
        fields = line.split("  ", 1)
        if (
            len(fields) != 2
            or len(fields[0]) != 64
            or any(character not in "0123456789abcdef" for character in fields[0])
        ):
            fail(f"{index}:{line_number}: malformed checksum row")
        digest, relative = fields
        if relative in expected_paths:
            fail(f"{index}: duplicate path {relative!r}")
        path = safe_relative(root, relative)
        if file_sha(path) != digest:
            fail(f"{path}: checksum mismatch")
        expected_paths.add(relative)
    actual_paths = {
        str(path.relative_to(root))
        for path in root.rglob("*")
        if path.is_file() and path != index
    }
    if actual_paths != expected_paths:
        fail(f"{index}: checksum path set differs from component files")
    if expected_entries is not None and len(expected_paths) != expected_entries:
        fail(
            f"{index}: expected {expected_entries} entries, "
            f"found {len(expected_paths)}"
        )
    return len(expected_paths)


def audit_leaf_extension_reconstruction() -> dict[str, Any]:
    leaf_script = LEAF_ROOT / "audit_leaf_extensions.py"
    if file_sha(leaf_script) != LEAF_SCRIPT_SHA256:
        fail(f"{leaf_script}: frozen source SHA-256 mismatch")
    leaf_component_files = audit_checksum_index(
        LEAF_ROOT, LEAF_COMPONENT_SUMS_SHA256, 3
    )
    skeleton_files = audit_checksum_index(
        SKELETON, SKELETON_SUMS_SHA256, 2_150
    )
    published_report_path = LEAF_ROOT / "results" / "AUDIT_REPORT.json"
    if file_sha(published_report_path) != LEAF_REPORT_FILE_SHA256:
        fail(f"{published_report_path}: frozen report-file mismatch")
    published_report = strict_json(published_report_path)
    published_core = {
        name: value
        for name, value in published_report.items()
        if name != "audit_sha256"
    }
    if (
        published_report.get("audit_sha256") != LEAF_AUDIT_SHA256
        or sha(canonical(published_core)) != LEAF_AUDIT_SHA256
    ):
        fail("published leaf report logical self-hash mismatch")

    with tempfile.TemporaryDirectory(
        prefix="c12-global-receipt-audit-"
    ) as temporary:
        fresh_report_path = Path(temporary) / "leaf-report.json"
        command = [
            sys.executable,
            "-S",
            str(leaf_script.relative_to(REPOSITORY)),
            "--campaign-root",
            str(SKELETON.relative_to(REPOSITORY)),
            "--report",
            str(fresh_report_path),
        ]
        completed = subprocess.run(
            command,
            cwd=REPOSITORY,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            fail(
                "fresh leaf-extension audit failed: "
                f"{completed.stderr or completed.stdout}"
            )
        fresh_report = strict_json(fresh_report_path)
    if canonical(fresh_report) != canonical(published_report):
        fail("fresh leaf report differs from frozen published report")
    if (
        fresh_report.get("result")
        != "COMPACT LEAF EXTENSION AUDIT PASSED"
        or fresh_report.get("audit_model")
        != "c12-compact-leaf-kmtotalizer-reconstruction-v1"
        or fresh_report.get("stdlib_only") is not True
        or fresh_report.get("python_sat_imported") is not False
        or fresh_report.get("coverage") != EXPECTED_COVERAGE
        or fresh_report.get("input_manifest_variants")
        != EXPECTED_MANIFEST_VARIANTS
        or fresh_report.get("partition_exhaustion")
        != EXPECTED_PARTITION_EXHAUSTION
        or fresh_report.get("audit_sha256") != LEAF_AUDIT_SHA256
    ):
        fail("fresh leaf report result/model/coverage mismatch")
    leaf_cnf_records = []
    for suite, family in (
        ("ordinary_profiles", "ordinary"),
        ("h0", "h0"),
        ("h1", "h1"),
    ):
        for record in fresh_report["families"][family]:
            leaf_cnf_records.append(
                {
                    "suite": suite,
                    "source_index": record["case_index"],
                    "case_id": record["case_id"],
                    "cnf_sha256": record["cnf_sha256"],
                }
            )
    leaf_cnf_index = {
        "record_count": len(leaf_cnf_records),
        "sha256": sha(canonical(leaf_cnf_records)),
        "by_suite": {
            suite: sum(
                record["suite"] == suite
                for record in leaf_cnf_records
            )
            for suite in ("ordinary_profiles", "h0", "h1")
        },
    }
    if leaf_cnf_index != EXPECTED_LEAF_CNF_INDEX:
        fail("fresh reconstructed leaf-CNF index mismatch")
    return {
        "logical_audit_sha256": LEAF_AUDIT_SHA256,
        "leaf_source_sha256": LEAF_SCRIPT_SHA256,
        "leaf_component_files": leaf_component_files,
        "portable_skeleton_files": skeleton_files,
        "coverage": fresh_report["coverage"],
        "input_manifest_variants": fresh_report[
            "input_manifest_variants"
        ],
        "partition_exhaustion": fresh_report[
            "partition_exhaustion"
        ],
        "leaf_cnf_index": leaf_cnf_index,
    }


def audit_formal_linkage() -> dict[str, Any]:
    path = COMPACT_ROOT / "formal_partition.json"
    formal = strict_json(path)
    validate_self_hash(formal, "aggregate_sha256", str(path))
    core = {
        name: value
        for name, value in formal.items()
        if name not in ("core_sha256", "aggregate_sha256")
    }
    if formal.get("core_sha256") != sha(canonical(core)):
        fail(f"{path}: core_sha256 mismatch")
    if (
        formal.get("model_version") != FORMAL_MODEL
        or formal.get("complete") is not True
        or len(formal.get("certificate_records", []))
        != EXPECTED_CERTIFICATES
    ):
        fail(f"{path}: model/completeness mismatch")
    component = formal.get("component_audits", {}).get("leaf_extensions", {})
    artifacts = component.get("artifacts", {})
    if (
        component.get("result")
        != "COMPACT LEAF EXTENSION LINK AUDIT PASSED"
        or component.get("audit_sha256") != LEAF_AUDIT_SHA256
        or component.get("coverage") != EXPECTED_COVERAGE
        or component.get("input_manifest_variants")
        != EXPECTED_MANIFEST_VARIANTS
        or component.get("partition_exhaustion")
        != EXPECTED_PARTITION_EXHAUSTION
        or component.get("leaf_cnf_index")
        != EXPECTED_LEAF_CNF_INDEX
        or component.get("stdlib_only") is not True
        or component.get("python_sat_imported") is not False
        or artifacts.get("leaf_script", {}).get("sha256")
        != LEAF_SCRIPT_SHA256
    ):
        fail("formal partition does not bind the frozen leaf audit")
    tool_metadata = formal.get("audit_tools", {}).get(
        "audit_leaf_extension_link.py"
    )
    tool = COMPACT_ROOT / "audit_leaf_extension_link.py"
    if (
        not isinstance(tool_metadata, dict)
        or tool_metadata.get("bytes") != tool.stat().st_size
        or tool_metadata.get("sha256") != file_sha(tool)
    ):
        fail("formal partition leaf-link tool identity mismatch")
    return {
        "model_version": FORMAL_MODEL,
        "aggregate_sha256": formal["aggregate_sha256"],
        "certificate_records": EXPECTED_CERTIFICATES,
    }


def run_full_lrat_verifier(
    zstd: str, cake_lpr: Path | None
) -> dict[str, Any]:
    verifier = COMPACT_ROOT / "verify_public_package.py"
    command = [
        sys.executable,
        str(verifier),
        "--root",
        str(COMPACT_ROOT),
        "--zstd",
        zstd,
    ]
    if cake_lpr is not None:
        command.extend(("--cake-lpr", str(cake_lpr)))
    completed = subprocess.run(
        command,
        cwd=REPOSITORY,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        fail(
            "portable LRAT verifier failed: "
            f"{completed.stderr or completed.stdout}"
        )
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        fail(f"portable LRAT verifier emitted invalid JSON: {error}")
    if value.get("result") != "PUBLIC PACKAGE VERIFICATION PASSED":
        fail("portable LRAT verifier result marker mismatch")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--leaf-only",
        action="store_true",
        help="audit the stdlib leaf reconstruction before formal assembly",
    )
    parser.add_argument(
        "--verify-lrats",
        action="store_true",
        help="also stream-hash all restored LRATs with the public verifier",
    )
    parser.add_argument("--zstd", default="zstd")
    parser.add_argument("--cake-lpr", type=Path)
    arguments = parser.parse_args()
    if arguments.leaf_only and arguments.verify_lrats:
        parser.error("--leaf-only and --verify-lrats are incompatible")
    try:
        leaf = audit_leaf_extension_reconstruction()
        formal = None if arguments.leaf_only else audit_formal_linkage()
        lrat = (
            run_full_lrat_verifier(arguments.zstd, arguments.cake_lpr)
            if arguments.verify_lrats
            else None
        )
    except (
        ReceiptError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
    ) as error:
        print(f"GLOBAL RECEIPT VERIFICATION FAILED: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "result": "GLOBAL RECEIPT VERIFICATION PASSED",
                "leaf_extension_reconstruction": leaf,
                "formal_partition": formal,
                "lrat_streams_verified_now": lrat is not None,
                "lrat_verification": lrat,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
