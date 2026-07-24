#!/usr/bin/env python3
"""Fail-closed offline replay of the frozen compact-encoder audit package."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any, Sequence


if not __debug__:
    raise RuntimeError(
        "this proof verifier refuses Python -O because checks must remain enabled"
    )


HERE = Path(__file__).resolve().parent
SOURCE_SNAPSHOT = HERE / "source_snapshot"
RESULTS = HERE / "results"

EXPECTED = {
    "auditor_source_integrated": (
        "cd22aedc14c9ea87ac1c4aba3a27d3cbc663f8159d12e4b609822229ebeb749d"
    ),
    "boundaries": (
        "00a99825b80170c154231233705f3e2a67d54dc119ab11300527291f25abd239"
    ),
    "boundaries_canonical": (
        "e8faba67dca00bd9fd889996c93667ad2742409bb4619d3c9d4352ce365471d8"
    ),
    "base": (
        "637d9326388f77f933f3d066cd762d8c0ac4b2df0d2260d688e031d55959e7f0"
    ),
    "base_body": (
        "6a1a2eb2843a4ddcf9138c5a85aaeccd2950b3e099e0ab8a26ce9fc815ab0cc5"
    ),
    "driver": (
        "cfe317d0d0e1dc045173e199c480411ebef0902270074797d51fd3eaa848402c"
    ),
    "original_report": (
        "f24ae7bd8028a100625373f0f7a5f6ab39b65d5026555ae1b8917c72a833701a"
    ),
    "small_vectors": (
        "4593235969317bb0f45f657a38cea53c5753cffcebb713adddee3d3cde36e7e4"
    ),
    "source_pin": (
        "69ed12e0a81a197a7068de88fe466e63544fd489f02d83385d2a917b26919c79"
    ),
    "source_vectors": (
        "f3d5fa319a43347b79b471aa646d62a2ccd1569fdda4e84de4e228b35bb61eb7"
    ),
}


class VerificationFailure(RuntimeError):
    """A frozen artifact failed one of its release gates."""


def fail(message: str) -> None:
    raise VerificationFailure(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def file_sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        fail(f"expected a regular non-symlink file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def strict_json(path: Path) -> Any:
    def unique(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                fail(f"{path}: duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique,
            parse_constant=lambda value: fail(
                f"{path}: invalid JSON constant {value}"
            ),
        )
    except VerificationFailure:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"{path}: invalid JSON: {error}")


def load_auditor() -> ModuleType:
    path = HERE / "audit_kmtotalizer.py"
    require(
        file_sha256(path) == EXPECTED["auditor_source_integrated"],
        "integrated auditor source hash changed",
    )
    spec = importlib.util.spec_from_file_location(
        "c1264_compact_encoder_auditor", path
    )
    if spec is None or spec.loader is None:
        fail("could not construct an import specification for the auditor")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def audit_source_snapshot(auditor: ModuleType) -> None:
    require(
        file_sha256(HERE / "SOURCE_PIN.json") == EXPECTED["source_pin"],
        "SOURCE_PIN.json hash changed",
    )
    pin = strict_json(HERE / "SOURCE_PIN.json")
    require(
        pin["commit"]["sha1"] == auditor.SOURCE_COMMIT,
        "source commit differs between pin and auditor",
    )
    require(
        pin["version_at_commit"] == auditor.SOURCE_VERSION,
        "source version differs between pin and auditor",
    )

    for relative, specification in auditor.SOURCE_FILES.items():
        expected_bytes, expected_blob, expected_hash = specification
        path = SOURCE_SNAPSHOT / relative
        require(
            path.stat().st_size == expected_bytes,
            f"{relative}: source-snapshot byte count changed",
        )
        require(
            file_sha256(path) == expected_hash,
            f"{relative}: source-snapshot SHA-256 changed",
        )
        pin_row = pin["files"][relative]
        require(
            pin_row
            == {
                "bytes": expected_bytes,
                "git_blob_sha1": expected_blob,
                "sha256": expected_hash,
            },
            f"{relative}: SOURCE_PIN.json row changed",
        )


def audit_portable_report() -> None:
    report = strict_json(RESULTS / "AUDIT_REPORT.json")
    require(report["result"] == "PASS", "portable report is not PASS")
    require(
        report["original_run"]["original_report_sha256"]
        == EXPECTED["original_report"],
        "original report provenance hash changed",
    )
    require(
        report["production_comparison"]["full_sha256"] == EXPECTED["base"],
        "portable report production hash changed",
    )
    require(
        report["production_comparison"]["body_sha256"]
        == EXPECTED["base_body"],
        "portable report body hash changed",
    )
    require(
        report["small_semantics"]["clause_test_vector_sha256"]
        == EXPECTED["small_vectors"],
        "portable report small-vector hash changed",
    )
    require(
        report["official_source_comparison"]["vector_manifest_sha256"]
        == EXPECTED["source_vectors"],
        "portable report official-vector hash changed",
    )


def snapshot_git_reader(
    _repository: Path, arguments: Sequence[str]
) -> bytes:
    if list(arguments[:4]) == [
        "ls-tree",
        "-r",
        "--name-only",
        "7abb1d6fdafe1d75fe3e5cdfb48f7e07a8a76efd",
    ] and list(arguments[4:]) == ["cardenc"]:
        names = sorted(
            str(path.relative_to(SOURCE_SNAPSHOT))
            for path in (SOURCE_SNAPSHOT / "cardenc").glob("*.hh")
        )
        return ("\n".join(names) + "\n").encode()
    if len(arguments) == 2 and arguments[0] == "show":
        prefix = "7abb1d6fdafe1d75fe3e5cdfb48f7e07a8a76efd:"
        require(
            arguments[1].startswith(prefix),
            "source adapter requested an unpinned commit",
        )
        relative = arguments[1][len(prefix) :]
        path = SOURCE_SNAPSHOT / relative
        require(
            path.resolve().is_relative_to(SOURCE_SNAPSHOT.resolve()),
            "source adapter requested a path outside the snapshot",
        )
        if path.is_symlink() or not path.is_file():
            fail(f"source adapter requested missing snapshot file {relative}")
        return path.read_bytes()
    fail(f"unexpected source-snapshot operation: {list(arguments)!r}")


def main() -> int:
    try:
        auditor = load_auditor()
        audit_source_snapshot(auditor)
        audit_portable_report()

        require(
            file_sha256(HERE / "source_reference_driver.cc")
            == EXPECTED["driver"],
            "source-reference driver hash changed",
        )
        target = RESULTS / "reconstructed_global_base.cnf"
        boundaries = RESULTS / "production_boundaries.json"
        require(
            file_sha256(target) == EXPECTED["base"],
            "published reconstructed base hash changed",
        )
        require(
            file_sha256(boundaries) == EXPECTED["boundaries"],
            "published boundary-file hash changed",
        )

        with tempfile.TemporaryDirectory(
            prefix="c1264-compact-encoder-audit-"
        ) as temporary:
            output = Path(temporary)
            replica = output / "reconstructed_global_base.cnf"
            manifest, _sections = auditor.reconstruct_production(replica)
            require(
                manifest["full_sha256"] == EXPECTED["base"],
                "independent reconstruction hash changed",
            )
            require(
                manifest["body_sha256"] == EXPECTED["base_body"],
                "independent reconstruction body hash changed",
            )
            require(
                manifest["constraint_boundaries_sha256"]
                == EXPECTED["boundaries_canonical"],
                "canonical boundary hash changed",
            )
            auditor.audit_target(target, replica, manifest)

            semantics = auditor.exhaustive_small_semantics(7)
            require(
                semantics["existential_primary_assignments_checked"] == 5376,
                "small semantic assignment count changed",
            )
            require(
                semantics["clause_test_vector_sha256"]
                == EXPECTED["small_vectors"],
                "small semantic clause-vector hash changed",
            )

            expected_boundaries = (
                json.dumps(
                    manifest["constraint_boundaries"],
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            ).encode()
            require(
                expected_boundaries == boundaries.read_bytes(),
                "published boundaries differ from reconstruction",
            )

            auditor.git_output = snapshot_git_reader
            vectors = auditor.audit_official_source_vectors(
                SOURCE_SNAPSHOT,
                output / "official-source-check",
                HERE / "source_reference_driver.cc",
            )
            require(
                vectors["vectors_checked"] == 115,
                "official source-vector count changed",
            )
            require(
                vectors["clauses_compared"] == 123220,
                "official source clause-comparison count changed",
            )
            require(
                vectors["vector_manifest_sha256"]
                == EXPECTED["source_vectors"],
                "official source-vector manifest hash changed",
            )

        print("COMPACT ENCODER FROZEN AUDIT: PASS")
        print(f"production_sha256 {EXPECTED['base']}")
        print("small_truth_assignments 5376")
        print("official_source_vectors 115")
        print("official_source_clauses 123220")
        return 0
    except (
        VerificationFailure,
        auditor.AuditFailure if "auditor" in locals() else RuntimeError,
        OSError,
    ) as error:
        print(f"COMPACT ENCODER FROZEN AUDIT FAILED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
