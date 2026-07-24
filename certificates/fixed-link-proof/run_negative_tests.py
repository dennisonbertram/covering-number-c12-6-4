#!/usr/bin/env python3
"""Negative tests for the fixed-link public verifier's fail-closed boundary."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from unittest import mock
from pathlib import Path
from typing import Any, Callable, Dict, List


HERE = Path(__file__).resolve().parent
VERIFIER = HERE / "verify_public_release.py"
ARCHIVE_BUILDER = HERE / "make_release_archives.py"


class NegativeTestError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise NegativeTestError(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        fail("could not load %s" % path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


V = load_module("fixed_link_verifier", VERIFIER)
A = load_module("fixed_link_archive_builder", ARCHIVE_BUILDER)


def must_reject(name: str, action: Callable[[], None]) -> str:
    try:
        action()
    except (
        V.VerificationError,
        A.ArchiveError,
        OSError,
        ValueError,
        tarfile.TarError,
    ):
        return name
    fail("%s: verifier accepted a forbidden mutation" % name)


def test_optimized_python() -> str:
    arguments = [
        sys.executable,
        "-O",
        str(VERIFIER),
        "--repo-root",
        str(HERE.parent.parent),
        "--release-assets",
        str(HERE / "release-assets.json"),
        "--drat-archive",
        "/nonexistent/drat.tar",
        "--lrat-archive",
        "/nonexistent/lrat.tar",
        "--lrat-check",
        "/nonexistent/lrat-check",
        "--cake-lpr",
        "/nonexistent/cake_lpr",
        "--zstd",
        "/nonexistent/zstd",
    ]
    checked = subprocess.run(
        arguments,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=30,
    )
    if (
        checked.returncode == 0
        or "refusing optimized Python (-O)" not in checked.stderr
    ):
        fail("optimized_python: optimized execution was not explicitly rejected")
    return "optimized_python"


def test_duplicate_json() -> str:
    with tempfile.TemporaryDirectory(prefix="c12-negative-json-") as temporary:
        path = Path(temporary) / "duplicate.json"
        path.write_text('{"x":1,"x":2}\n', encoding="utf-8")
        return must_reject("duplicate_json_key", lambda: V.strict_json(path))


def test_nonfinite_json() -> str:
    with tempfile.TemporaryDirectory(prefix="c12-negative-nan-") as temporary:
        path = Path(temporary) / "nan.json"
        path.write_text('{"x":NaN}\n', encoding="utf-8")
        return must_reject("nonfinite_json", lambda: V.strict_json(path))


def test_path_traversal() -> str:
    return must_reject(
        "path_traversal",
        lambda: V.safe_relative("../../escape", "negative path"),
    )


def test_absolute_path() -> str:
    return must_reject(
        "absolute_path",
        lambda: V.safe_relative("/tmp/escape", "negative path"),
    )


def test_symlink() -> str:
    with tempfile.TemporaryDirectory(prefix="c12-negative-symlink-") as temporary:
        root = Path(temporary)
        target = root / "target"
        target.write_text("x", encoding="utf-8")
        link = root / "link"
        link.symlink_to(target)
        return must_reject(
            "symlink_artifact",
            lambda: V.regular(link, "negative symlink", root),
        )


def test_caller_symlink_path() -> str:
    with tempfile.TemporaryDirectory(prefix="c12-negative-input-link-") as temporary:
        root = Path(temporary)
        target = root / "target"
        target.write_text("x", encoding="utf-8")
        link = root / "caller-input"
        link.symlink_to(target)
        return must_reject(
            "caller_symlink_path",
            lambda: V.checked_input_path(link, "negative caller input", "file"),
        )


def test_missing_case() -> str:
    with tempfile.TemporaryDirectory(prefix="c12-negative-missing-") as temporary:
        root = Path(temporary)
        (root / "link_orbit_000.json").write_text("{}\n", encoding="utf-8")
        return must_reject(
            "missing_case",
            lambda: V.exact_directory_files(
                root,
                ["link_orbit_000.json", "link_orbit_001.json"],
                "negative exact set",
            ),
        )


def test_extra_case() -> str:
    with tempfile.TemporaryDirectory(prefix="c12-negative-extra-") as temporary:
        root = Path(temporary)
        (root / "link_orbit_000.json").write_text("{}\n", encoding="utf-8")
        (root / "link_orbit_999.json").write_text("{}\n", encoding="utf-8")
        return must_reject(
            "extra_case",
            lambda: V.exact_directory_files(
                root,
                ["link_orbit_000.json"],
                "negative exact set",
            ),
        )


def test_self_hash() -> str:
    payload = {"status": "VERIFIED_UNSAT"}
    payload["receipt_sha256"] = sha(canonical(payload))
    payload["status"] = "SAT"
    return must_reject(
        "receipt_self_hash",
        lambda: V.verify_self_hash(
            payload, "receipt_sha256", None, "negative receipt"
        ),
    )


def test_component_inventory() -> str:
    with tempfile.TemporaryDirectory(prefix="c12-negative-index-") as temporary:
        root = Path(temporary)
        (root / "kept.txt").write_text("kept\n", encoding="utf-8")
        (root / "extra.txt").write_text("extra\n", encoding="utf-8")
        (root / "SHA256SUMS").write_text(
            "%s  ./kept.txt\n" % file_sha(root / "kept.txt"),
            encoding="utf-8",
        )
        return must_reject(
            "unindexed_file",
            lambda: V.verify_component_sums(root),
        )


def test_unbound_checker_binary() -> str:
    with tempfile.TemporaryDirectory(prefix="c12-negative-checker-") as temporary:
        fake = Path(temporary) / "fake-checker"
        fake.write_text("#!/bin/sh\necho c VERIFIED\n", encoding="utf-8")
        fake.chmod(0o755)
        return must_reject(
            "unbound_checker_binary",
            lambda: V.verify_replay_checker_identities(fake, fake),
        )


def test_unpinned_classification_component() -> str:
    with tempfile.TemporaryDirectory(
        prefix="c12-negative-classification-"
    ) as temporary:
        root = Path(temporary)
        verifier = root / "verify_frozen_classification.py"
        verifier.write_text(
            "print(%r)\n" % V.EXPECTED_CLASSIFICATION_PASS,
            encoding="utf-8",
        )
        verifier.chmod(0o755)
        (root / "SHA256SUMS").write_text(
            "%s  ./verify_frozen_classification.py\n" % file_sha(verifier),
            encoding="utf-8",
        )
        reps = root / "representatives.txt"
        reps.write_text("", encoding="utf-8")
        return must_reject(
            "unpinned_classification_component",
            lambda: V.run_classification_check(root, reps),
        )


def test_ambiguous_classification_marker() -> str:
    fake_result = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout="prefix PASS suffix\n",
        stderr="",
    )
    with (
        mock.patch.object(V, "verify_component_sums", return_value=None),
        mock.patch.object(V, "regular", return_value=None),
        mock.patch.object(V.subprocess, "run", return_value=fake_result),
    ):
        return must_reject(
            "ambiguous_classification_marker",
            lambda: V.run_classification_check(
                Path("/placeholder/classification"),
                Path("/placeholder/representatives"),
            ),
        )


def test_archive_builder_symlink_parent() -> str:
    with tempfile.TemporaryDirectory(
        prefix="c12-negative-archive-parent-"
    ) as temporary:
        root = Path(temporary)
        real = root / "real"
        package = real / "package"
        package.mkdir(parents=True)
        link = root / "linked-parent"
        link.symlink_to(real, target_is_directory=True)
        return must_reject(
            "archive_builder_symlink_parent",
            lambda: A.checked_directory(link / "package", "package"),
        )


def test_archive_builder_symlink_artifact_parent() -> str:
    with tempfile.TemporaryDirectory(
        prefix="c12-negative-archive-artifact-"
    ) as temporary:
        root = Path(temporary)
        package = root / "package"
        real_proofs = root / "real-proofs"
        package.mkdir()
        real_proofs.mkdir()
        source = real_proofs / "link_orbit_000.drat.zst"
        source.write_bytes(b"payload")
        (package / "proofs").symlink_to(
            real_proofs, target_is_directory=True
        )
        return must_reject(
            "archive_builder_symlink_artifact_parent",
            lambda: A.regular(
                package / "proofs" / source.name,
                package,
            ),
        )


def test_noncanonical_tar() -> str:
    with tempfile.TemporaryDirectory(prefix="c12-negative-tar-") as temporary:
        root = Path(temporary)
        archive_path = root / "bad.tar"
        with tarfile.open(archive_path, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            info = tarfile.TarInfo("proofs/link_orbit_000.drat.zst")
            info.type = tarfile.SYMTYPE
            info.linkname = "../../escape"
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            archive.addfile(info)
        record: Dict[str, Any] = {
            "bytes": archive_path.stat().st_size,
            "sha256": file_sha(archive_path),
            "members": [
                {
                    "path": "proofs/link_orbit_000.drat.zst",
                    "bytes": 0,
                }
            ],
        }
        return must_reject(
            "nonregular_tar_member",
            lambda: V.validate_tar_metadata(archive_path, record),
        )


def test_compressed_member_hash() -> str:
    with tempfile.TemporaryDirectory(prefix="c12-negative-member-") as temporary:
        root = Path(temporary)
        archive_path = root / "one.tar"
        payload = b"not the pinned compressed proof"
        source = root / "source"
        source.write_bytes(payload)
        with tarfile.open(archive_path, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            info = tarfile.TarInfo("proofs/link_orbit_000.drat.zst")
            info.size = len(payload)
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = 0
            with source.open("rb") as handle:
                archive.addfile(info, handle)
        record = {
            "bytes": archive_path.stat().st_size,
            "sha256": file_sha(archive_path),
            "members": [
                {
                    "path": "proofs/link_orbit_000.drat.zst",
                    "bytes": len(payload),
                    "sha256": "0" * 64,
                }
            ],
        }
        archive = V.validate_tar_metadata(archive_path, record)
        try:
            return must_reject(
                "compressed_member_hash",
                lambda: V.copy_member(
                    archive,
                    archive.getmembers()[0],
                    record["members"][0],
                    root / "copied.zst",
                ),
            )
        finally:
            archive.close()


def test_skip_mode_nonzero() -> str:
    arguments = [
        str(VERIFIER),
        "--repo-root",
        "/placeholder/repo",
        "--release-assets",
        "/placeholder/assets.json",
        "--drat-archive",
        "/placeholder/drat.tar",
        "--lrat-archive",
        "/placeholder/lrat.tar",
        "--lrat-check",
        "/placeholder/lrat-check",
        "--cake-lpr",
        "/placeholder/cake_lpr",
        "--zstd",
        "/placeholder/zstd",
        "--skip-classification-replay",
    ]
    old_argv = sys.argv
    sys.argv = arguments
    try:
        with (
            mock.patch.object(
                V, "checked_input_path", return_value=Path("/placeholder")
            ),
            mock.patch.object(
                V,
                "load_production",
                return_value=(
                    {"entries": [], "manifest_sha256": "x"},
                    b"",
                    Path("/reps"),
                ),
            ),
            mock.patch.object(
                V,
                "load_receipts",
                return_value=({"aggregate_sha256": "a"}, []),
            ),
            mock.patch.object(V, "load_release_assets", return_value={}),
            mock.patch.object(V, "replay_archives", return_value=None),
            mock.patch.object(V, "file_sha", return_value="0" * 64),
        ):
            returncode = V.main()
    finally:
        sys.argv = old_argv
    if returncode != 3:
        fail("skip_mode_nonzero: partial mode did not return exit code 3")
    return "skip_mode_nonzero"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if not __debug__:
        fail("negative tests themselves refuse optimized Python")
    tests = [
        test_optimized_python,
        test_duplicate_json,
        test_nonfinite_json,
        test_path_traversal,
        test_absolute_path,
        test_symlink,
        test_caller_symlink_path,
        test_missing_case,
        test_extra_case,
        test_self_hash,
        test_component_inventory,
        test_unbound_checker_binary,
        test_unpinned_classification_component,
        test_ambiguous_classification_marker,
        test_archive_builder_symlink_parent,
        test_archive_builder_symlink_artifact_parent,
        test_noncanonical_tar,
        test_compressed_member_hash,
        test_skip_mode_nonzero,
    ]
    passed: List[str] = []
    for test in tests:
        name = test()
        passed.append(name)
        print("PASS %s" % name)
    report = {
        "model_version": "c12-fixed-link-public-negative-tests-v1",
        "passed": len(passed),
        "failed": 0,
        "tests": passed,
        "verifier_sha256": file_sha(VERIFIER),
    }
    report["logical_sha256"] = sha(canonical(report))
    if args.report is not None:
        temporary = args.report.with_suffix(args.report.suffix + ".tmp")
        temporary.write_text(
            json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, args.report)
    print("PASS all-negative-tests logical=%s" % report["logical_sha256"])
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (NegativeTestError, OSError, ValueError) as error:
        print("ERROR: %s" % error, file=sys.stderr)
        raise SystemExit(2)
