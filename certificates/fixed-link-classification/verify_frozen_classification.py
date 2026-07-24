#!/usr/bin/env python3
"""Fail-closed portable replay of the fixed-link classification."""

from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import shlex
import subprocess
import sys
import tempfile


if not __debug__:
    raise RuntimeError(
        "this proof verifier refuses Python -O because checks must remain enabled"
    )


HERE = pathlib.Path(__file__).resolve().parent
BASE_CNF = (
    HERE.parent
    / "compact-encoder-audit"
    / "results"
    / "reconstructed_global_base.cnf"
)
EXPECTED = {
    "canonical_source": (
        "ed9cc2f731e6638121dc698ee00b9744f8affe70ffe92a22544c4816e75c304d"
    ),
    "audit_source": (
        "b52138327612bbbba1c51758cdc955a432a08615caf9b4a4360e8e089e51981e"
    ),
    "frozen_report": (
        "be0b413d611fe33a3514507ed73b7016cea8cac1ac941b372643c678ba46a017"
    ),
    "empty": (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ),
    "covers": (
        "52951ea29f8e249a739a6d4eef31d874e552f789cbe0f99d93722bd7437547d9"
    ),
    "representatives": (
        "369a844c4590d435fc24f82424a0775d51ce326d243aaf740d025c52c81d652b"
    ),
    "case_hashes": (
        "3352f4cfa1009d09fda4e7af6c5a06b4fd6821fd5437f7a707b357d8c31dc8be"
    ),
}


class VerificationFailure(RuntimeError):
    """A frozen classification artifact failed verification."""


def fail(message: str) -> None:
    raise VerificationFailure(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def file_sha256(path: pathlib.Path) -> str:
    if path.is_symlink() or not path.is_file():
        fail(f"expected a regular non-symlink file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_checked(
    command: list[str],
    *,
    stdout: int | None = subprocess.PIPE,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        check=False,
        stdout=stdout,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        fail(
            f"command failed ({completed.returncode}): {command!r}\n"
            f"{completed.stderr}"
        )
    return completed


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-representatives", type=pathlib.Path)
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    canonical_source = HERE / "canonical_enum.cpp"
    audit_source = HERE / "audit_classification.py"
    frozen_report = HERE / "results" / "AUDIT_REPORT.json"
    require(
        file_sha256(canonical_source) == EXPECTED["canonical_source"],
        "canonical enumerator source hash changed",
    )
    require(
        file_sha256(audit_source) == EXPECTED["audit_source"],
        "classification auditor source hash changed",
    )
    require(
        file_sha256(frozen_report) == EXPECTED["frozen_report"],
        "frozen audit report hash changed",
    )

    compiler = shlex.split(os.environ.get("CXX", "c++"))
    require(bool(compiler), "CXX resolved to an empty command")
    with tempfile.TemporaryDirectory(prefix="c1264-fixed-link-") as directory:
        scratch = pathlib.Path(directory)
        executable = scratch / "canonical_enum"
        compile_command = [
            *compiler,
            "-std=c++20",
            "-O3",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            str(canonical_source),
            "-o",
            str(executable),
        ]
        run_checked(compile_command)

        covers8 = scratch / "covers8.txt"
        result8 = run_checked([str(executable), "8", str(covers8)])
        require(
            "target=8 solutions=0 " in result8.stdout,
            "eight-block run did not report zero solutions",
        )
        require(
            file_sha256(covers8) == EXPECTED["empty"],
            "eight-block output is not empty",
        )

        covers9 = scratch / "covers9.txt"
        result9 = run_checked([str(executable), "9", str(covers9)])
        require(
            "target=9 solutions=359100 " in result9.stdout,
            "nine-block run did not report 359100 solutions",
        )
        require(
            file_sha256(covers9) == EXPECTED["covers"],
            "canonical nine-block cover list hash changed",
        )

        audit_output = scratch / "audit"
        audit_command = [
            sys.executable,
            "-S",
            str(audit_source),
            "--covers",
            str(covers9),
            "--base-cnf",
            str(BASE_CNF),
            "--output-dir",
            str(audit_output),
        ]
        if args.candidate_representatives is not None:
            audit_command.extend(
                [
                    "--candidate-representatives",
                    str(args.candidate_representatives),
                ]
            )
        audit_result = run_checked(audit_command)
        require(
            '"result": "PASS"' in audit_result.stdout,
            "classification auditor did not report PASS",
        )
        regenerated_report = audit_output / "AUDIT_REPORT.json"
        require(
            regenerated_report.read_bytes() == frozen_report.read_bytes(),
            "regenerated report differs from the frozen report",
        )
        require(
            file_sha256(audit_output / "link_representatives.txt")
            == EXPECTED["representatives"],
            "regenerated representative hash changed",
        )
        require(
            file_sha256(audit_output / "conceptual_case_hashes.json")
            == EXPECTED["case_hashes"],
            "regenerated case-hash manifest changed",
        )

    print(
        "PASS fixed-link classification: 359100 covers; 119700 admissible; "
        "768 group elements; 266 orbits"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationFailure as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
