#!/usr/bin/env python3
"""Independent reconstruction and semantic audit of the compact C(12,6,4) CNF.

This program uses only the Python standard library.  In particular, it does
not import Python-SAT or call its compiled ``pycard`` extension.  The encoder
below is a line-for-line semantic transcription of the pinned upstream
``cardenc/mto.hh`` implementation identified in ``SOURCE_PIN.json``.

The audit has two independent gates:

* exhaustive existential truth tables, discharged by the small DPLL checker
  in this file, for AtMost, AtLeast, and Equals encodings; and
* byte-for-byte reconstruction of the production ``global_base.cnf``,
  including clause order, auxiliary identifiers, section boundaries, and
  SHA-256 hashes.

No solver campaign is run.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
import os
import platform
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


if not __debug__:
    raise RuntimeError(
        "this proof auditor refuses Python -O because fail-closed checks "
        "must remain enabled"
    )


SOURCE_COMMIT = "7abb1d6fdafe1d75fe3e5cdfb48f7e07a8a76efd"
SOURCE_VERSION = "1.9.dev7"
SOURCE_MTO_GIT_BLOB_SHA1 = "eb52038ee5a6708555078e3836415d16c07a352e"
SOURCE_MTO_SHA256 = (
    "fb5b7cc56c2ea3bc02c0a9004e4a2915c1a3440e9e749e369da78bef14b82626"
)
EXPECTED_SOURCE_PIN_SHA256 = (
    "69ed12e0a81a197a7068de88fe466e63544fd489f02d83385d2a917b26919c79"
)
SOURCE_FILES = {
    "cardenc/card.hh": (
        2468,
        "17533a00e87ce169c56a5652df2a29932f320fef",
        "815d15147b034d3c8c93978ed90d26f43d45e0df307f63545f74cb9f5e10a2d5",
    ),
    "cardenc/clset.hh": (
        1874,
        "a6c4d8896b274c7380f9236dc93f9c7f5e9d2239",
        "cfd9acc8cca431c0681a06891ff53083a4d1838a3c0bfdaa1cbc3c050e1e7b31",
    ),
    "cardenc/common.hh": (
        1303,
        "24ddb92275555892df8e53d2b2c78b8e65303e76",
        "2fb65ee5bb58158d1464f62b596b3ac66b6631850ae20fec0ad5e75008480619",
    ),
    "cardenc/mto.hh": (
        11355,
        SOURCE_MTO_GIT_BLOB_SHA1,
        SOURCE_MTO_SHA256,
    ),
    "pysat/__init__.py": (
        680,
        "8a974a611052b5e1f158d3d73abcb17818c10bb9",
        "e334843c05f588a429155df0b06fd5562762b9540de22f64d90ed7fb6845416c",
    ),
    "pysat/card.py": (
        30066,
        "3b6e055a206970ee5efde0fc8768d9a8d139c49e",
        "adabf7fedfe60b36cbc3c48075770e87e3cd6c5b5a013552009ce96f282a890e",
    ),
}

POINTS = tuple(range(12))
BLOCKS = tuple(itertools.combinations(POINTS, 6))
BLOCK_SETS = tuple(frozenset(block) for block in BLOCKS)
MATCHED_PAIRS = frozenset((2 * index, 2 * index + 1) for index in range(6))

PRIMARY_VARIABLES = 924
EXPECTED_TOTAL_VARIABLES = 122_519
EXPECTED_SECTION_COUNTS = (57_972, 141_960, 155_980, 495)
EXPECTED_BASE_CLAUSES = sum(EXPECTED_SECTION_COUNTS)
EXPECTED_FULL_SHA256 = (
    "637d9326388f77f933f3d066cd762d8c0ac4b2df0d2260d688e031d55959e7f0"
)
EXPECTED_BODY_SHA256 = (
    "6a1a2eb2843a4ddcf9138c5a85aaeccd2950b3e099e0ab8a26ce9fc815ab0cc5"
)
EXPECTED_SECTION_SHA256 = (
    "9a90ad6ce85edc53f9639b077534cfede27971974451b4676e414fbb0ad1ae9b",
    "2d300e47472c3aa8340555f1ffa0eb0abf7f22c4563fb18baaf43eeeb5362b40",
    "bd56975a519fed6bce06eb8159f02417051c12b4f3a1fb61babf6e494153386c",
    "381d8e308ae3cc608ab74288477f1506c882b6af2eb2b0be891f94bb44612538",
)
EXPECTED_SECTION_SHAPES = (
    {2: 6_888, 3: 30_276, 4: 20_808},
    {2: 42_696, 3: 88_836, 4: 10_428},
    {2: 64_020, 3: 91_960},
    {28: 495},
)


class AuditFailure(RuntimeError):
    """A fail-closed audit mismatch."""


def fail(message: str) -> None:
    raise AuditFailure(message)


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def clause_bytes(clause: Sequence[int]) -> bytes:
    return (" ".join(str(literal) for literal in clause) + " 0\n").encode()


@dataclass
class Top:
    """The collision-free IDPool specialization used by the production build."""

    value: int

    def fresh(self) -> int:
        self.value += 1
        return self.value


# Pure-Python transcription of cardenc/mto.hh.
# Function and local names deliberately track the pinned C++ source.


def to_UA(
    top: Top,
    clauses: list[tuple[int, ...]],
    outlst: Sequence[int],
    alst: Sequence[int],
    blst: Sequence[int],
) -> None:
    del top  # mto.hh accepts top_id here but does not modify it.
    m = len(alst)
    n = len(blst)

    for j in range(n):
        clauses.append((-blst[j], outlst[j]))

    for i in range(m):
        clauses.append((-alst[i], outlst[i]))

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            clauses.append((-alst[i - 1], -blst[j - 1], outlst[i + j - 1]))


def to_TO(
    top: Top, clauses: list[tuple[int, ...]], invars: Sequence[int]
) -> list[int]:
    n = len(invars)
    if n < 2:
        return list(invars)

    outvars = [top.fresh() for _ in range(n)]
    stack: list[tuple[list[int], list[int]]] = [
        (list(invars), list(outvars))
    ]

    while stack:
        ilst, olst = stack.pop()
        n = len(ilst)
        half = n - (n >> 1)

        fsthalf = ilst[:half]
        if half < 2:
            outfsthalf = list(fsthalf)
        else:
            outfsthalf = [top.fresh() for _ in range(half)]
            stack.append((fsthalf, outfsthalf))

        sndhalf = ilst[half:]
        if n - half < 2:
            outsndhalf = list(sndhalf)
        else:
            outsndhalf = [top.fresh() for _ in range(n - half)]
            stack.append((sndhalf, outsndhalf))

        to_UA(top, clauses, olst, outfsthalf, outsndhalf)

    return outvars


def mto_MUA_A(
    top: Top,
    clauses: list[tuple[int, ...]],
    hs: Sequence[int],
    rs: Sequence[int],
    fs: Sequence[int],
    ass: Sequence[int],
    gs: Sequence[int],
    bs: Sequence[int],
    p: int,
) -> None:
    sigma = len(hs)
    alfa = len(fs)
    m = len(ass)
    beta = len(gs)
    n = len(bs)

    c = top.fresh()

    # phi 1
    for j in range(1, n + 1):
        clauses.append((-bs[j - 1], rs[j - 1], c))

    for i in range(1, m + 1):
        clauses.append((-ass[i - 1], rs[i - 1], c))

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if i + j < p:
                clauses.append(
                    (-ass[i - 1], -bs[j - 1], rs[i + j - 1], c)
                )
            elif i + j > p:
                clauses.append(
                    (-ass[i - 1], -bs[j - 1], rs[((i + j) % p) - 1])
                )
            else:
                clauses.append((-ass[i - 1], -bs[j - 1], c))

    # phi 2
    if sigma == 0:
        clauses.append((-c,))
    else:
        clauses.append((-c, hs[0]))

    for j in range(1, beta + 1):
        if j <= sigma:
            clauses.append((-gs[j - 1], hs[j - 1]))
        else:
            clauses.append((-gs[j - 1],))

        if j < sigma:
            clauses.append((-c, -gs[j - 1], hs[j]))
        else:
            clauses.append((-c, -gs[j - 1]))

    for i in range(1, alfa + 1):
        if i <= sigma:
            clauses.append((-fs[i - 1], hs[i - 1]))
        else:
            clauses.append((-fs[i - 1],))

        if i < sigma:
            clauses.append((-c, -fs[i - 1], hs[i]))
        else:
            clauses.append((-c, -fs[i - 1]))

    for i in range(1, alfa + 1):
        for j in range(1, beta + 1):
            if i + j <= sigma:
                clauses.append((-fs[i - 1], -gs[j - 1], hs[i + j - 1]))
            else:
                clauses.append((-fs[i - 1], -gs[j - 1]))

            lits = [-c, -fs[i - 1], -gs[j - 1]]
            if i + j < sigma:
                lits.append(hs[i + j])
            clauses.append(tuple(lits))


def mto_MTO_A(
    top: Top,
    clauses: list[tuple[int, ...]],
    invars: Sequence[int],
    p: int,
    k: int = -1,
) -> tuple[list[int], list[int]]:
    if len(invars) < p:
        return [], to_TO(top, clauses, invars)

    un = len(invars) // p
    if k >= 0 and k // p < un:
        un = k // p

    us = [top.fresh() for _ in range(un)]
    ls = [top.fresh() for _ in range(p - 1)]

    stack: list[
        tuple[list[int], list[int], list[int]]
    ] = [(list(invars), list(us), list(ls))]

    while stack:
        ilst, ulst, llst = stack.pop()
        ni = len(ilst)
        half = ni - (ni >> 1)

        fsthalf = ilst[:half]
        if half < p:
            ufsthalf: list[int] = []
            lfsthalf = to_TO(top, clauses, fsthalf)
        else:
            un = half // p
            if k >= 0 and k // p < un:
                un = k // p
            ufsthalf = [top.fresh() for _ in range(un)]
            lfsthalf = [top.fresh() for _ in range(p - 1)]
            stack.append((fsthalf, ufsthalf, lfsthalf))

        sndhalf = ilst[half:]
        if ni - half < p:
            usndhalf: list[int] = []
            lsndhalf = to_TO(top, clauses, sndhalf)
        else:
            un = (ni - half) // p
            if k >= 0 and k // p < un:
                un = k // p
            usndhalf = [top.fresh() for _ in range(un)]
            lsndhalf = [top.fresh() for _ in range(p - 1)]
            stack.append((sndhalf, usndhalf, lsndhalf))

        mto_MUA_A(
            top,
            clauses,
            ulst,
            llst,
            ufsthalf,
            lfsthalf,
            usndhalf,
            lsndhalf,
            p,
        )

    return us, ls


def mto_comparator(
    clauses: list[tuple[int, ...]],
    upper: Sequence[int],
    lower: Sequence[int],
    p: int,
    k: int,
) -> None:
    ro = k // p
    nu = k % p

    for i in range(ro + 1, len(upper) + 1):
        clauses.append((-upper[i - 1],))

    for i in range(nu + 1, p):
        if ro > 0:
            if ro - 1 < len(upper):
                clauses.append((-upper[ro - 1], -lower[i - 1]))
        else:
            clauses.append((-lower[i - 1],))


def common_encode_atleast1(
    clauses: list[tuple[int, ...]], variables: Sequence[int]
) -> None:
    clauses.append(tuple(variables))


def common_encode_atleastN(
    clauses: list[tuple[int, ...]], variables: Sequence[int]
) -> None:
    clauses.extend((variable,) for variable in variables)


def common_encode_atmost0(
    clauses: list[tuple[int, ...]], variables: Sequence[int]
) -> None:
    clauses.extend((-variable,) for variable in variables)


def common_encode_atmostNm1(
    clauses: list[tuple[int, ...]], variables: Sequence[int]
) -> None:
    clauses.append(tuple(-variable for variable in variables))


def kmto_encode_atmostN(
    top: Top,
    clauses: list[tuple[int, ...]],
    variables: Sequence[int],
    k: int,
) -> None:
    n = len(variables)
    if k >= n:
        return
    if k == 0:
        common_encode_atmost0(clauses, variables)
        return

    p = max(2, math.isqrt(k))
    upper, lower = mto_MTO_A(top, clauses, variables, p, k)
    mto_comparator(clauses, upper, lower, p, k)


def encode_atmost(
    variables: Sequence[int], bound: int, top: Top
) -> list[tuple[int, ...]]:
    if bound < 0:
        fail(f"negative AtMost bound {bound}")
    variables = list(variables)
    top.value = max([top.value] + [abs(literal) for literal in variables])
    clauses: list[tuple[int, ...]] = []

    # cardenc/card.hh::_encode_atmost dispatch, including its special cases.
    if bound >= len(variables):
        return clauses
    if bound == len(variables) - 1:
        common_encode_atmostNm1(clauses, variables)
    elif bound == 0:
        common_encode_atmost0(clauses, variables)
    else:
        kmto_encode_atmostN(top, clauses, variables, bound)
    return clauses


def encode_atleast(
    variables: Sequence[int], bound: int, top: Top
) -> list[tuple[int, ...]]:
    if bound > len(variables):
        fail(f"AtLeast bound {bound} exceeds arity {len(variables)}")
    variables = list(variables)
    top.value = max([top.value] + [abs(literal) for literal in variables])
    clauses: list[tuple[int, ...]] = []

    # cardenc/card.hh::_encode_atleast.
    if bound <= 0:
        return clauses
    if bound == 1:
        common_encode_atleast1(clauses, variables)
    elif bound == len(variables):
        common_encode_atleastN(clauses, variables)
    else:
        negated = [-literal for literal in variables]
        clauses.extend(encode_atmost(negated, len(variables) - bound, top))
    return clauses


def encode_equals(
    variables: Sequence[int], bound: int, top: Top
) -> tuple[list[tuple[int, ...]], dict[str, int]]:
    # pysat.card.CardEnc.equals calls AtLeast first and AtMost second.
    start_top = top.value
    atleast = encode_atleast(variables, bound, top)
    middle_top = top.value
    atmost = encode_atmost(variables, bound, top)
    return atleast + atmost, {
        "top_before": start_top,
        "top_after_atleast": middle_top,
        "top_after_atmost": top.value,
        "atleast_clauses": len(atleast),
        "atmost_clauses": len(atmost),
    }


def production_specifications() -> tuple[
    tuple[int, ...],
    tuple[tuple[tuple[int, int], int, tuple[int, ...]], ...],
    tuple[tuple[tuple[int, int, int], int, tuple[int, ...]], ...],
    tuple[tuple[int, ...], ...],
]:
    if len(BLOCKS) != PRIMARY_VARIABLES:
        fail(f"expected 924 primary blocks, got {len(BLOCKS)}")
    primaries = tuple(range(1, PRIMARY_VARIABLES + 1))

    pairs = []
    for edge in itertools.combinations(POINTS, 2):
        edge_set = frozenset(edge)
        literals = tuple(
            index + 1
            for index, block_set in enumerate(BLOCK_SETS)
            if edge_set <= block_set
        )
        if len(literals) != math.comb(10, 4):
            fail(f"pair {edge}: expected 210 literals")
        pairs.append(
            (
                edge,
                10 if edge in MATCHED_PAIRS else 9,
                literals,
            )
        )

    triples = []
    for triple in itertools.combinations(POINTS, 3):
        triple_set = frozenset(triple)
        literals = tuple(
            index + 1
            for index, block_set in enumerate(BLOCK_SETS)
            if triple_set <= block_set
        )
        if len(literals) != math.comb(9, 3):
            fail(f"triple {triple}: expected 84 literals")
        triples.append((triple, 4, literals))

    coverage = []
    for quad in itertools.combinations(POINTS, 4):
        quad_set = frozenset(quad)
        clause = tuple(
            index + 1
            for index, block_set in enumerate(BLOCK_SETS)
            if quad_set <= block_set
        )
        if len(clause) != math.comb(8, 2):
            fail(f"quadruple {quad}: expected 28 covering blocks")
        coverage.append(clause)

    return primaries, tuple(pairs), tuple(triples), tuple(coverage)


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def git_output(repository: Path, arguments: Sequence[str]) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        stderr = (
            error.stderr.decode(errors="replace")
            if isinstance(error, subprocess.CalledProcessError)
            else str(error)
        )
        fail(f"git source-pin check failed: {stderr.strip()}")
    return completed.stdout


def audit_source_pin(repository: Path, pin_path: Path) -> dict[str, object]:
    if not repository.is_dir():
        fail(f"pinned source repository is missing: {repository}")
    if pin_path.is_symlink() or not pin_path.is_file():
        fail(f"SOURCE_PIN.json is missing or a symlink: {pin_path}")
    if file_sha256(pin_path) != EXPECTED_SOURCE_PIN_SHA256:
        fail("SOURCE_PIN.json SHA-256 changed")

    commit = git_output(
        repository, ["rev-parse", f"{SOURCE_COMMIT}^{{commit}}"]
    ).decode().strip()
    if commit != SOURCE_COMMIT:
        fail(f"source commit resolved to {commit}")
    remote = git_output(repository, ["remote", "get-url", "origin"]).decode().strip()
    if remote not in (
        "https://github.com/pysathq/pysat",
        "https://github.com/pysathq/pysat.git",
        "git@github.com:pysathq/pysat.git",
    ):
        fail(f"unexpected source remote {remote!r}")

    checked_files = {}
    for source_path, (expected_bytes, expected_blob, expected_sha) in (
        SOURCE_FILES.items()
    ):
        blob = git_output(
            repository,
            ["rev-parse", f"{SOURCE_COMMIT}:{source_path}"],
        ).decode().strip()
        if blob != expected_blob:
            fail(f"{source_path}: Git blob {blob} changed")
        raw = git_output(
            repository, ["show", f"{SOURCE_COMMIT}:{source_path}"]
        )
        if len(raw) != expected_bytes:
            fail(f"{source_path}: byte count {len(raw)} changed")
        digest = sha256_bytes(raw)
        if digest != expected_sha:
            fail(f"{source_path}: SHA-256 {digest} changed")
        checked_files[source_path] = {
            "bytes": len(raw),
            "git_blob_sha1": blob,
            "sha256": digest,
        }

    version_raw = git_output(
        repository, ["show", f"{SOURCE_COMMIT}:pysat/__init__.py"]
    )
    if b"VERSION = (1, 9, 'dev', 7)" not in version_raw:
        fail("pinned source does not declare version 1.9.dev7")
    return {
        "repository_path": str(repository.resolve()),
        "remote": remote,
        "commit": commit,
        "declared_version": SOURCE_VERSION,
        "source_pin_json": {
            "path": str(pin_path.resolve()),
            "sha256": file_sha256(pin_path),
        },
        "checked_files": checked_files,
    }


def run_checked(
    arguments: Sequence[str], *, cwd: Path | None = None
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            list(arguments),
            cwd=str(cwd) if cwd else None,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        stderr = (
            error.stderr.decode(errors="replace")
            if isinstance(error, subprocess.CalledProcessError)
            else str(error)
        )
        fail(
            f"command failed ({' '.join(arguments)}): {stderr.strip()}"
        )


def parse_reference_output(
    raw: bytes, label: str
) -> tuple[int, list[tuple[int, ...]]]:
    lines = raw.splitlines()
    if not lines:
        fail(f"{label}: empty source-reference output")
    fields = lines[0].split()
    if len(fields) != 3 or fields[0] != b"p":
        fail(f"{label}: malformed source-reference header")
    try:
        top = int(fields[1])
        expected_clauses = int(fields[2])
    except ValueError:
        fail(f"{label}: noninteger source-reference header")
    clauses = []
    for line_number, line in enumerate(lines[1:], start=2):
        try:
            values = tuple(int(token) for token in line.split())
        except ValueError:
            fail(f"{label}:{line_number}: noninteger clause")
        if not values or values[-1] != 0 or 0 in values[:-1]:
            fail(f"{label}:{line_number}: malformed clause")
        clauses.append(values[:-1])
    if len(clauses) != expected_clauses:
        fail(
            f"{label}: header says {expected_clauses} clauses, "
            f"parsed {len(clauses)}"
        )
    return top, clauses


def audit_official_source_vectors(
    repository: Path, output_dir: Path, driver_source: Path
) -> dict[str, object]:
    if driver_source.is_symlink() or not driver_source.is_file():
        fail(f"source reference driver is missing: {driver_source}")

    include_dir = output_dir / "pinned_source_headers" / "cardenc"
    include_dir.mkdir(parents=True, exist_ok=True)
    header_names = git_output(
        repository,
        [
            "ls-tree",
            "-r",
            "--name-only",
            SOURCE_COMMIT,
            "cardenc",
        ],
    ).decode().splitlines()
    materialized = 0
    for source_path in header_names:
        if not source_path.endswith(".hh"):
            continue
        raw = git_output(
            repository, ["show", f"{SOURCE_COMMIT}:{source_path}"]
        )
        destination = include_dir / Path(source_path).name
        destination.write_bytes(raw)
        materialized += 1
    if materialized < 10:
        fail(f"only {materialized} official headers were materialized")

    binary = output_dir / "official_source_reference"
    compiler = os.environ.get("CXX", "c++")
    compile_result = run_checked(
        [
            compiler,
            "-std=c++11",
            "-O2",
            "-I",
            str(include_dir),
            str(driver_source),
            "-o",
            str(binary),
        ]
    )
    if compile_result.stdout:
        fail("official source driver compilation wrote unexpected stdout")
    compiler_version = run_checked([compiler, "--version"]).stdout.decode(
        errors="replace"
    ).splitlines()[0]

    vectors: list[tuple[str, int, int, int, int]] = []
    for arity in range(1, 10):
        for operation in ("atmost", "atleast"):
            for bound in range(arity + 1):
                vectors.append((operation, arity, bound, arity, 1))

    # These exercise every radix and arity used in the production base.
    vectors.extend(
        [
            ("atmost", 84, 4, 7_000, 1),
            ("atmost", 210, 9, 8_000, 1),
            ("atmost", 210, 10, 9_000, 1),
            ("atmost", 924, 40, 10_000, 1),
            ("atmost", 924, 884, 20_000, -1),
        ]
    )

    vector_hasher = hashlib.sha256()
    clause_total = 0
    top_after_first_exact_half: int | None = None
    for index, (operation, arity, bound, top_before, sign) in enumerate(
        vectors
    ):
        inputs = tuple(sign * variable for variable in range(1, arity + 1))
        pure_top = Top(top_before)
        if operation == "atmost":
            pure_clauses = encode_atmost(inputs, bound, pure_top)
        else:
            pure_clauses = encode_atleast(inputs, bound, pure_top)

        result = run_checked(
            [
                str(binary),
                operation,
                str(arity),
                str(bound),
                str(top_before),
                str(sign),
            ]
        )
        reference_top, reference_clauses = parse_reference_output(
            result.stdout, f"source-vector-{index}"
        )
        if reference_top != pure_top.value:
            fail(
                f"source-vector-{index}: top {reference_top} "
                f"!= transcription {pure_top.value}"
            )
        if reference_clauses != pure_clauses:
            for clause_index, (reference, pure) in enumerate(
                itertools.zip_longest(reference_clauses, pure_clauses)
            ):
                if reference != pure:
                    fail(
                        f"source-vector-{index}: clause {clause_index} "
                        f"official={reference}, transcription={pure}"
                    )
            fail(f"source-vector-{index}: unexplained clause mismatch")

        if arity == 924 and bound == 884 and sign == -1:
            top_after_first_exact_half = reference_top
        row = {
            "operation": operation,
            "arity": arity,
            "bound": bound,
            "top_before": top_before,
            "top_after": reference_top,
            "input_sign": sign,
            "clauses": len(reference_clauses),
            "clause_sha256": sha256_bytes(
                b"".join(
                    clause_bytes(clause) for clause in reference_clauses
                )
            ),
        }
        vector_hasher.update(canonical_json_bytes(row))
        clause_total += len(reference_clauses)

    if top_after_first_exact_half is None:
        fail("large negative-input source vector was not checked")

    # Reproduce the actual two-step ID allocation of Equals(924, 40).
    negative_inputs = tuple(-variable for variable in range(1, 925))
    first_top = Top(924)
    first_pure = encode_atmost(negative_inputs, 884, first_top)
    first_reference = run_checked(
        [str(binary), "atmost", "924", "884", "924", "-1"]
    )
    official_first_top, official_first = parse_reference_output(
        first_reference.stdout, "production-equals-atleast-half"
    )
    if official_first_top != first_top.value or official_first != first_pure:
        fail("actual Equals AtLeast half differs from official source")

    positive_inputs = tuple(range(1, 925))
    second_top = Top(official_first_top)
    second_pure = encode_atmost(positive_inputs, 40, second_top)
    second_reference = run_checked(
        [
            str(binary),
            "atmost",
            "924",
            "40",
            str(official_first_top),
            "1",
        ]
    )
    official_second_top, official_second = parse_reference_output(
        second_reference.stdout, "production-equals-atmost-half"
    )
    if official_second_top != second_top.value or official_second != second_pure:
        fail("actual Equals AtMost half differs from official source")
    exact_raw = b"".join(
        clause_bytes(clause) for clause in official_first + official_second
    )
    if sha256_bytes(exact_raw) != EXPECTED_SECTION_SHA256[0]:
        fail("official source exact-section vector has unexpected SHA-256")
    if official_second_top != 10_363:
        fail(
            f"official source exact-section top {official_second_top} "
            "!= 10363"
        )
    for label, top_before, top_after, clauses in (
        (
            "production_equals_atleast_half",
            924,
            official_first_top,
            official_first,
        ),
        (
            "production_equals_atmost_half",
            official_first_top,
            official_second_top,
            official_second,
        ),
    ):
        vector_hasher.update(
            canonical_json_bytes(
                {
                    "label": label,
                    "top_before": top_before,
                    "top_after": top_after,
                    "clauses": len(clauses),
                    "clause_sha256": sha256_bytes(
                        b"".join(
                            clause_bytes(clause) for clause in clauses
                        )
                    ),
                }
            )
        )

    return {
        "driver_source": {
            "path": str(driver_source.resolve()),
            "sha256": file_sha256(driver_source),
        },
        "compiled_binary": {
            "path": str(binary.resolve()),
            "sha256": file_sha256(binary),
        },
        "compiler": compiler_version,
        "materialized_official_headers": materialized,
        "vectors_checked": len(vectors) + 2,
        "clauses_compared": clause_total + len(official_first) + len(official_second),
        "vector_manifest_sha256": vector_hasher.hexdigest(),
        "production_equals_section": {
            "clauses": len(official_first) + len(official_second),
            "top_after": official_second_top,
            "sha256": sha256_bytes(exact_raw),
        },
        "result": "byte-identical to the official C++ source implementation",
    }


def reconstruct_production(
    output_path: Path,
) -> tuple[dict[str, object], list[list[tuple[int, ...]]]]:
    primaries, pairs, triples, coverage = production_specifications()
    top = Top(PRIMARY_VARIABLES)
    sections: list[list[tuple[int, ...]]] = [[], [], [], []]
    boundaries: list[dict[str, object]] = []

    clause_start = 0
    exact_top_before = top.value
    exact, exact_parts = encode_equals(primaries, 40, top)
    sections[0].extend(exact)
    boundaries.append(
        {
            "section": "exact_block_count",
            "operation": "equals",
            "arity": len(primaries),
            "bound": 40,
            "clause_start_zero_based": clause_start,
            "clause_end_exclusive": clause_start + len(exact),
            "top_before": exact_top_before,
            "top_after": top.value,
            "internal_parts": exact_parts,
            "clause_sha256": sha256_bytes(
                b"".join(clause_bytes(clause) for clause in exact)
            ),
        }
    )
    clause_start += len(exact)

    for edge, bound, literals in pairs:
        top_before = top.value
        encoded = encode_atmost(literals, bound, top)
        sections[1].extend(encoded)
        boundaries.append(
            {
                "section": "pair_atmost",
                "index": len(
                    [
                        row
                        for row in boundaries
                        if row["section"] == "pair_atmost"
                    ]
                ),
                "object": list(edge),
                "operation": "atmost",
                "arity": len(literals),
                "bound": bound,
                "clause_start_zero_based": clause_start,
                "clause_end_exclusive": clause_start + len(encoded),
                "top_before": top_before,
                "top_after": top.value,
                "clause_sha256": sha256_bytes(
                    b"".join(clause_bytes(clause) for clause in encoded)
                ),
            }
        )
        clause_start += len(encoded)

    for triple, bound, literals in triples:
        top_before = top.value
        encoded = encode_atmost(literals, bound, top)
        sections[2].extend(encoded)
        boundaries.append(
            {
                "section": "triple_atmost",
                "index": len(
                    [
                        row
                        for row in boundaries
                        if row["section"] == "triple_atmost"
                    ]
                ),
                "object": list(triple),
                "operation": "atmost",
                "arity": len(literals),
                "bound": bound,
                "clause_start_zero_based": clause_start,
                "clause_end_exclusive": clause_start + len(encoded),
                "top_before": top_before,
                "top_after": top.value,
                "clause_sha256": sha256_bytes(
                    b"".join(clause_bytes(clause) for clause in encoded)
                ),
            }
        )
        clause_start += len(encoded)

    coverage_start = clause_start
    sections[3].extend(coverage)
    boundaries.append(
        {
            "section": "quadruple_coverage",
            "operation": "literal_clauses",
            "objects": len(coverage),
            "arity": 28,
            "clause_start_zero_based": coverage_start,
            "clause_end_exclusive": coverage_start + len(coverage),
            "top_before": top.value,
            "top_after": top.value,
            "clause_sha256": sha256_bytes(
                b"".join(clause_bytes(clause) for clause in coverage)
            ),
        }
    )
    clause_start += len(coverage)

    section_counts = tuple(len(section) for section in sections)
    if section_counts != EXPECTED_SECTION_COUNTS:
        fail(
            f"section counts {section_counts} != {EXPECTED_SECTION_COUNTS}"
        )
    if clause_start != EXPECTED_BASE_CLAUSES:
        fail(f"reconstructed {clause_start} clauses")
    if top.value != EXPECTED_TOTAL_VARIABLES:
        fail(f"final auxiliary top {top.value} != 122519")

    section_raw = [
        b"".join(clause_bytes(clause) for clause in section)
        for section in sections
    ]
    header = (
        f"p cnf {top.value} {sum(section_counts)}\n".encode()
    )
    raw = header + b"".join(section_raw)
    output_path.write_bytes(raw)

    used = bytearray(top.value + 1)
    shapes = []
    for section in sections:
        shape = Counter()
        for clause in section:
            shape[len(clause)] += 1
            for literal in clause:
                used[abs(literal)] = 1
        shapes.append(dict(sorted(shape.items())))
    unused_auxiliaries = [
        variable
        for variable in range(PRIMARY_VARIABLES + 1, top.value + 1)
        if not used[variable]
    ]
    if unused_auxiliaries:
        fail(
            f"{len(unused_auxiliaries)} reconstructed auxiliaries are unused"
        )

    manifest: dict[str, object] = {
        "source_commit": SOURCE_COMMIT,
        "source_version": SOURCE_VERSION,
        "source_mto_git_blob_sha1": SOURCE_MTO_GIT_BLOB_SHA1,
        "source_mto_sha256": SOURCE_MTO_SHA256,
        "primary_variables": PRIMARY_VARIABLES,
        "auxiliary_variables": top.value - PRIMARY_VARIABLES,
        "variables": top.value,
        "clauses": sum(section_counts),
        "bytes": len(raw),
        "full_sha256": sha256_bytes(raw),
        "body_sha256": sha256_bytes(b"".join(section_raw)),
        "section_counts": list(section_counts),
        "section_sha256": [sha256_bytes(part) for part in section_raw],
        "section_shapes": [
            {str(key): value for key, value in shape.items()}
            for shape in shapes
        ],
        "constraint_boundaries": boundaries,
        "constraint_boundaries_sha256": sha256_bytes(
            canonical_json_bytes(boundaries)
        ),
    }
    return manifest, sections


def simplify_clauses(
    clauses: Sequence[Sequence[int]], assignment: dict[int, bool]
) -> tuple[bool, list[tuple[int, ...]], dict[int, bool]]:
    """Unit-propagate a CNF; return (consistent, residual, assignment)."""
    current = dict(assignment)
    residual = [tuple(clause) for clause in clauses]
    while True:
        reduced: list[tuple[int, ...]] = []
        units: list[int] = []
        for clause in residual:
            unresolved = []
            satisfied = False
            for literal in clause:
                variable = abs(literal)
                if variable in current:
                    value = current[variable]
                    if value == (literal > 0):
                        satisfied = True
                        break
                else:
                    unresolved.append(literal)
            if satisfied:
                continue
            if not unresolved:
                return False, [], current
            if len(unresolved) == 1:
                units.append(unresolved[0])
            reduced.append(tuple(unresolved))

        changed = False
        for literal in units:
            variable = abs(literal)
            value = literal > 0
            if variable in current and current[variable] != value:
                return False, [], current
            if variable not in current:
                current[variable] = value
                changed = True
        residual = reduced
        if not changed:
            return True, residual, current


def dpll_satisfiable(
    clauses: Sequence[Sequence[int]], assumptions: Sequence[int]
) -> bool:
    initial: dict[int, bool] = {}
    for literal in assumptions:
        variable = abs(literal)
        value = literal > 0
        if variable in initial and initial[variable] != value:
            return False
        initial[variable] = value

    def search(
        current_clauses: Sequence[Sequence[int]],
        assignment: dict[int, bool],
    ) -> bool:
        consistent, residual, propagated = simplify_clauses(
            current_clauses, assignment
        )
        if not consistent:
            return False
        if not residual:
            return True
        clause = min(residual, key=len)
        variable = abs(clause[0])
        if variable in propagated:
            fail("DPLL selected an assigned variable")
        for value in (True, False):
            branch = dict(propagated)
            branch[variable] = value
            if search(residual, branch):
                return True
        return False

    return search(clauses, initial)


def exhaustive_small_semantics(max_arity: int) -> dict[str, object]:
    tests = 0
    clause_vector_hasher = hashlib.sha256()
    operation_counts: Counter[str] = Counter()

    for arity in range(1, max_arity + 1):
        inputs = tuple(range(1, arity + 1))
        for operation in ("atmost", "atleast", "equals"):
            for bound in range(arity + 1):
                top = Top(arity)
                if operation == "atmost":
                    clauses = encode_atmost(inputs, bound, top)
                elif operation == "atleast":
                    clauses = encode_atleast(inputs, bound, top)
                else:
                    clauses, _ = encode_equals(inputs, bound, top)

                vector = {
                    "arity": arity,
                    "operation": operation,
                    "bound": bound,
                    "top": top.value,
                    "clauses": clauses,
                }
                clause_vector_hasher.update(canonical_json_bytes(vector))

                for mask in range(1 << arity):
                    assumptions = tuple(
                        variable
                        if mask & (1 << (variable - 1))
                        else -variable
                        for variable in inputs
                    )
                    actual = dpll_satisfiable(clauses, assumptions)
                    count = bin(mask).count("1")
                    if operation == "atmost":
                        expected = count <= bound
                    elif operation == "atleast":
                        expected = count >= bound
                    else:
                        expected = count == bound
                    if actual != expected:
                        fail(
                            "small semantics mismatch: "
                            f"arity={arity}, operation={operation}, "
                            f"bound={bound}, mask={mask}, expected={expected}"
                        )
                    tests += 1
                    operation_counts[operation] += 1

    return {
        "max_arity": max_arity,
        "existential_primary_assignments_checked": tests,
        "operation_counts": dict(sorted(operation_counts.items())),
        "clause_test_vector_sha256": clause_vector_hasher.hexdigest(),
        "solver": "independent standard-library DPLL with unit propagation",
    }


def first_byte_mismatch(left: bytes, right: bytes) -> int | None:
    for index, (lbyte, rbyte) in enumerate(zip(left, right)):
        if lbyte != rbyte:
            return index
    if len(left) != len(right):
        return min(len(left), len(right))
    return None


def audit_target(
    target: Path,
    replica: Path,
    manifest: dict[str, object],
) -> dict[str, object]:
    if target.is_symlink() or not target.is_file():
        fail(f"target is not a regular non-symlink file: {target}")
    target_before = file_sha256(target)
    replica_hash = file_sha256(replica)
    target_raw = target.read_bytes()
    replica_raw = replica.read_bytes()
    target_after = file_sha256(target)
    if target_before != target_after:
        fail("production target changed while being audited")
    mismatch = first_byte_mismatch(target_raw, replica_raw)
    if mismatch is not None:
        fail(
            "reconstruction differs from production at byte "
            f"{mismatch}: target={target_raw[mismatch:mismatch + 32]!r}, "
            f"replica={replica_raw[mismatch:mismatch + 32]!r}"
        )

    if target_before != EXPECTED_FULL_SHA256:
        fail(f"target full SHA-256 changed: {target_before}")
    if replica_hash != EXPECTED_FULL_SHA256:
        fail(f"replica full SHA-256 changed: {replica_hash}")
    if manifest["body_sha256"] != EXPECTED_BODY_SHA256:
        fail(f"body SHA-256 changed: {manifest['body_sha256']}")
    if tuple(manifest["section_sha256"]) != EXPECTED_SECTION_SHA256:
        fail("section SHA-256 list changed")
    actual_shapes = tuple(
        {int(key): value for key, value in shape.items()}
        for shape in manifest["section_shapes"]
    )
    if actual_shapes != EXPECTED_SECTION_SHAPES:
        fail(f"section clause shapes changed: {actual_shapes}")

    # The equality must not be a vacuous self-hash check.
    mutated = bytearray(replica_raw)
    mutation_index = replica_raw.index(b"-1041")
    mutated[mutation_index + 1] = ord("2")
    if sha256_bytes(bytes(mutated)) == EXPECTED_FULL_SHA256:
        fail("mutation self-test did not alter the pinned hash")
    if first_byte_mismatch(target_raw, bytes(mutated)) != mutation_index + 1:
        fail("mutation self-test did not identify the exact changed byte")

    return {
        "target": str(target),
        "target_bytes": len(target_raw),
        "target_sha256_before": target_before,
        "target_sha256_after": target_after,
        "replica": str(replica),
        "replica_bytes": len(replica_raw),
        "replica_sha256": replica_hash,
        "byte_for_byte_equal": True,
        "mutation_detection": {
            "mutated_byte_offset": mutation_index + 1,
            "detected_exact_offset": True,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--target",
        type=Path,
        required=True,
        help="published compact global-base CNF to compare byte for byte",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=(
            Path(__file__).resolve().parents[2]
            / ".verification"
            / "compact-encoder-audit"
        ),
    )
    parser.add_argument(
        "--source-repo",
        type=Path,
        required=True,
        help="Git clone containing the pinned Python-SAT commit",
    )
    parser.add_argument(
        "--reference-driver",
        type=Path,
        default=Path(__file__).resolve().parent
        / "source_reference_driver.cc",
    )
    parser.add_argument("--small-max-arity", type=int, default=7)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    started = time.monotonic()
    try:
        if not 1 <= args.small_max_arity <= 9:
            fail("--small-max-arity must be between 1 and 9")
        args.output_dir.mkdir(parents=True, exist_ok=True)
        source_pin = audit_source_pin(
            args.source_repo.resolve(),
            Path(__file__).resolve().parent / "SOURCE_PIN.json",
        )
        source_vectors = audit_official_source_vectors(
            args.source_repo.resolve(),
            args.output_dir.resolve(),
            args.reference_driver.resolve(),
        )
        replica = args.output_dir / "reconstructed_global_base.cnf"
        manifest, _sections = reconstruct_production(replica)
        semantics = exhaustive_small_semantics(args.small_max_arity)
        comparison = audit_target(args.target.resolve(), replica, manifest)

        boundaries_path = args.output_dir / "production_boundaries.json"
        boundaries_raw = (
            json.dumps(
                manifest["constraint_boundaries"],
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode()
        boundaries_path.write_bytes(boundaries_raw)

        compact_manifest = {
            key: value
            for key, value in manifest.items()
            if key != "constraint_boundaries"
        }
        report: dict[str, object] = {
            "result": "PASS",
            "claim": (
                "Pure-Python source transcription reproduces every production "
                "clause and auxiliary identifier byte-for-byte, and all small "
                "existential semantics tests pass."
            ),
            "source": {
                "repository": "https://github.com/pysathq/pysat",
                "commit": SOURCE_COMMIT,
                "version": SOURCE_VERSION,
                "mto_path": "cardenc/mto.hh",
                "mto_git_blob_sha1": SOURCE_MTO_GIT_BLOB_SHA1,
                "mto_sha256": SOURCE_MTO_SHA256,
                "verified_pin": source_pin,
                "official_cpp_comparison": source_vectors,
            },
            "reconstruction": compact_manifest,
            "boundaries": {
                "path": str(boundaries_path),
                "bytes": len(boundaries_raw),
                "sha256": sha256_bytes(boundaries_raw),
                "entries": len(manifest["constraint_boundaries"]),
                "canonical_sha256": manifest[
                    "constraint_boundaries_sha256"
                ],
            },
            "small_semantics": semantics,
            "production_comparison": comparison,
            "auditor": {
                "path": str(Path(__file__).resolve()),
                "sha256": file_sha256(Path(__file__).resolve()),
                "imports_pysat": False,
                "python": sys.version,
                "platform": platform.platform(),
            },
            "elapsed_seconds": time.monotonic() - started,
        }
        report_without_hash = canonical_json_bytes(report)
        report["report_core_sha256"] = sha256_bytes(report_without_hash)
        report_path = args.output_dir / "AUDIT_REPORT.json"
        report_path.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(
            json.dumps(
                {
                    "result": "PASS",
                    "production_sha256": manifest["full_sha256"],
                    "body_sha256": manifest["body_sha256"],
                    "variables": manifest["variables"],
                    "clauses": manifest["clauses"],
                    "small_truth_assignments": semantics[
                        "existential_primary_assignments_checked"
                    ],
                    "boundaries_sha256": sha256_bytes(boundaries_raw),
                    "report": str(report_path),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    except AuditFailure as error:
        print(f"AUDIT GAP: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
