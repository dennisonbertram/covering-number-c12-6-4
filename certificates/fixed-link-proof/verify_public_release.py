#!/usr/bin/env python3
"""Fail-closed public verifier for the fixed-link proof release.

The verifier reconstructs all 266 CNFs from the pinned compact base and
production roots, validates every receipt/log/archive byte, checks the raw
DRAT and LRAT identities after decompression, and replays every LRAT with
the exact hash-bound C and CakeML checker binaries recorded by the campaign.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Dict, Iterable, List, Optional, Sequence, Tuple


EXPECTED_CASES = 266
EXPECTED_BASE_SHA256 = (
    "637d9326388f77f933f3d066cd762d8c0ac4b2df0d2260d688e031d55959e7f0"
)
EXPECTED_BASE_BODY_SHA256 = (
    "6a1a2eb2843a4ddcf9138c5a85aaeccd2950b3e099e0ab8a26ce9fc815ab0cc5"
)
EXPECTED_REPRESENTATIVES_SHA256 = (
    "369a844c4590d435fc24f82424a0775d51ce326d243aaf740d025c52c81d652b"
)
EXPECTED_CLASSIFICATION_SHA256SUMS = (
    "a4ce0d022be620df1656d9bee71b4460b20909a7eb0fba9c4d4b18d4879c90c3"
)
EXPECTED_CLASSIFICATION_PASS = (
    "PASS fixed-link classification: 359100 covers; 119700 admissible; "
    "768 group elements; 266 orbits"
)

# These four identities are updated only when the frozen production manifest
# and proof metadata are deliberately regenerated together.
EXPECTED_PRODUCTION_MANIFEST_SHA256 = (
    "d8b6d765c5b9f237633bd879f18b07daa98cfa1ed1b1f5d264d99e279a48fcd2"
)
EXPECTED_PRODUCTION_MANIFEST_FILE_SHA256 = (
    "8f61b714e4bc24d5a3b0faaaceeaf71732e4758f9603a7f335ab97d9d3e4d5f6"
)
EXPECTED_AGGREGATE_SHA256 = (
    "8735ea4aedb5d30fc1fa65ff289f4357bec14d354a993270a620254d30ff575a"
)
EXPECTED_AGGREGATE_FILE_SHA256 = (
    "1d04132e74a52520315325e71ffda4a6d971cb5d422f45f26be43bebba2f0e45"
)
EXPECTED_RELEASE_ASSETS_SHA256 = (
    "499c345b3d48666b67b17df2dda79b6f7af5e7fa7c05668900eb9cd7b5bee2f6"
)
EXPECTED_RELEASE_ASSETS_FILE_SHA256 = (
    "8f43378cc80c8a055f51e4dccc486feb26ee7f94f29aec8404bb059fc98d725d"
)
EXPECTED_DRAT_ARCHIVE_SHA256 = (
    "67acd4729329ad4656b5a94e8a472b11a14a5c81fccaa468448f12957663af4a"
)
EXPECTED_LRAT_ARCHIVE_SHA256 = (
    "c45ea9e621db38f4e25f290cb664352c0b80f1839ad475b422098b12fbbbd615"
)
EXPECTED_HISTORICAL_TOOLS = {
    "cadical": {
        "bytes": 888792,
        "sha256": "1639c68fd8da9db992a37c978e3ccee5833830fd135c412090926ce95937c312",
    },
    "drat-trim": {
        "bytes": 69720,
        "sha256": "42a69f9a17bcd58001676abf02d58992bd0ede58410a467dda07a350fec498c9",
    },
    "lrat-check": {
        "bytes": 36040,
        "sha256": "ac89c8365eaf6548b6237e6e3ff630373582e60854695491a99108df3a7db0e5",
    },
    "cake_lpr": {
        "bytes": 546984,
        "sha256": "9d26b48cb92a860568edea1b7febcebe98e265cc0e74e8c55faa0fac9e63eda7",
    },
}

LOG_KINDS = {
    "solve": "s UNSATISFIABLE",
    "drat-trim": "s VERIFIED",
    "lrat-check": "c VERIFIED",
    "cake-lpr": "s VERIFIED UNSAT",
}


class VerificationError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise VerificationError(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def stream_identity(handle: BinaryIO) -> Tuple[int, str]:
    size = 0
    h = hashlib.sha256()
    for chunk in iter(lambda: handle.read(1 << 20), b""):
        size += len(chunk)
        h.update(chunk)
    return size, h.hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def strict_json(path: Path) -> Any:
    def unique(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                fail("%s: duplicate JSON key %r" % (path, key))
            result[key] = value
        return result

    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique,
            parse_constant=lambda value: fail(
                "%s: invalid JSON constant %s" % (path, value)
            ),
        )
    except VerificationError:
        raise
    except Exception as error:
        fail("%s: invalid JSON: %s" % (path, error))


def verify_self_hash(
    payload: Dict[str, Any],
    field: str,
    expected: Optional[str],
    label: str,
) -> None:
    logical = payload.get(field)
    core = {key: value for key, value in payload.items() if key != field}
    actual = sha(canonical(core))
    if logical != actual or (expected is not None and logical != expected):
        fail("%s: %s mismatch (%s != %s)" % (label, field, logical, actual))


def safe_relative(value: Any, label: str) -> PurePosixPath:
    if not isinstance(value, str):
        fail("%s: path must be a string" % label)
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(
        part in ("", ".", "..") for part in path.parts
    ):
        fail("%s: unsafe relative path %r" % (label, value))
    return path


def ensure_no_symlink_components(path: Path, stop: Path) -> None:
    current = path
    stop = stop.resolve()
    while True:
        if current.is_symlink():
            fail("%s: symlink path component rejected" % current)
        if current == stop:
            return
        if current.parent == current:
            fail("%s: path escaped trusted root %s" % (path, stop))
        current = current.parent


def safe_path(root: Path, value: Any, label: str) -> Path:
    relative = safe_relative(value, label)
    candidate = root.joinpath(*relative.parts)
    ensure_no_symlink_components(candidate, root)
    try:
        candidate.resolve().relative_to(root.resolve())
    except ValueError:
        fail("%s: path escaped trusted root" % label)
    return candidate


def regular(path: Path, label: str, root: Optional[Path] = None) -> None:
    if root is not None:
        ensure_no_symlink_components(path, root)
    if path.is_symlink() or not path.is_file():
        fail("%s: %s is not a regular non-symlink file" % (label, path))


def checked_input_path(value: Path, label: str, kind: str) -> Path:
    """Reject symlinks before canonicalizing a caller-supplied path."""
    raw = Path(os.path.abspath(os.fspath(value)))
    current = raw
    while True:
        if current.is_symlink():
            fail("%s: symlink path component rejected: %s" % (label, current))
        if current.parent == current:
            break
        current = current.parent
    if kind == "file":
        if not raw.is_file():
            fail("%s: not a regular file: %s" % (label, raw))
    elif kind == "directory":
        if not raw.is_dir():
            fail("%s: not a directory: %s" % (label, raw))
    else:
        fail("%s: internal path-kind error" % label)
    return raw.resolve()


def exact_directory_files(
    directory: Path, expected_names: Iterable[str], label: str
) -> None:
    if directory.is_symlink() or not directory.is_dir():
        fail("%s: missing regular directory %s" % (label, directory))
    actual = sorted(
        entry.name for entry in directory.iterdir() if entry.is_file() or entry.is_symlink()
    )
    expected = sorted(expected_names)
    if actual != expected:
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        fail("%s: file-set mismatch missing=%r extra=%r" % (label, missing, extra))


def verify_component_sums(
    root: Path,
    label: str = "proof component",
    expected_manifest_sha256: Optional[str] = None,
) -> None:
    checksum_path = root / "SHA256SUMS"
    regular(checksum_path, label + " checksum manifest", root)
    if (
        expected_manifest_sha256 is not None
        and file_sha(checksum_path) != expected_manifest_sha256
    ):
        fail("%s checksum-manifest identity mismatch" % label)
    pattern = __import__("re").compile(r"^([0-9a-f]{64})  \./(.+)$")
    records: Dict[str, str] = {}
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        match = pattern.fullmatch(line)
        if match is None:
            fail("%s SHA256SUMS contains a malformed line" % label)
        digest, value = match.groups()
        relative = safe_relative(value, label + " SHA256SUMS entry")
        normalized = str(relative)
        if normalized in records:
            fail("%s SHA256SUMS contains a duplicate path" % label)
        records[normalized] = digest
    actual: Dict[str, Path] = {}
    for path in root.rglob("*"):
        relative = str(PurePosixPath(*path.relative_to(root).parts))
        if path.is_symlink():
            fail("%s: symlink rejected by %s inventory" % (path, label))
        if path.is_file() and relative != "SHA256SUMS":
            actual[relative] = path
        elif path.is_dir():
            continue
        elif relative != "SHA256SUMS":
            fail("%s: unsupported filesystem entry" % path)
    if set(records) != set(actual):
        fail(
            "%s inventory mismatch missing=%r extra=%r"
            % (
                label,
                sorted(set(records) - set(actual)),
                sorted(set(actual) - set(records)),
            )
        )
    for relative, digest in records.items():
        if file_sha(actual[relative]) != digest:
            fail("%s: %s checksum mismatch" % (relative, label))


def read_base(base: Path) -> Tuple[bytes, bytes]:
    regular(base, "compact base")
    raw = base.read_bytes()
    if file_sha(base) != EXPECTED_BASE_SHA256:
        fail("compact base full-file SHA-256 mismatch")
    try:
        newline = raw.index(b"\n") + 1
    except ValueError:
        fail("compact base has no DIMACS header line")
    header = raw[:newline]
    body = raw[newline:]
    if header != b"p cnf 122519 356407\n":
        fail("compact base DIMACS header mismatch")
    if sha(body) != EXPECTED_BASE_BODY_SHA256:
        fail("compact base body SHA-256 mismatch")
    if raw.count(b"\n") != 356_408:
        fail("compact base clause-line count mismatch")
    return raw, body


def load_production(
    production: Path, base: Path
) -> Tuple[Dict[str, Any], bytes, Path]:
    manifest_path = production / "manifest.json"
    regular(manifest_path, "production manifest", production)
    if file_sha(manifest_path) != EXPECTED_PRODUCTION_MANIFEST_FILE_SHA256:
        fail("production manifest file SHA-256 mismatch")
    manifest = strict_json(manifest_path)
    verify_self_hash(
        manifest,
        "manifest_sha256",
        EXPECTED_PRODUCTION_MANIFEST_SHA256,
        "production manifest",
    )
    if manifest.get("model_version") != "c12-fixed-link-classification-v1":
        fail("production model version mismatch")
    compact = manifest.get("compact_base")
    if (
        not isinstance(compact, dict)
        or compact.get("sha256") != EXPECTED_BASE_SHA256
        or compact.get("body_sha256") != EXPECTED_BASE_BODY_SHA256
        or compact.get("variables") != 122_519
        or compact.get("clauses") != 356_407
    ):
        fail("production compact-base metadata mismatch")
    base_raw, body = read_base(base)
    if compact.get("bytes") != len(base_raw):
        fail("production compact-base size mismatch")

    entries = manifest.get("entries")
    if not isinstance(entries, list) or len(entries) != EXPECTED_CASES:
        fail("production entry count mismatch")
    if [entry.get("orbit_index") for entry in entries] != list(range(EXPECTED_CASES)):
        fail("production orbit-index exact set/order mismatch")
    expected_root_names = [
        "link_orbit_%03d.units" % index for index in range(EXPECTED_CASES)
    ]
    exact_directory_files(production / "roots", expected_root_names, "production roots")

    root_order = manifest.get("root_order", {}).get("global_variables")
    if (
        not isinstance(root_order, list)
        or len(root_order) != 210
        or len(set(root_order)) != 210
        or root_order != sorted(root_order)
    ):
        fail("production root variable order mismatch")

    derived_representative_lines = []
    indexed_roots = []
    for index, entry in enumerate(entries):
        case_id = "link_orbit_%03d" % index
        expected_root = "roots/%s.units" % case_id
        if entry.get("root") != expected_root:
            fail("%s: root path mismatch" % case_id)
        root_path = safe_path(production, entry["root"], case_id + " root")
        regular(root_path, case_id + " root", production)
        root_raw = root_path.read_bytes()
        if (
            entry.get("root_bytes") != len(root_raw)
            or entry.get("root_sha256") != sha(root_raw)
        ):
            fail("%s: root byte identity mismatch" % case_id)
        lines = root_raw.decode("ascii").splitlines()
        if len(lines) != 210:
            fail("%s: root must contain exactly 210 clauses" % case_id)
        units = []
        for line in lines:
            fields = line.split()
            if len(fields) != 2 or fields[1] != "0":
                fail("%s: malformed unit clause" % case_id)
            try:
                literal = int(fields[0])
            except ValueError:
                fail("%s: noninteger unit literal" % case_id)
            if literal == 0:
                fail("%s: zero unit literal" % case_id)
            units.append(literal)
        if units != entry.get("signed_root_units"):
            fail("%s: signed unit list mismatch" % case_id)
        if [abs(literal) for literal in units] != root_order:
            fail("%s: root does not set all 210 variables exactly once" % case_id)
        positives = [literal for literal in units if literal > 0]
        negatives = [literal for literal in units if literal < 0]
        if (
            len(positives) != 9
            or len(negatives) != 201
            or entry.get("positive_units") != 9
            or entry.get("negative_units") != 201
            or positives != entry.get("selected_global_variables")
        ):
            fail("%s: 9-positive/201-negative partition mismatch" % case_id)
        local = entry.get("local_block_indices")
        if (
            not isinstance(local, list)
            or len(local) != 9
            or len(set(local)) != 9
            or local != sorted(local)
            or any(not isinstance(value, int) or value < 0 or value >= 210 for value in local)
        ):
            fail("%s: local representative mismatch" % case_id)
        derived_representative_lines.append(
            " ".join(str(value) for value in local) + " \n"
        )
        case_raw = b"p cnf 122519 356617\n" + body + root_raw
        if (
            entry.get("case_variables") != 122_519
            or entry.get("case_clauses") != 356_617
            or entry.get("case_bytes") != len(case_raw)
            or entry.get("case_cnf_sha256") != sha(case_raw)
        ):
            fail("%s: reconstructed CNF identity mismatch" % case_id)
        indexed_roots.append(
            {
                "path": entry["root"],
                "bytes": entry["root_bytes"],
                "sha256": entry["root_sha256"],
            }
        )
    if manifest.get("root_index_sha256") != sha(canonical(indexed_roots)):
        fail("production root-index logical identity mismatch")

    representatives = manifest.get("representatives")
    if not isinstance(representatives, dict):
        fail("production representatives metadata missing")
    reps_path = safe_path(
        production, representatives.get("path"), "representatives"
    )
    regular(reps_path, "representatives", production)
    reps_raw = reps_path.read_bytes()
    derived = "".join(derived_representative_lines).encode("ascii")
    if reps_raw != derived:
        fail("stored representatives differ from production entries")
    if (
        representatives.get("count") != EXPECTED_CASES
        or representatives.get("bytes") != len(reps_raw)
        or representatives.get("sha256") != sha(reps_raw)
        or sha(reps_raw) != EXPECTED_REPRESENTATIVES_SHA256
    ):
        fail("stored representatives identity mismatch")
    return manifest, body, reps_path


def run_classification_check(classification: Path, reps: Path) -> None:
    verify_component_sums(
        classification,
        "classification component",
        EXPECTED_CLASSIFICATION_SHA256SUMS,
    )
    verifier = classification / "verify_frozen_classification.py"
    regular(verifier, "classification verifier", classification)
    checked = subprocess.run(
        [
            sys.executable,
            "-S",
            str(verifier),
            "--candidate-representatives",
            str(reps),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=900,
    )
    output_lines = [
        line.strip() for line in checked.stdout.splitlines() if line.strip()
    ]
    if (
        checked.returncode != 0
        or not output_lines
        or output_lines[-1] != EXPECTED_CLASSIFICATION_PASS
    ):
        fail(
            "classification replay failed: %s"
            % (checked.stderr[-1000:] or checked.stdout[-1000:])
        )


def load_receipts(
    proof: Path,
    production_manifest: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    verify_component_sums(proof)
    aggregate_path = proof / "aggregate.json"
    regular(aggregate_path, "proof aggregate", proof)
    if file_sha(aggregate_path) != EXPECTED_AGGREGATE_FILE_SHA256:
        fail("proof aggregate file SHA-256 mismatch")
    aggregate = strict_json(aggregate_path)
    verify_self_hash(
        aggregate,
        "aggregate_sha256",
        EXPECTED_AGGREGATE_SHA256,
        "proof aggregate",
    )
    if (
        aggregate.get("source_manifest_sha256")
        != production_manifest["manifest_sha256"]
        or aggregate.get("source_manifest_file_sha256")
        != EXPECTED_PRODUCTION_MANIFEST_FILE_SHA256
        or aggregate.get("case_count") != EXPECTED_CASES
        or aggregate.get("verified_unsat_count") != EXPECTED_CASES
    ):
        fail("proof aggregate production/count binding mismatch")
    if aggregate.get("tools") != EXPECTED_HISTORICAL_TOOLS:
        fail("proof aggregate historical tool identity mismatch")

    case_ids = ["link_orbit_%03d" % index for index in range(EXPECTED_CASES)]
    exact_directory_files(
        proof / "receipts",
        [case_id + ".json" for case_id in case_ids],
        "receipt directory",
    )
    exact_directory_files(
        proof / "logs",
        [
            "%s.%s.log" % (case_id, kind)
            for case_id in case_ids
            for kind in LOG_KINDS
        ],
        "log directory",
    )
    identities = aggregate.get("receipt_identities")
    if (
        not isinstance(identities, list)
        or len(identities) != EXPECTED_CASES
        or [identity.get("case_id") for identity in identities] != case_ids
    ):
        fail("aggregate receipt-identity exact set/order mismatch")

    receipts = []
    for index, (identity, entry) in enumerate(
        zip(identities, production_manifest["entries"])
    ):
        case_id = case_ids[index]
        receipt_path = proof / "receipts" / (case_id + ".json")
        receipt = strict_json(receipt_path)
        verify_self_hash(receipt, "receipt_sha256", identity.get("receipt_sha256"), case_id)
        if (
            receipt.get("model_version") != "c12-fixed-link-proof-artifacts-v1"
            or receipt.get("source_manifest_sha256")
            != production_manifest["manifest_sha256"]
            or receipt.get("case_id") != case_id
            or receipt.get("case_index") != index
            or receipt.get("case_cnf_sha256") != entry["case_cnf_sha256"]
            or receipt.get("root_sha256") != entry["root_sha256"]
            or receipt.get("status") != "VERIFIED_UNSAT"
        ):
            fail("%s: receipt production identity mismatch" % case_id)
        if (
            identity.get("case_cnf_sha256") != receipt["case_cnf_sha256"]
            or identity.get("drat_raw_sha256")
            != receipt.get("drat", {}).get("raw_sha256")
            or identity.get("lrat_raw_sha256")
            != receipt.get("lrat", {}).get("raw_sha256")
        ):
            fail("%s: aggregate receipt digest mismatch" % case_id)
        for kind, marker in LOG_KINDS.items():
            record = receipt.get("logs", {}).get(kind)
            if not isinstance(record, dict):
                fail("%s: missing %s log record" % (case_id, kind))
            expected_path = "logs/%s.%s.log" % (case_id, kind)
            if record.get("path") != expected_path or record.get("success_marker") != marker:
                fail("%s: %s log path/marker mismatch" % (case_id, kind))
            log_path = safe_path(proof, record["path"], case_id + " " + kind)
            regular(log_path, case_id + " " + kind + " log", proof)
            raw = log_path.read_bytes()
            if (
                record.get("bytes") != len(raw)
                or record.get("sha256") != sha(raw)
                or marker not in [line.strip() for line in raw.decode("utf-8").splitlines()]
            ):
                fail("%s: %s log identity/marker mismatch" % (case_id, kind))
        for kind, directory in (("drat", "proofs"), ("lrat", "lrat")):
            artifact = receipt.get(kind)
            expected_path = "%s/%s.%s.zst" % (directory, case_id, kind)
            if (
                not isinstance(artifact, dict)
                or artifact.get("compressed_path") != expected_path
                or not isinstance(artifact.get("compressed_bytes"), int)
                or artifact["compressed_bytes"] <= 0
                or not isinstance(artifact.get("raw_bytes"), int)
                or artifact["raw_bytes"] <= 0
                or not isinstance(artifact.get("compressed_sha256"), str)
                or len(artifact["compressed_sha256"]) != 64
                or not isinstance(artifact.get("raw_sha256"), str)
                or len(artifact["raw_sha256"]) != 64
            ):
                fail("%s: %s artifact schema/path mismatch" % (case_id, kind))
        receipts.append(receipt)

    total_fields = (
        ("drat", "raw_bytes", "total_raw_drat_bytes"),
        ("lrat", "raw_bytes", "total_raw_lrat_bytes"),
        ("drat", "compressed_bytes", "total_compressed_drat_bytes"),
        ("lrat", "compressed_bytes", "total_compressed_lrat_bytes"),
    )
    for kind, field, aggregate_field in total_fields:
        actual = sum(receipt[kind][field] for receipt in receipts)
        if aggregate.get(aggregate_field) != actual:
            fail("aggregate %s mismatch" % aggregate_field)
    return aggregate, receipts


def load_release_assets(
    path: Path,
    aggregate: Dict[str, Any],
    receipts: List[Dict[str, Any]],
) -> Dict[str, Any]:
    regular(path, "release-assets manifest")
    if file_sha(path) != EXPECTED_RELEASE_ASSETS_FILE_SHA256:
        fail("release-assets manifest file SHA-256 mismatch")
    assets = strict_json(path)
    verify_self_hash(
        assets,
        "release_assets_sha256",
        EXPECTED_RELEASE_ASSETS_SHA256,
        "release-assets manifest",
    )
    if (
        assets.get("proof_aggregate_sha256") != aggregate["aggregate_sha256"]
        or assets.get("proof_aggregate_file_sha256") != EXPECTED_AGGREGATE_FILE_SHA256
        or assets.get("source_manifest_sha256")
        != aggregate["source_manifest_sha256"]
        or assets.get("case_count") != EXPECTED_CASES
    ):
        fail("release-assets aggregate/count binding mismatch")
    for kind, expected_sha in (
        ("drat", EXPECTED_DRAT_ARCHIVE_SHA256),
        ("lrat", EXPECTED_LRAT_ARCHIVE_SHA256),
    ):
        archive = assets.get("archives", {}).get(kind)
        if (
            not isinstance(archive, dict)
            or archive.get("sha256") != expected_sha
            or archive.get("member_count") != EXPECTED_CASES
            or not isinstance(archive.get("members"), list)
            or len(archive["members"]) != EXPECTED_CASES
        ):
            fail("%s release archive metadata mismatch" % kind)
        expected_members = []
        for receipt in receipts:
            artifact = receipt[kind]
            expected_members.append(
                {
                    "path": artifact["compressed_path"],
                    "bytes": artifact["compressed_bytes"],
                    "sha256": artifact["compressed_sha256"],
                    "raw_bytes": artifact["raw_bytes"],
                    "raw_sha256": artifact["raw_sha256"],
                }
            )
        if archive["members"] != expected_members:
            fail("%s release member list differs from receipts" % kind)
        if archive.get("member_index_sha256") != sha(canonical(expected_members)):
            fail("%s release member-index logical hash mismatch" % kind)
    return assets


def validate_tar_metadata(
    archive_path: Path,
    record: Dict[str, Any],
) -> tarfile.TarFile:
    regular(archive_path, "release archive")
    if (
        archive_path.stat().st_size != record["bytes"]
        or file_sha(archive_path) != record["sha256"]
    ):
        fail("%s: release archive byte identity mismatch" % archive_path)
    try:
        archive = tarfile.open(archive_path, mode="r:")
    except tarfile.TarError as error:
        fail("%s: invalid uncompressed tar: %s" % (archive_path, error))
    members = archive.getmembers()
    expected = record["members"]
    if len(members) != len(expected):
        archive.close()
        fail("%s: archive member count mismatch" % archive_path)
    for member, item in zip(members, expected):
        safe_relative(member.name, "tar member")
        if (
            member.name != item["path"]
            or not member.isreg()
            or member.size != item["bytes"]
            or member.uid != 0
            or member.gid != 0
            or member.uname != ""
            or member.gname != ""
            or member.mtime != 0
            or member.mode != 0o644
        ):
            archive.close()
            fail("%s: noncanonical tar member %s" % (archive_path, member.name))
    return archive


def copy_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    expected: Dict[str, Any],
    destination: Path,
) -> None:
    extracted = archive.extractfile(member)
    if extracted is None:
        fail("%s: could not read tar member" % member.name)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    with temporary.open("wb") as output:
        h = hashlib.sha256()
        size = 0
        for chunk in iter(lambda: extracted.read(1 << 20), b""):
            size += len(chunk)
            h.update(chunk)
            output.write(chunk)
    os.replace(temporary, destination)
    if size != expected["bytes"] or h.hexdigest() != expected["sha256"]:
        fail("%s: compressed member identity mismatch" % member.name)


def decompress_identity(
    zstd: Path,
    compressed: Path,
    expected_bytes: int,
    expected_sha: str,
    destination: Optional[Path],
) -> None:
    command = [str(zstd), "-q", "-d", "-c", str(compressed)]
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.stdout is None:
        fail("zstd did not expose decompression stream")
    if destination is None:
        output_handle = None
    else:
        output_handle = destination.open("wb")
    try:
        size = 0
        h = hashlib.sha256()
        for chunk in iter(lambda: process.stdout.read(1 << 20), b""):
            size += len(chunk)
            h.update(chunk)
            if output_handle is not None:
                output_handle.write(chunk)
    finally:
        if output_handle is not None:
            output_handle.close()
    stderr = process.stderr.read() if process.stderr is not None else b""
    returncode = process.wait()
    if (
        returncode != 0
        or size != expected_bytes
        or h.hexdigest() != expected_sha
    ):
        fail(
            "%s: decompressed identity mismatch or zstd failure: %s"
            % (compressed, stderr.decode(errors="replace")[-500:])
        )


def materialize_case(body: bytes, root: Path, destination: Path, expected: str) -> None:
    raw = b"p cnf 122519 356617\n" + body + root.read_bytes()
    if sha(raw) != expected:
        fail("%s: materialized public CNF hash mismatch" % destination.name)
    destination.write_bytes(raw)


def run_checker(
    command: List[str], marker: str, label: str, environment: Optional[Dict[str, str]] = None
) -> None:
    try:
        checked = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=3_600,
            env=environment,
        )
    except subprocess.TimeoutExpired:
        fail("%s: checker timeout" % label)
    if checked.returncode != 0 or marker not in [
        line.strip() for line in checked.stdout.splitlines()
    ]:
        fail(
            "%s: checker failed: %s"
            % (label, (checked.stderr or checked.stdout)[-1000:])
        )


def verify_replay_checker_identities(
    lrat_check: Path,
    cake_lpr: Path,
) -> None:
    for binary, label, tool in (
        (lrat_check, "C LRAT checker", "lrat-check"),
        (cake_lpr, "CakeML LRAT checker", "cake_lpr"),
    ):
        regular(binary, label)
        expected = EXPECTED_HISTORICAL_TOOLS[tool]
        if (
            binary.stat().st_size != expected["bytes"]
            or file_sha(binary) != expected["sha256"]
        ):
            fail(
                "%s identity mismatch: full replay requires the exact "
                "hash-bound checker" % label
            )


def replay_archives(
    production: Path,
    manifest: Dict[str, Any],
    body: bytes,
    receipts: List[Dict[str, Any]],
    assets: Dict[str, Any],
    drat_path: Path,
    lrat_path: Path,
    zstd: Path,
    lrat_check: Path,
    cake_lpr: Path,
) -> None:
    regular(zstd, "zstd")
    verify_replay_checker_identities(lrat_check, cake_lpr)
    drat_record = assets["archives"]["drat"]
    lrat_record = assets["archives"]["lrat"]
    drat_tar = validate_tar_metadata(drat_path, drat_record)
    lrat_tar = validate_tar_metadata(lrat_path, lrat_record)
    try:
        with tempfile.TemporaryDirectory(prefix="c12-fixed-link-public-replay-") as temporary:
            work = Path(temporary)
            for index, receipt in enumerate(receipts):
                case_id = "link_orbit_%03d" % index
                compressed = work / "proof.zst"
                copy_member(
                    drat_tar,
                    drat_tar.getmembers()[index],
                    drat_record["members"][index],
                    compressed,
                )
                decompress_identity(
                    zstd,
                    compressed,
                    receipt["drat"]["raw_bytes"],
                    receipt["drat"]["raw_sha256"],
                    None,
                )
                compressed.unlink()

                copy_member(
                    lrat_tar,
                    lrat_tar.getmembers()[index],
                    lrat_record["members"][index],
                    compressed,
                )
                lrat = work / "proof.lrat"
                decompress_identity(
                    zstd,
                    compressed,
                    receipt["lrat"]["raw_bytes"],
                    receipt["lrat"]["raw_sha256"],
                    lrat,
                )
                compressed.unlink()
                root = safe_path(
                    production,
                    manifest["entries"][index]["root"],
                    case_id + " root",
                )
                cnf = work / "case.cnf"
                materialize_case(
                    body,
                    root,
                    cnf,
                    receipt["case_cnf_sha256"],
                )
                run_checker(
                    [str(lrat_check), str(cnf), str(lrat)],
                    "c VERIFIED",
                    case_id + " C LRAT replay",
                )
                environment = os.environ.copy()
                environment.update(
                    {"CML_HEAP_SIZE": "8192", "CML_STACK_SIZE": "2048"}
                )
                run_checker(
                    [
                        str(cake_lpr),
                        "--CML_HEAP_SIZE=8192",
                        "--CML_STACK_SIZE=2048",
                        str(cnf),
                        str(lrat),
                    ],
                    "s VERIFIED UNSAT",
                    case_id + " CakeML LRAT replay",
                    environment,
                )
                cnf.unlink()
                lrat.unlink()
                print(
                    "%d/%d %s C+CakeML VERIFIED"
                    % (index + 1, EXPECTED_CASES, case_id),
                    flush=True,
                )
    finally:
        drat_tar.close()
        lrat_tar.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--production-dir", type=Path)
    parser.add_argument("--proof-dir", type=Path)
    parser.add_argument("--classification-dir", type=Path)
    parser.add_argument("--release-assets", type=Path, required=True)
    parser.add_argument("--drat-archive", type=Path, required=True)
    parser.add_argument("--lrat-archive", type=Path, required=True)
    parser.add_argument("--lrat-check", type=Path, required=True)
    parser.add_argument("--cake-lpr", type=Path, required=True)
    parser.add_argument("--zstd", type=Path, required=True)
    parser.add_argument(
        "--skip-classification-replay",
        action="store_true",
        help="Only for targeted metadata tests; full verification must omit this.",
    )
    args = parser.parse_args()
    if not __debug__:
        fail("refusing optimized Python (-O)")
    root = checked_input_path(
        args.repo_root, "repository root", "directory"
    )
    production = checked_input_path(
        args.production_dir
        if args.production_dir
        else root / "certificates" / "fixed-link-campaign",
        "production directory",
        "directory",
    )
    proof = checked_input_path(
        args.proof_dir
        if args.proof_dir
        else root / "certificates" / "fixed-link-proof",
        "proof directory",
        "directory",
    )
    classification = checked_input_path(
        args.classification_dir
        if args.classification_dir
        else root / "certificates" / "fixed-link-classification",
        "classification directory",
        "directory",
    )
    release_assets = checked_input_path(
        args.release_assets, "release-assets manifest", "file"
    )
    drat_archive = checked_input_path(
        args.drat_archive, "DRAT release archive", "file"
    )
    lrat_archive = checked_input_path(
        args.lrat_archive, "LRAT release archive", "file"
    )
    zstd = checked_input_path(args.zstd, "zstd", "file")
    lrat_check = checked_input_path(
        args.lrat_check, "C LRAT checker", "file"
    )
    cake_lpr = checked_input_path(
        args.cake_lpr, "CakeML LRAT checker", "file"
    )
    base = root / "certificates" / "global" / "compact_campaign" / "global_base.cnf"
    manifest, body, reps = load_production(production, base)
    if not args.skip_classification_replay:
        run_classification_check(classification, reps)
    aggregate, receipts = load_receipts(proof, manifest)
    assets = load_release_assets(release_assets, aggregate, receipts)
    replay_archives(
        production,
        manifest,
        body,
        receipts,
        assets,
        drat_archive,
        lrat_archive,
        zstd,
        lrat_check,
        cake_lpr,
    )
    if args.skip_classification_replay:
        print(
            "PARTIAL ONLY: proof archives and all 266 C/CakeML LRAT replays "
            "passed, but the independent link classification was explicitly "
            "skipped. This is not a completion gate."
        )
    else:
        print(
            "PASS: independent link classification replayed; all 266 fixed-link "
            "CNFs reconstructed; raw DRAT/LRAT identities verified; every LRAT "
            "accepted by C and CakeML checkers."
        )
    print("C checker SHA-256: %s" % file_sha(lrat_check))
    print("CakeML checker SHA-256: %s" % file_sha(cake_lpr))
    return 3 if args.skip_classification_replay else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (VerificationError, OSError, ValueError, tarfile.TarError) as error:
        print("ERROR: %s" % error, file=sys.stderr)
        raise SystemExit(2)
