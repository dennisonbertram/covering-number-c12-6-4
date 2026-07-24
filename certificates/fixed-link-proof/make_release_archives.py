#!/usr/bin/env python3
"""Create deterministic DRAT and LRAT release archives from the bound package."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Sequence, Tuple


EXPECTED_AGGREGATE_SHA256 = (
    "8735ea4aedb5d30fc1fa65ff289f4357bec14d354a993270a620254d30ff575a"
)
EXPECTED_CASES = 266


class ArchiveError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise ArchiveError(message)


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


def strict_json(path: Path) -> Any:
    def unique(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                fail("%s: duplicate JSON key %r" % (path, key))
            result[key] = value
        return result

    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=unique,
        parse_constant=lambda value: fail(
            "%s: invalid JSON constant %s" % (path, value)
        ),
    )


def safe_relative(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(
        part in ("", ".", "..") for part in path.parts
    ):
        fail("unsafe archive member path %r" % value)
    return path


def ensure_no_symlink_components(
    path: Path, stop: Optional[Path] = None
) -> None:
    current = path
    while True:
        if current.is_symlink():
            fail("%s: symlink path component rejected" % current)
        if stop is not None and current == stop:
            return
        if current.parent == current:
            if stop is not None:
                fail("%s: path escaped trusted root %s" % (path, stop))
            return
        current = current.parent


def checked_directory(value: Path, label: str, create: bool = False) -> Path:
    """Reject every symlink component before resolving a directory argument."""
    raw = Path(os.path.abspath(os.fspath(value)))
    ensure_no_symlink_components(raw)
    if create:
        raw.mkdir(parents=True, exist_ok=True)
        ensure_no_symlink_components(raw)
    if raw.is_symlink() or not raw.is_dir():
        fail("%s must be a regular non-symlink directory" % label)
    return raw.resolve()


def regular(path: Path, root: Optional[Path] = None) -> None:
    if root is not None:
        ensure_no_symlink_components(path, root)
    if not path.is_file() or path.is_symlink():
        fail("%s is not a regular non-symlink file" % path)


def create_archive(
    package: Path,
    output: Path,
    records: List[Dict[str, Any]],
) -> Dict[str, Any]:
    temporary = output.with_suffix(output.suffix + ".tmp")
    ensure_no_symlink_components(output, output.parent)
    ensure_no_symlink_components(temporary, output.parent)
    if output.is_symlink() or temporary.is_symlink():
        fail("%s: archive output symlink rejected" % output)
    if temporary.exists():
        regular(temporary, output.parent)
        temporary.unlink()
    with tarfile.open(
        temporary,
        mode="w",
        format=tarfile.USTAR_FORMAT,
        dereference=False,
    ) as archive:
        for record in records:
            relative = safe_relative(record["path"])
            source = package.joinpath(*relative.parts)
            regular(source, package)
            if (
                source.stat().st_size != record["bytes"]
                or file_sha(source) != record["sha256"]
            ):
                fail("%s: package artifact identity mismatch" % source)
            info = tarfile.TarInfo(str(relative))
            info.size = record["bytes"]
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = 0
            info.type = tarfile.REGTYPE
            with source.open("rb") as handle:
                archive.addfile(info, handle)
    os.replace(temporary, output)
    if output.stat().st_size >= 2_000_000_000:
        fail("%s exceeds the 2 GB release-asset limit" % output)
    member_index_sha = sha(canonical(records))
    return {
        "path": output.name,
        "format": "deterministic-ustar-of-per-case-zstd-files",
        "bytes": output.stat().st_size,
        "sha256": file_sha(output),
        "member_count": len(records),
        "member_index_sha256": member_index_sha,
        "members": records,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not __debug__:
        fail("refusing optimized Python")
    package = checked_directory(args.package, "package")
    output = checked_directory(args.output, "output", create=True)
    aggregate_path = package / "aggregate.json"
    regular(aggregate_path, package)
    aggregate = strict_json(aggregate_path)
    aggregate_sha = aggregate.pop("aggregate_sha256", None)
    if (
        aggregate_sha != sha(canonical(aggregate))
        or aggregate_sha != EXPECTED_AGGREGATE_SHA256
    ):
        fail("aggregate logical identity mismatch")
    aggregate["aggregate_sha256"] = aggregate_sha
    identities = aggregate.get("receipt_identities")
    if (
        not isinstance(identities, list)
        or len(identities) != EXPECTED_CASES
        or [item.get("case_id") for item in identities]
        != ["link_orbit_%03d" % index for index in range(EXPECTED_CASES)]
    ):
        fail("aggregate exact case set mismatch")

    archive_records: Dict[str, List[Dict[str, Any]]] = {
        "drat": [],
        "lrat": [],
    }
    for identity in identities:
        receipt_path = package / "receipts" / (identity["case_id"] + ".json")
        regular(receipt_path, package)
        receipt = strict_json(receipt_path)
        receipt_sha = receipt.pop("receipt_sha256", None)
        if (
            receipt_sha != sha(canonical(receipt))
            or receipt_sha != identity["receipt_sha256"]
        ):
            fail("%s: receipt logical identity mismatch" % receipt_path)
        receipt["receipt_sha256"] = receipt_sha
        for kind in ("drat", "lrat"):
            artifact = receipt[kind]
            relative = safe_relative(artifact["compressed_path"])
            expected_parent = "proofs" if kind == "drat" else "lrat"
            if relative.parent != PurePosixPath(expected_parent):
                fail("%s: %s path is outside its allowlisted directory" % (identity["case_id"], kind))
            archive_records[kind].append(
                {
                    "path": str(relative),
                    "bytes": artifact["compressed_bytes"],
                    "sha256": artifact["compressed_sha256"],
                    "raw_bytes": artifact["raw_bytes"],
                    "raw_sha256": artifact["raw_sha256"],
                }
            )

    for kind in ("drat", "lrat"):
        archive_records[kind].sort(key=lambda item: item["path"])
        expected_paths = [
            ("%s/link_orbit_%03d.%s.zst" % (
                "proofs" if kind == "drat" else "lrat",
                index,
                kind,
            ))
            for index in range(EXPECTED_CASES)
        ]
        if [item["path"] for item in archive_records[kind]] != expected_paths:
            fail("%s member exact-case set mismatch" % kind)

    assets = {
        "model_version": "c12-fixed-link-release-assets-v1",
        "proof_aggregate_sha256": aggregate_sha,
        "proof_aggregate_file_sha256": file_sha(aggregate_path),
        "source_manifest_sha256": aggregate["source_manifest_sha256"],
        "case_count": EXPECTED_CASES,
        "archives": {
            "drat": create_archive(
                package,
                output / "c12-fixed-link-drat.tar",
                archive_records["drat"],
            ),
            "lrat": create_archive(
                package,
                output / "c12-fixed-link-lrat.tar",
                archive_records["lrat"],
            ),
        },
    }
    assets["release_assets_sha256"] = sha(canonical(assets))
    manifest_path = output / "release-assets.json"
    temporary = manifest_path.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(assets, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, manifest_path)
    print(
        "PASS release-assets=%s drat=%s lrat=%s"
        % (
            assets["release_assets_sha256"],
            assets["archives"]["drat"]["sha256"],
            assets["archives"]["lrat"]["sha256"],
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ArchiveError, ValueError, OSError) as error:
        print("ERROR: %s" % error, file=sys.stderr)
        raise SystemExit(2)
