#!/usr/bin/env python3
"""Create provenance-bound portable variants of frozen suite manifests."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Sequence


SOURCE_IDENTITIES = {
    "ordinary_profile_refinements": {
        "file_sha256": (
            "7521a231ba85249d2afaf05a77995ecd424a5d29a8136ea2e141b387e68426f4"
        ),
        "manifest_sha256": (
            "f5066fcf1b978b5e967cf921d0d3dbeb7ad97c4f10d707cbc06cdb89bd179c0e"
        ),
        "base_path": "../global_base.cnf",
        "parent_path": "../manifest.json",
    },
    "h0_profiles": {
        "file_sha256": (
            "009026d3ed3c27b3ffbf518f645016581bab848b5a5a21ffbaa60f25916f1d20"
        ),
        "manifest_sha256": (
            "fad8acff6636457a1227f1c99ba94ba50e341084bad8bc7f74426bba779fa1e9"
        ),
        "base_path": "../global_base.cnf",
    },
    "h1_profiles": {
        "file_sha256": (
            "4a697492d0dd293584ea164fa1ea27ab93cb69895781b3e6138aa1667caa9bd8"
        ),
        "manifest_sha256": (
            "58a262664267ba87cf8c7c37ec7e7739c094beb3a7409189c7268dff4f09c3b8"
        ),
        "base_path": "../global_base.cnf",
    },
}
PARENT_MANIFEST_FILE_SHA256 = (
    "1808957c797ac914f3954d07b066a1d05c9d56a201a1c441a4cd5efe312a2abb"
)
PARENT_MANIFEST_SHA256 = (
    "4b3ea887dcb05312b6ee82d10988bc5b0faf9d61c9a1fec292114559ff259835"
)


class PortableManifestError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise PortableManifestError(message)


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
    except PortableManifestError:
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


def portable_suite_manifest(
    source_path: Path, suite: str
) -> dict[str, Any]:
    identity = SOURCE_IDENTITIES[suite]
    if file_sha(source_path) != identity["file_sha256"]:
        fail(f"{source_path}: frozen source file SHA-256 mismatch")
    source = strict_json(source_path)
    validate_self_hash(source, "manifest_sha256", str(source_path))
    if source["manifest_sha256"] != identity["manifest_sha256"]:
        fail(f"{source_path}: frozen logical manifest SHA-256 mismatch")
    core = {
        name: value
        for name, value in source.items()
        if name not in ("core_sha256", "manifest_sha256")
    }
    if source.get("core_sha256") != sha(canonical(core)):
        fail(f"{source_path}: frozen core_sha256 mismatch")

    portable = dict(source)
    portable["base"] = {
        **portable["base"],
        "path": identity["base_path"],
    }
    sanitized_fields = {"base.path": identity["base_path"]}
    if suite == "ordinary_profile_refinements":
        portable["parent_campaign"] = {
            **portable["parent_campaign"],
            "path": identity["parent_path"],
        }
        sanitized_fields["parent_campaign.path"] = identity[
            "parent_path"
        ]
    portable["portable_provenance"] = {
        "model_version": "c12-portable-suite-manifest-v1",
        "source_manifest_file_sha256": identity["file_sha256"],
        "source_manifest_sha256": identity["manifest_sha256"],
        "sanitized_fields": sanitized_fields,
    }
    portable_core = {
        name: value
        for name, value in portable.items()
        if name not in ("core_sha256", "manifest_sha256")
    }
    portable["core_sha256"] = sha(canonical(portable_core))
    portable_outer = {
        name: value
        for name, value in portable.items()
        if name != "manifest_sha256"
    }
    portable["manifest_sha256"] = sha(canonical(portable_outer))
    return portable


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def build(source_root: Path, destination: Path) -> dict[str, Any]:
    if destination.exists():
        fail(f"{destination}: destination already exists")
    parent_source = source_root / "manifest.json"
    if file_sha(parent_source) != PARENT_MANIFEST_FILE_SHA256:
        fail(f"{parent_source}: parent file SHA-256 mismatch")
    parent = strict_json(parent_source)
    validate_self_hash(parent, "manifest_sha256", str(parent_source))
    if parent.get("manifest_sha256") != PARENT_MANIFEST_SHA256:
        fail(f"{parent_source}: parent logical SHA-256 mismatch")
    destination.mkdir(parents=True)
    write_json(destination / "manifest.json", parent)

    suites = {}
    for suite in SOURCE_IDENTITIES:
        portable = portable_suite_manifest(
            source_root / suite / "manifest.json", suite
        )
        output = destination / suite / "manifest.json"
        write_json(output, portable)
        suites[suite] = {
            "path": str(output.relative_to(destination)),
            "bytes": output.stat().st_size,
            "file_sha256": file_sha(output),
            "manifest_sha256": portable["manifest_sha256"],
            "source_manifest_file_sha256": SOURCE_IDENTITIES[suite][
                "file_sha256"
            ],
            "source_manifest_sha256": SOURCE_IDENTITIES[suite][
                "manifest_sha256"
            ],
        }
    return {
        "model_version": "c12-portable-manifest-set-v1",
        "parent": {
            "path": "manifest.json",
            "bytes": (destination / "manifest.json").stat().st_size,
            "file_sha256": file_sha(destination / "manifest.json"),
            "manifest_sha256": parent["manifest_sha256"],
        },
        "suites": suites,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        result = build(
            arguments.source_root.resolve(),
            arguments.destination.resolve(),
        )
    except (
        PortableManifestError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
    ) as error:
        print(f"PORTABLE MANIFEST BUILD FAILED: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {"result": "PORTABLE MANIFEST BUILD PASSED", **result},
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
