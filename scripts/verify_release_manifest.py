#!/usr/bin/env python3
"""Fail-closed verification of repository release-component manifests."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Sequence


if not __debug__:
    raise RuntimeError(
        "this release verifier refuses Python -O because checks must remain enabled"
    )


REPO = Path(__file__).resolve().parents[1]
INDEX = REPO / "manifests" / "release-components.json"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
MANIFEST_LINE = re.compile(r"([0-9a-f]{64})  (.+)\Z")
EXPECTED_COMPONENT_MANIFESTS = {
    "upper-bound-witness": "data/SHA256SUMS",
    "local-degree-lemma": "certificates/local/SHA256SUMS",
    "functional-global-reduction": "certificates/functional/SHA256SUMS",
    "compact-encoder-audit": "certificates/compact-encoder-audit/SHA256SUMS",
    "compact-leaf-extension-audit": (
        "certificates/compact-leaf-extension-audit/SHA256SUMS"
    ),
    "checker-toolchain": "toolchain/SHA256SUMS",
    "fixed-link-classification": (
        "certificates/fixed-link-classification/SHA256SUMS"
    ),
    "fixed-link-campaign": "certificates/fixed-link-campaign/SHA256SUMS",
    "fixed-link-proof": "certificates/fixed-link-proof/SHA256SUMS",
}


class ManifestFailure(RuntimeError):
    pass


def fail(message: str) -> None:
    raise ManifestFailure(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


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
    except ManifestFailure:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"{path}: invalid JSON: {error}")


def sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        fail(f"expected regular non-symlink file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inside_repo(path: Path, label: str) -> Path:
    if path.is_absolute():
        fail(f"{label}: absolute paths are forbidden")
    normalized = Path(os.path.abspath(REPO / path))
    try:
        normalized.relative_to(REPO)
    except ValueError:
        fail(f"{label}: path escapes the repository")
    reject_symlink_chain(normalized, label)
    return normalized


def reject_symlink_chain(path: Path, label: str) -> None:
    current = path
    while current != REPO.parent:
        if current.is_symlink():
            fail(f"{label}: symlink path component rejected: {current}")
        if current == REPO:
            return
        current = current.parent
    fail(f"{label}: path is not rooted in the repository")


def parse_checksum_manifest(path: Path) -> dict[Path, str]:
    reject_symlink_chain(path, str(path.relative_to(REPO)))
    if not path.is_file():
        fail(f"checksum manifest is missing: {path}")
    entries: dict[Path, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        fail(f"{path}: cannot read checksum manifest: {error}")
    require(lines, f"{path}: checksum manifest is empty")

    for number, line in enumerate(lines, start=1):
        match = MANIFEST_LINE.fullmatch(line)
        if match is None:
            fail(f"{path}:{number}: malformed SHA-256 line")
        expected, name = match.groups()
        require(name != "", f"{path}:{number}: empty file name")
        relative = Path(name)
        require(
            not relative.is_absolute(),
            f"{path}:{number}: absolute file name rejected",
        )
        candidate = Path(os.path.abspath(path.parent / relative))
        try:
            repo_relative = candidate.relative_to(REPO)
        except ValueError:
            fail(f"{path}:{number}: checksum path escapes the repository")
        reject_symlink_chain(candidate, str(repo_relative))
        require(
            candidate.is_file(),
            f"{path}:{number}: listed file is missing: {repo_relative}",
        )
        require(
            candidate not in entries,
            f"{path}:{number}: duplicate normalized path {repo_relative}",
        )
        actual = sha256(candidate)
        require(
            actual == expected,
            f"{repo_relative}: expected {expected}, got {actual}",
        )
        entries[candidate] = expected
    return entries


def verify_component(component: Any) -> tuple[str, str]:
    require(isinstance(component, dict), "component must be an object")
    expected_keys = {
        "description",
        "id",
        "manifest",
        "manifest_sha256",
        "required_when_complete",
        "status",
    }
    require(
        set(component) == expected_keys,
        f"component keys differ from schema: {sorted(component)}",
    )
    identifier = component["id"]
    status = component["status"]
    require(
        isinstance(identifier, str) and identifier,
        "component id must be a nonempty string",
    )
    require(
        identifier in EXPECTED_COMPONENT_MANIFESTS,
        f"unexpected component id: {identifier}",
    )
    require(
        isinstance(component["description"], str)
        and component["description"],
        f"{identifier}: description must be nonempty",
    )
    require(
        status in ("complete", "pending"),
        f"{identifier}: invalid status {status!r}",
    )
    require(
        component["manifest"] == EXPECTED_COMPONENT_MANIFESTS[identifier],
        f"{identifier}: component manifest path changed",
    )
    manifest_relative = Path(component["manifest"])
    manifest = inside_repo(manifest_relative, f"{identifier}.manifest")
    required = component["required_when_complete"]
    require(
        isinstance(required, list)
        and all(isinstance(item, str) and item for item in required),
        f"{identifier}: required_when_complete must be a string list",
    )

    if status == "pending":
        require(
            component["manifest_sha256"] is None,
            f"{identifier}: pending component must not pin a manifest hash",
        )
        return identifier, status

    expected_manifest_sha = component["manifest_sha256"]
    require(
        isinstance(expected_manifest_sha, str)
        and HEX64.fullmatch(expected_manifest_sha) is not None,
        f"{identifier}: invalid manifest_sha256",
    )
    require(
        sha256(manifest) == expected_manifest_sha,
        f"{identifier}: component manifest hash changed",
    )
    entries = parse_checksum_manifest(manifest)
    for name in required:
        required_path = inside_repo(Path(name), f"{identifier}.required")
        require(
            required_path in entries,
            f"{identifier}: required artifact is not checksum-pinned: {name}",
        )
    return identifier, status


def main() -> int:
    try:
        reject_symlink_chain(INDEX, "manifests/release-components.json")
        index = strict_json(INDEX)
        require(
            isinstance(index, dict)
            and set(index) == {"components", "release_state", "schema_version"},
            "release index keys differ from schema",
        )
        require(index["schema_version"] == 1, "unsupported manifest schema")
        require(
            index["release_state"] in ("complete", "pending"),
            "invalid release_state",
        )
        require(
            isinstance(index["components"], list) and index["components"],
            "components must be a nonempty list",
        )

        results = [verify_component(item) for item in index["components"]]
        identifiers = [identifier for identifier, _status in results]
        require(
            len(set(identifiers)) == len(identifiers),
            "duplicate component id",
        )
        require(
            set(identifiers) == set(EXPECTED_COMPONENT_MANIFESTS),
            "release index omits or adds a required component",
        )
        pending = [
            identifier
            for identifier, status in results
            if status == "pending"
        ]
        expected_state = "pending" if pending else "complete"
        require(
            index["release_state"] == expected_state,
            "release_state disagrees with component statuses",
        )

        print(f"RELEASE MANIFESTS VERIFIED: {len(results)} components")
        if pending:
            print("RELEASE PENDING: " + ", ".join(pending))
            return 2
        print("RELEASE MANIFEST STATE: COMPLETE")
        return 0
    except (ManifestFailure, OSError, TypeError, ValueError) as error:
        print(f"RELEASE MANIFEST VERIFICATION FAILED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
