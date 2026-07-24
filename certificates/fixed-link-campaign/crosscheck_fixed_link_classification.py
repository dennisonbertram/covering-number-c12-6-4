#!/usr/bin/env python3
"""Byte-for-byte cross-check of the production and independent link artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
from typing import Any


if not __debug__:
    raise RuntimeError("this cross-check refuses Python -O")


class CrosscheckFailure(RuntimeError):
    """An independently produced artifact disagreed with the production one."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CrosscheckFailure(message)


def reject_constant(token: str) -> None:
    raise CrosscheckFailure(f"non-finite JSON number is forbidden: {token}")


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def load_json(path: pathlib.Path) -> Any:
    require(path.is_file() and not path.is_symlink(), f"unsafe JSON file: {path}")
    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_pairs,
        parse_constant=reject_constant,
    )


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_bytes(path: pathlib.Path) -> bytes:
    require(path.is_file() and not path.is_symlink(), f"unsafe regular file: {path}")
    return path.read_bytes()


def file_sha256(path: pathlib.Path) -> str:
    return sha256_bytes(file_bytes(path))


def resolve_relative(root: pathlib.Path, raw: Any) -> pathlib.Path:
    require(isinstance(raw, str) and raw, "relative path must be a nonempty string")
    relative = pathlib.PurePosixPath(raw)
    require(not relative.is_absolute(), f"absolute artifact path forbidden: {raw}")
    require(".." not in relative.parts, f"parent traversal forbidden: {raw}")
    candidate = root.joinpath(*relative.parts)
    resolved_root = root.resolve(strict=True)
    resolved = candidate.resolve(strict=True)
    require(resolved_root in resolved.parents, f"artifact path escaped root: {raw}")
    require(candidate.is_file() and not candidate.is_symlink(), f"unsafe artifact: {raw}")
    return candidate


def conceptual_representatives(entries: list[dict[str, Any]]) -> bytes:
    lines = []
    for entry in entries:
        indices = entry["local_block_indices"]
        require(
            isinstance(indices, list)
            and len(indices) == 9
            and indices == sorted(indices)
            and len(set(indices)) == 9,
            "invalid production representative indices",
        )
        lines.append("".join(f"{index} " for index in indices) + "\n")
    return "".join(lines).encode("ascii")


def conceptual_case_manifest(entries: list[dict[str, Any]]) -> bytes:
    records = []
    for case_index, entry in enumerate(entries):
        records.append(
            {
                "conceptual_cnf_sha256": entry["case_cnf_sha256"],
                "index": case_index,
                "negative_units": 201,
                "positive_units": 9,
                "selected_global_variables": entry["selected_global_variables"],
                "unit_count": 210,
            }
        )
    return (
        json.dumps(records, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--production-dir", required=True, type=pathlib.Path)
    parser.add_argument("--proof-manifest", required=True, type=pathlib.Path)
    parser.add_argument("--conceptual-report", required=True, type=pathlib.Path)
    parser.add_argument("--conceptual-representatives", type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    production_dir = args.production_dir.resolve(strict=True)
    require(
        production_dir.is_dir() and not args.production_dir.is_symlink(),
        "unsafe production directory",
    )
    production_manifest_path = production_dir / "manifest.json"
    production = load_json(production_manifest_path)
    proof_manifest_path = args.proof_manifest.resolve(strict=True)
    proof = load_json(proof_manifest_path)
    proof_dir = proof_manifest_path.parent
    conceptual = load_json(args.conceptual_report.resolve(strict=True))

    production_entries = production.get("entries")
    proof_entries = proof.get("entries")
    require(
        isinstance(production_entries, list)
        and isinstance(proof_entries, list)
        and len(production_entries) == len(proof_entries) == 266,
        "expected 266 entries in both manifests",
    )
    require(conceptual.get("result") == "PASS", "conceptual classifier did not PASS")
    require(
        production["compact_base"]["sha256"]
        == proof["base_cnf"]["sha256"]
        == conceptual["global_cases"]["base_sha256"],
        "compact-base hashes disagree",
    )
    require(
        production["compact_base"]["body_sha256"]
        == proof["base_cnf"]["body_sha256"],
        "compact-base body hashes disagree",
    )
    require(
        production["partition"]["orbit_count"]
        == proof["case_count"]
        == conceptual["orbits"]["orbit_count"]
        == 266,
        "case/orbit counts disagree",
    )
    require(
        production["partition"]["orbit_size_histogram"]
        == conceptual["orbits"]["orbit_size_histogram"],
        "orbit-size histograms disagree",
    )
    require(
        production["partition"]["stabilizer_order_histogram"]
        == conceptual["orbits"]["stabilizer_order_histogram"],
        "stabilizer histograms disagree",
    )
    require(
        production["partition"]["orbit_size_sum"]
        == conceptual["orbits"]["orbit_size_sum"]
        == 119700,
        "orbit unions disagree",
    )
    require(
        production["group"]["order"] == conceptual["orbits"]["group_order"] == 768,
        "group orders disagree",
    )

    root_stream = hashlib.sha256()
    case_stream = hashlib.sha256()
    for index, (ours, independent) in enumerate(
        zip(production_entries, proof_entries)
    ):
        require(ours["orbit_index"] == index, f"production index mismatch at {index}")
        require(independent["case_index"] == index, f"proof index mismatch at {index}")
        require(
            ours["local_block_indices"] == independent["local_block_indexes"],
            f"representative mismatch at {index}",
        )
        require(
            ours["selected_global_variables"]
            == independent["selected_global_block_variables"],
            f"selected global variables mismatch at {index}",
        )
        require(
            ours["case_cnf_sha256"] == independent["case_cnf_sha256"],
            f"case CNF hash mismatch at {index}",
        )
        require(
            ours["case_bytes"] == independent["case_cnf_bytes"],
            f"case byte count mismatch at {index}",
        )
        require(
            ours["root_bytes"] == independent["root_bytes"],
            f"root byte count mismatch at {index}",
        )
        require(
            ours["root_sha256"] == independent["root_sha256"],
            f"root manifest hash mismatch at {index}",
        )

        ours_root = resolve_relative(production_dir, ours["root"])
        independent_root = resolve_relative(proof_dir, independent["root"])
        ours_bytes = file_bytes(ours_root)
        independent_bytes = file_bytes(independent_root)
        require(ours_bytes == independent_bytes, f"root bytes mismatch at {index}")
        require(len(ours_bytes) == ours["root_bytes"], f"root size mismatch at {index}")
        require(
            sha256_bytes(ours_bytes) == ours["root_sha256"],
            f"root disk hash mismatch at {index}",
        )
        root_stream.update(index.to_bytes(4, "big"))
        root_stream.update(len(ours_bytes).to_bytes(8, "big"))
        root_stream.update(ours_bytes)
        case_stream.update(index.to_bytes(4, "big"))
        case_stream.update(bytes.fromhex(ours["case_cnf_sha256"]))

    representatives = conceptual_representatives(production_entries)
    representative_sha256 = sha256_bytes(representatives)
    production_representative_record = production["representatives"]
    require(
        isinstance(production_representative_record, dict)
        and production_representative_record["count"] == 266
        and production_representative_record["bytes"] == len(representatives)
        and production_representative_record["sha256"]
        == representative_sha256,
        "production representative record mismatch",
    )
    production_representative_path = resolve_relative(
        production_dir, production_representative_record["path"]
    )
    require(
        file_bytes(production_representative_path) == representatives,
        "production representative bytes mismatch",
    )
    require(
        representative_sha256
        == proof["representatives"]["sha256"]
        == conceptual["representatives"]["sha256"],
        "conceptual representative hash mismatch",
    )
    proof_representatives = pathlib.Path(proof["representatives"]["path"])
    require(
        proof_representatives.is_absolute(),
        "proof representative path must be absolute",
    )
    require(
        file_bytes(proof_representatives) == representatives,
        "proof representative bytes mismatch",
    )
    if args.conceptual_representatives is not None:
        require(
            file_bytes(args.conceptual_representatives.resolve(strict=True))
            == representatives,
            "supplied conceptual representative bytes mismatch",
        )

    case_manifest = conceptual_case_manifest(production_entries)
    case_manifest_sha256 = sha256_bytes(case_manifest)
    require(
        case_manifest_sha256
        == conceptual["global_cases"]["case_hash_manifest_sha256"],
        "conceptual case-hash manifest mismatch",
    )

    report: dict[str, Any] = {
        "case_hashes": {
            "all_266_equal": True,
            "conceptual_manifest_sha256": case_manifest_sha256,
            "indexed_hash_stream_sha256": case_stream.hexdigest(),
        },
        "counts": {
            "cases": 266,
            "group_order": 768,
            "orbit_union": 119700,
        },
        "inputs": {
            "conceptual_report_sha256": file_sha256(
                args.conceptual_report.resolve(strict=True)
            ),
            "production_manifest_file_sha256": file_sha256(
                production_manifest_path
            ),
            "production_manifest_logical_sha256": production["manifest_sha256"],
            "proof_manifest_file_sha256": file_sha256(proof_manifest_path),
            "proof_manifest_logical_sha256": proof["manifest_sha256"],
        },
        "representatives": {
            "all_266_equal": True,
            "conceptual_text_sha256": representative_sha256,
            "production_stored_byte_equal": True,
        },
        "result": "PASS",
        "roots": {
            "all_266_byte_equal": True,
            "indexed_byte_stream_sha256": root_stream.hexdigest(),
        },
        "source_sha256": file_sha256(pathlib.Path(__file__).resolve(strict=True)),
    }
    logical = sha256_bytes(
        json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    report["logical_sha256"] = logical
    output = args.output
    require(not output.is_symlink(), "output must not be a symbolic link")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (CrosscheckFailure, OSError, ValueError, TypeError) as error:
        print(f"CROSSCHECK FAILED: {error}", file=sys.stderr)
        raise SystemExit(1)
