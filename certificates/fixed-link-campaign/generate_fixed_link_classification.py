#!/usr/bin/env python3
"""Generate the exact 266-orbit fixed-link partition for C(12,6,4).

Pure standard library.  The local points are
    [1,3,4,5,6,7,8,9,10,11]
after deleting the fixed nonmatching pair P={0,2}.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
import struct
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Sequence, Set, Tuple


if not __debug__:
    raise RuntimeError("refusing Python -O: fail-closed checks must remain active")


MODEL = "c12-fixed-link-classification-v1"
EXPECTED_BASE_SHA256 = (
    "637d9326388f77f933f3d066cd762d8c0ac4b2df0d2260d688e031d55959e7f0"
)
EXPECTED_BASE_BODY_SHA256 = (
    "6a1a2eb2843a4ddcf9138c5a85aaeccd2950b3e099e0ab8a26ce9fc815ab0cc5"
)
EXPECTED_REPRESENTATIVES_SHA256 = (
    "369a844c4590d435fc24f82424a0775d51ce326d243aaf740d025c52c81d652b"
)
EXPECTED_BASE_HEADER = b"p cnf 122519 356407"
BASE_VARIABLES = 122_519
BASE_CLAUSES = 356_407
ROOT_CLAUSES = 210
CASE_CLAUSES = BASE_CLAUSES + ROOT_CLAUSES

LOCAL_POINTS = tuple(range(10))
LOCAL_TO_GLOBAL = (1, 3, 4, 5, 6, 7, 8, 9, 10, 11)
FIXED_PAIR = (0, 2)
LOCAL_PAIRS = tuple(itertools.combinations(LOCAL_POINTS, 2))
LOCAL_PAIR_INDEX = {pair: index for index, pair in enumerate(LOCAL_PAIRS)}
LOCAL_BLOCKS = tuple(itertools.combinations(LOCAL_POINTS, 4))
LOCAL_BLOCK_INDEX = {block: index for index, block in enumerate(LOCAL_BLOCKS)}
GLOBAL_BLOCKS = tuple(itertools.combinations(range(12), 6))
GLOBAL_BLOCK_INDEX = {
    block: index + 1 for index, block in enumerate(GLOBAL_BLOCKS)
}
ALL_LOCAL_PAIR_MASK = (1 << len(LOCAL_PAIRS)) - 1
WORD_MASK = (1 << 64) - 1


class GenerationError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise GenerationError(message)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(raw)
    os.replace(temporary, path)


def popcount(value: int) -> int:
    return bin(value).count("1")


def block_pair_mask(block: Sequence[int]) -> int:
    return sum(
        1 << LOCAL_PAIR_INDEX[tuple(sorted(pair))]
        for pair in itertools.combinations(block, 2)
    )


LOCAL_BLOCK_PAIR_MASKS = tuple(
    block_pair_mask(block) for block in LOCAL_BLOCKS
)


def cover_words(cover: int) -> Tuple[int, int, int, int]:
    return tuple(
        (cover >> (64 * index)) & WORD_MASK for index in range(4)
    )  # type: ignore[return-value]


def cover_bytes(cover: int) -> bytes:
    return struct.pack("<QQQQ", *cover_words(cover))


def cover_digest(covers: Iterable[int]) -> str:
    digest = hashlib.sha256()
    for cover in sorted(covers, key=cover_words):
        digest.update(cover_bytes(cover))
    return digest.hexdigest()


def selected_indices(cover: int) -> Tuple[int, ...]:
    result = []
    remaining = cover
    while remaining:
        bit = remaining & -remaining
        result.append(bit.bit_length() - 1)
        remaining -= bit
    return tuple(result)


def partitions_into_triples(
    items: Sequence[int], groups: int
) -> Iterator[Tuple[Tuple[int, int, int], ...]]:
    """Enumerate unordered partitions, fixing the least remaining item."""
    values = tuple(items)
    if groups == 0:
        if not values:
            yield ()
        return
    if len(values) != 3 * groups:
        return
    first = values[0]
    for pair in itertools.combinations(values[1:], 2):
        group = (first,) + pair
        rest = tuple(value for value in values if value not in group)
        for tail in partitions_into_triples(rest, groups - 1):
            yield (group,) + tail


def validate_cover(cover: int, expected_degrees: Sequence[int]) -> None:
    indices = selected_indices(cover)
    if len(indices) != sum(expected_degrees) // 4:
        fail("cover block count does not match its degree target")
    degrees = [0] * 10
    covered = 0
    for index in indices:
        if not 0 <= index < len(LOCAL_BLOCKS):
            fail("local block index out of range")
        covered |= LOCAL_BLOCK_PAIR_MASKS[index]
        for point in LOCAL_BLOCKS[index]:
            degrees[point] += 1
    if covered != ALL_LOCAL_PAIR_MASK:
        fail("emitted local family does not cover every pair")
    if tuple(degrees) != tuple(expected_degrees):
        fail("emitted local family has the wrong point degrees")


def enumerate_degree_target(
    target: Tuple[int, ...]
) -> Iterator[int]:
    """Enumerate covers with one fixed degree vector, once each.

    Every degree-three point occurs in three blocks whose other triples
    partition its nine neighbours.  Start with the least such point, then
    repeatedly finish the least unfinished degree-three point.  Once those
    points are saturated, only a tiny high-point completion remains.
    """
    if len(target) != 10 or any(value < 3 for value in target):
        fail("invalid degree target")
    block_count, remainder = divmod(sum(target), 4)
    if remainder or block_count not in (8, 9):
        fail("degree target has invalid total")
    low_points = tuple(
        point for point, degree in enumerate(target) if degree == 3
    )
    if not low_points:
        fail("degree target has no degree-three point")
    pivot = low_points[0]
    other_points = tuple(point for point in LOCAL_POINTS if point != pivot)

    def recurse(
        covered: int,
        remaining_degrees: List[int],
        selected: int,
        depth: int,
    ) -> Iterator[int]:
        slots = block_count - depth
        if (
            slots < 0
            or sum(remaining_degrees) != 4 * slots
            or any(
                degree < 0 or degree > slots
                for degree in remaining_degrees
            )
        ):
            return

        # A degree-three point has exactly nine incident pair occurrences.
        # Any repeated neighbour would leave another neighbour uncovered.
        for point in low_points:
            uncovered_neighbours = sum(
                1
                for other in LOCAL_POINTS
                if other != point
                and not (
                    covered
                    >> LOCAL_PAIR_INDEX[tuple(sorted((point, other)))]
                    & 1
                )
            )
            if uncovered_neighbours != 3 * remaining_degrees[point]:
                return

        if depth == block_count:
            if (
                covered == ALL_LOCAL_PAIR_MASK
                and not any(remaining_degrees)
            ):
                validate_cover(selected, target)
                yield selected
            return

        unfinished = next(
            (
                point
                for point in low_points
                if remaining_degrees[point] > 0
            ),
            None,
        )
        if unfinished is not None:
            neighbours = tuple(
                other
                for other in LOCAL_POINTS
                if other != unfinished
                and not (
                    covered
                    >> LOCAL_PAIR_INDEX[
                        tuple(sorted((unfinished, other)))
                    ]
                    & 1
                )
            )
            count = remaining_degrees[unfinished]
            for groups in partitions_into_triples(neighbours, count):
                additions: List[int] = []
                use = [0] * 10
                valid = True
                for group in groups:
                    block = tuple(sorted((unfinished,) + group))
                    index = LOCAL_BLOCK_INDEX[block]
                    if selected >> index & 1:
                        valid = False
                        break
                    additions.append(index)
                    for point in block:
                        use[point] += 1
                if (
                    not valid
                    or any(
                        use[point] > remaining_degrees[point]
                        for point in LOCAL_POINTS
                    )
                ):
                    continue
                new_remaining = list(remaining_degrees)
                new_selected = selected
                new_covered = covered
                for index in additions:
                    new_selected |= 1 << index
                    new_covered |= LOCAL_BLOCK_PAIR_MASKS[index]
                    for point in LOCAL_BLOCKS[index]:
                        new_remaining[point] -= 1
                yield from recurse(
                    new_covered,
                    new_remaining,
                    new_selected,
                    depth + len(additions),
                )
            return

        active = tuple(
            point
            for point in LOCAL_POINTS
            if remaining_degrees[point] > 0
        )
        available = tuple(
            LOCAL_BLOCK_INDEX[block]
            for block in itertools.combinations(active, 4)
            if all(remaining_degrees[point] > 0 for point in block)
            and not (selected >> LOCAL_BLOCK_INDEX[block] & 1)
        )
        for indices in itertools.combinations(available, slots):
            use = [0] * 10
            new_covered = covered
            new_selected = selected
            for index in indices:
                new_covered |= LOCAL_BLOCK_PAIR_MASKS[index]
                new_selected |= 1 << index
                for point in LOCAL_BLOCKS[index]:
                    use[point] += 1
            if (
                use == remaining_degrees
                and new_covered == ALL_LOCAL_PAIR_MASK
            ):
                validate_cover(new_selected, target)
                yield new_selected

    for partition in partitions_into_triples(other_points, 3):
        selected = 0
        covered = 0
        remaining_degrees = list(target)
        for group in partition:
            block = tuple(sorted((pivot,) + group))
            index = LOCAL_BLOCK_INDEX[block]
            selected |= 1 << index
            covered |= LOCAL_BLOCK_PAIR_MASKS[index]
            for point in block:
                remaining_degrees[point] -= 1
        yield from recurse(covered, remaining_degrees, selected, 3)


def enumerate_no_eight_cover() -> Dict[str, Any]:
    targets = []
    for high in LOCAL_POINTS:
        target = [3] * 10
        target[high] = 5
        targets.append(tuple(target))
    for high_pair in itertools.combinations(LOCAL_POINTS, 2):
        target = [3] * 10
        for point in high_pair:
            target[point] = 4
        targets.append(tuple(target))
    emitted = 0
    for target in targets:
        emitted += sum(1 for _ in enumerate_degree_target(target))
    if len(targets) != 55 or emitted != 0:
        fail("the independent eight-block exhaustion did not return zero")
    return {
        "degree_patterns": 55,
        "degree_pattern_families": ["one degree 5", "two degrees 4"],
        "emitted_covers": emitted,
    }


def enumerate_nine_covers() -> Tuple[Set[int], Dict[str, int]]:
    covers: Set[int] = set()
    by_low_set: Dict[str, int] = {}
    emissions = 0
    for low in itertools.combinations(LOCAL_POINTS, 4):
        target = tuple(3 if point in low else 4 for point in LOCAL_POINTS)
        count = 0
        for cover in enumerate_degree_target(target):
            emissions += 1
            count += 1
            if cover in covers:
                fail("duplicate nine-block cover emitted")
            covers.add(cover)
        by_low_set[",".join(map(str, low))] = count
    if (
        emissions != 359_100
        or len(covers) != 359_100
        or set(by_low_set.values()) != {1_710}
        or len(by_low_set) != 210
    ):
        fail("nine-block enumeration count or low-set histogram mismatch")
    return covers, by_low_set


def compose(left: Tuple[int, ...], right: Tuple[int, ...]) -> Tuple[int, ...]:
    return tuple(left[right[index]] for index in LOCAL_POINTS)


def direct_group() -> Tuple[Tuple[int, ...], ...]:
    group = set()
    for distinguished_swap in (0, 1):
        for pair_permutation in itertools.permutations(range(4)):
            for flips in range(16):
                image = [0] * 10
                image[0] = distinguished_swap
                image[1] = 1 - distinguished_swap
                for source_pair in range(4):
                    target_pair = pair_permutation[source_pair]
                    flip = flips >> source_pair & 1
                    for endpoint in (0, 1):
                        source = 2 + 2 * source_pair + endpoint
                        image[source] = (
                            2 + 2 * target_pair + (endpoint ^ flip)
                        )
                permutation = tuple(image)
                if tuple(sorted(permutation)) != LOCAL_POINTS:
                    fail("group construction emitted a non-permutation")
                group.add(permutation)
    if len(group) != 768:
        fail("direct Gamma construction does not have order 768")
    return tuple(sorted(group))


def action_tables(
    group: Sequence[Tuple[int, ...]]
) -> Tuple[Tuple[int, ...], ...]:
    tables = []
    for permutation in group:
        table = []
        for block in LOCAL_BLOCKS:
            image = tuple(sorted(permutation[point] for point in block))
            table.append(LOCAL_BLOCK_INDEX[image])
        if tuple(sorted(table)) != tuple(range(210)):
            fail("group element does not permute local blocks")
        tables.append(tuple(table))
    return tuple(tables)


def transform_cover(cover: int, table: Sequence[int]) -> int:
    image = 0
    for index in selected_indices(cover):
        image |= 1 << table[index]
    return image


def classify(
    admissible: Set[int],
    group: Sequence[Tuple[int, ...]],
    tables: Sequence[Sequence[int]],
) -> List[Dict[str, Any]]:
    unseen = set(admissible)
    records: List[Dict[str, Any]] = []
    for seed in sorted(admissible, key=cover_words):
        if seed not in unseen:
            continue
        orbit = {transform_cover(seed, table) for table in tables}
        if not orbit <= admissible:
            fail("Gamma image left the admissible universe")
        representative = min(orbit, key=cover_words)
        if representative != seed:
            fail("orbit traversal did not encounter its canonical minimum")
        stabilizer = sum(
            transform_cover(representative, table) == representative
            for table in tables
        )
        if (
            stabilizer * len(orbit) != len(group)
            or unseen.isdisjoint(orbit)
        ):
            fail("orbit-stabilizer or unseen-set check failed")
        unseen.difference_update(orbit)
        records.append(
            {
                "representative": representative,
                "orbit_size": len(orbit),
                "stabilizer_order": stabilizer,
                "orbit_member_sha256": cover_digest(orbit),
            }
        )
    if unseen or len(records) != 266:
        fail("admissible universe did not partition into 266 orbits")
    if sum(record["orbit_size"] for record in records) != 119_700:
        fail("orbit sizes do not sum to 119700")
    return records


def read_base(path: Path) -> Tuple[bytes, bytes]:
    if path.is_symlink() or not path.is_file():
        fail("compact base must be a regular non-symlink file")
    raw = path.read_bytes()
    if sha256(raw) != EXPECTED_BASE_SHA256:
        fail("compact base full SHA-256 mismatch")
    try:
        header, body = raw.split(b"\n", 1)
    except ValueError:
        fail("compact base has no DIMACS body")
    if (
        header != EXPECTED_BASE_HEADER
        or sha256(body) != EXPECTED_BASE_BODY_SHA256
    ):
        fail("compact base header or body SHA-256 mismatch")
    return raw, body


def source_record(path: Path) -> Dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        fail("source file missing or symlinked")
    return {
        "path": path.name,
        "bytes": path.stat().st_size,
        "sha256": file_sha256(path),
    }


def build(output: Path, base_path: Path) -> Dict[str, Any]:
    _, base_body = read_base(base_path)
    no_eight = enumerate_no_eight_cover()
    all_covers, low_histogram = enumerate_nine_covers()
    admissible = {
        cover
        for cover in all_covers
        if sum(0 in LOCAL_BLOCKS[index] for index in selected_indices(cover))
        == 4
        and sum(
            1 in LOCAL_BLOCKS[index] for index in selected_indices(cover)
        )
        == 4
    }
    if len(admissible) != 119_700:
        fail("distinguished-partner degree-four filter mismatch")

    group = direct_group()
    tables = action_tables(group)
    records = classify(admissible, group, tables)

    local_to_variable = []
    containing_order = []
    for local_index, local_block in enumerate(LOCAL_BLOCKS):
        global_block = tuple(
            sorted(
                FIXED_PAIR
                + tuple(LOCAL_TO_GLOBAL[point] for point in local_block)
            )
        )
        variable = GLOBAL_BLOCK_INDEX[global_block]
        local_to_variable.append(variable)
        containing_order.append((variable, local_index))
    containing_order.sort()
    if (
        len(set(local_to_variable)) != 210
        or len(containing_order) != 210
    ):
        fail("local-to-global link-variable map is not bijective")

    roots = output / "roots"
    roots.mkdir(parents=True, exist_ok=True)
    entries = []
    expected_root_names = set()
    case_header = f"p cnf {BASE_VARIABLES} {CASE_CLAUSES}\n".encode()
    for orbit_index, record in enumerate(records):
        representative = record["representative"]
        local_indices = selected_indices(representative)
        if len(local_indices) != 9:
            fail("representative does not have nine blocks")
        selected_variables = {
            local_to_variable[index] for index in local_indices
        }
        signed_units = tuple(
            variable if variable in selected_variables else -variable
            for variable, _ in containing_order
        )
        if (
            len(signed_units) != 210
            or sum(value > 0 for value in signed_units) != 9
            or sum(value < 0 for value in signed_units) != 201
        ):
            fail("root does not contain exactly 9 positive and 201 negative units")
        root_raw = "".join(f"{literal} 0\n" for literal in signed_units).encode()
        root_name = f"link_orbit_{orbit_index:03d}.units"
        expected_root_names.add(root_name)
        root_path = roots / root_name
        atomic_write(root_path, root_raw)
        link_blocks = []
        for local_index in local_indices:
            local_block = LOCAL_BLOCKS[local_index]
            global_block = tuple(
                sorted(
                    FIXED_PAIR
                    + tuple(
                        LOCAL_TO_GLOBAL[point] for point in local_block
                    )
                )
            )
            link_blocks.append(
                {
                    "local_block_index": local_index,
                    "local_points": list(local_block),
                    "global_block": list(global_block),
                    "global_variable": local_to_variable[local_index],
                }
            )
        entries.append(
            {
                "orbit_index": orbit_index,
                "canonical_cover_words": list(cover_words(representative)),
                "local_block_indices": list(local_indices),
                "link_blocks": link_blocks,
                "selected_global_variables": sorted(selected_variables),
                "signed_root_units": list(signed_units),
                "positive_units": 9,
                "negative_units": 201,
                "orbit_size": record["orbit_size"],
                "stabilizer_order": record["stabilizer_order"],
                "orbit_member_sha256": record["orbit_member_sha256"],
                "root": f"roots/{root_name}",
                "root_bytes": len(root_raw),
                "root_sha256": sha256(root_raw),
                "case_variables": BASE_VARIABLES,
                "case_clauses": CASE_CLAUSES,
                "case_bytes": len(case_header) + len(base_body) + len(root_raw),
                "case_cnf_sha256": sha256(
                    case_header + base_body + root_raw
                ),
            }
        )
    actual_root_names = {
        path.name for path in roots.iterdir() if path.is_file()
    }
    if actual_root_names != expected_root_names:
        fail("root directory contains a missing or stale file")

    representatives_raw = "".join(
        "".join(f"{index} " for index in entry["local_block_indices"]) + "\n"
        for entry in entries
    ).encode("ascii")
    if sha256(representatives_raw) != EXPECTED_REPRESENTATIVES_SHA256:
        fail("canonical representative-list SHA-256 changed")
    representative_path = output / "link_representatives.txt"
    atomic_write(representative_path, representatives_raw)

    orbit_histogram: Dict[str, int] = {}
    stabilizer_histogram: Dict[str, int] = {}
    for entry in entries:
        orbit_key = str(entry["orbit_size"])
        stabilizer_key = str(entry["stabilizer_order"])
        orbit_histogram[orbit_key] = orbit_histogram.get(orbit_key, 0) + 1
        stabilizer_histogram[stabilizer_key] = (
            stabilizer_histogram.get(stabilizer_key, 0) + 1
        )

    generator_path = Path(__file__).resolve()
    auditor_path = generator_path.with_name(
        "audit_fixed_link_classification.py"
    )
    manifest: Dict[str, Any] = {
        "model_version": MODEL,
        "mathematical_scope": {
            "fixed_nonmatching_pair": list(FIXED_PAIR),
            "local_to_global_points": list(LOCAL_TO_GLOBAL),
            "distinguished_partner_local_points": [0, 1],
            "distinguished_partner_global_points": [1, 3],
            "link_block_size": 4,
            "link_block_count": 9,
            "pair_coverage": True,
        },
        "compact_base": {
            "expected_repository_path": (
                "certificates/global/compact_campaign/global_base.cnf"
            ),
            "variables": BASE_VARIABLES,
            "clauses": BASE_CLAUSES,
            "bytes": len(EXPECTED_BASE_HEADER) + 1 + len(base_body),
            "sha256": EXPECTED_BASE_SHA256,
            "body_sha256": EXPECTED_BASE_BODY_SHA256,
        },
        "enumeration": {
            "no_eight_cover": no_eight,
            "nine_block_cover_count": len(all_covers),
            "nine_block_cover_sha256": cover_digest(all_covers),
            "degree_three_set_count": len(low_histogram),
            "covers_per_degree_three_set": 1_710,
            "degree_three_set_histogram_sha256": sha256(
                canonical(low_histogram)
            ),
            "admissible_partner_degree4_count": len(admissible),
            "admissible_cover_sha256": cover_digest(admissible),
        },
        "group": {
            "name": "Gamma",
            "description": (
                "S2 on the two distinguished partners times C2 wr S4 "
                "on the four remaining matched pairs"
            ),
            "order": len(group),
            "element_sha256": sha256(canonical([list(item) for item in group])),
            "action_table_sha256": sha256(
                canonical([list(table) for table in tables])
            ),
        },
        "partition": {
            "orbit_count": len(entries),
            "orbit_size_sum": sum(entry["orbit_size"] for entry in entries),
            "orbit_size_histogram": orbit_histogram,
            "stabilizer_order_histogram": stabilizer_histogram,
        },
        "representatives": {
            "path": "link_representatives.txt",
            "count": len(entries),
            "bytes": len(representatives_raw),
            "sha256": EXPECTED_REPRESENTATIVES_SHA256,
            "format": (
                "one canonical representative per line; nine decimal local "
                "block indices, each followed by one ASCII space"
            ),
        },
        "link_variable_map": [
            {
                "local_block_index": local_index,
                "local_points": list(LOCAL_BLOCKS[local_index]),
                "global_variable": local_to_variable[local_index],
            }
            for local_index in range(210)
        ],
        "root_order": {
            "description": (
                "all 210 variables for blocks containing P, ascending by "
                "global primary variable; selected nine positive"
            ),
            "global_variables": [
                variable for variable, _ in containing_order
            ],
        },
        "entries": entries,
        "root_index_sha256": sha256(
            canonical(
                [
                    {
                        "path": entry["root"],
                        "bytes": entry["root_bytes"],
                        "sha256": entry["root_sha256"],
                    }
                    for entry in entries
                ]
            )
        ),
        "sources": {
            "generator": source_record(generator_path),
            "auditor": source_record(auditor_path),
            "python": sys.version,
            "uses_third_party_packages": False,
        },
    }
    manifest["manifest_sha256"] = sha256(canonical(manifest))
    atomic_write(
        output / "manifest.json",
        (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(),
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--base", type=Path, required=True, help="pinned compact base CNF"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent,
    )
    arguments = parser.parse_args()
    try:
        manifest = build(arguments.output_dir.resolve(), arguments.base.resolve())
    except (GenerationError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"FIXED-LINK GENERATION FAILED: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "result": "FIXED-LINK GENERATION PASSED",
                "manifest_sha256": manifest["manifest_sha256"],
                "covers": manifest["enumeration"]["nine_block_cover_count"],
                "admissible": manifest["enumeration"][
                    "admissible_partner_degree4_count"
                ],
                "group_order": manifest["group"]["order"],
                "orbits": manifest["partition"]["orbit_count"],
                "representatives_sha256": manifest["representatives"][
                    "sha256"
                ],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
