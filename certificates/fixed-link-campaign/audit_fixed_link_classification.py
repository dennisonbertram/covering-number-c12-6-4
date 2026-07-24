#!/usr/bin/env python3
"""Independent fail-closed audit of the fixed-link 266-orbit partition."""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
import struct
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, Iterator, List, Sequence, Set, Tuple


if not __debug__:
    raise RuntimeError("refusing Python -O: fail-closed checks must remain active")


MODEL = "c12-fixed-link-classification-v1"
BASE_SHA = "637d9326388f77f933f3d066cd762d8c0ac4b2df0d2260d688e031d55959e7f0"
BODY_SHA = "6a1a2eb2843a4ddcf9138c5a85aaeccd2950b3e099e0ab8a26ce9fc815ab0cc5"
REPRESENTATIVES_SHA = (
    "369a844c4590d435fc24f82424a0775d51ce326d243aaf740d025c52c81d652b"
)
BASE_HEADER = b"p cnf 122519 356407"
CASE_HEADER = b"p cnf 122519 356617\n"
LOCAL = tuple(range(10))
LOCAL_TO_GLOBAL = (1, 3, 4, 5, 6, 7, 8, 9, 10, 11)
PAIR_FIXED = (0, 2)
PAIRS = tuple(itertools.combinations(LOCAL, 2))
PAIR_ID = {pair: index for index, pair in enumerate(PAIRS)}
QUADS = tuple(itertools.combinations(LOCAL, 4))
QUAD_ID = {quad: index for index, quad in enumerate(QUADS)}
SIXES = tuple(itertools.combinations(range(12), 6))
SIX_ID = {block: index + 1 for index, block in enumerate(SIXES)}
ALL_PAIRS = (1 << 45) - 1
MASK64 = (1 << 64) - 1

TOP_KEYS = {
    "compact_base",
    "entries",
    "enumeration",
    "group",
    "link_variable_map",
    "manifest_sha256",
    "mathematical_scope",
    "model_version",
    "partition",
    "representatives",
    "root_index_sha256",
    "root_order",
    "sources",
}
ENTRY_KEYS = {
    "canonical_cover_words",
    "case_bytes",
    "case_clauses",
    "case_cnf_sha256",
    "case_variables",
    "link_blocks",
    "local_block_indices",
    "negative_units",
    "orbit_index",
    "orbit_member_sha256",
    "orbit_size",
    "positive_units",
    "root",
    "root_bytes",
    "root_sha256",
    "selected_global_variables",
    "signed_root_units",
    "stabilizer_order",
}


class AuditError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise AuditError(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def strict_json(path: Path) -> Dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        fail(f"{path}: regular non-symlink JSON required")

    def unique(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
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
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"{path}: invalid JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{path}: top-level object required")
    return value


def safe_file(root: Path, relative: Any) -> Path:
    if not isinstance(relative, str):
        fail("artifact path is not a string")
    pure = PurePosixPath(relative)
    if (
        pure.is_absolute()
        or not pure.parts
        or any(part in ("", ".", "..") for part in pure.parts)
    ):
        fail(f"unsafe relative artifact path {relative!r}")
    candidate = root
    for part in pure.parts:
        candidate = candidate / part
        if candidate.is_symlink():
            fail(f"symlink artifact path rejected: {relative}")
    if not candidate.is_file():
        fail(f"missing regular artifact: {relative}")
    try:
        candidate.resolve().relative_to(root.resolve())
    except ValueError:
        fail(f"artifact path escapes root: {relative}")
    return candidate


def words(cover: int) -> Tuple[int, int, int, int]:
    return tuple(
        cover >> (64 * index) & MASK64 for index in range(4)
    )  # type: ignore[return-value]


def packed(cover: int) -> bytes:
    return struct.pack("<QQQQ", *words(cover))


def digest_covers(covers: Iterable[int]) -> str:
    digest = hashlib.sha256()
    for cover in sorted(covers, key=words):
        digest.update(packed(cover))
    return digest.hexdigest()


def indices(cover: int) -> Tuple[int, ...]:
    output = []
    value = cover
    while value:
        bit = value & -value
        output.append(bit.bit_length() - 1)
        value -= bit
    return tuple(output)


def pair_mask(block: Sequence[int]) -> int:
    return sum(
        1 << PAIR_ID[tuple(sorted(pair))]
        for pair in itertools.combinations(block, 2)
    )


QUAD_PAIR_MASKS = tuple(pair_mask(block) for block in QUADS)


def triple_partitions(
    values: Sequence[int],
) -> Iterator[Tuple[Tuple[int, int, int], ...]]:
    """A separately written canonical partition iterator."""
    pool = tuple(values)
    if not pool:
        yield ()
        return
    anchor = min(pool)
    rest_without_anchor = tuple(item for item in pool if item != anchor)
    for companions in itertools.combinations(rest_without_anchor, 2):
        cell = tuple(sorted((anchor,) + companions))
        remainder = tuple(item for item in pool if item not in cell)
        for suffix in triple_partitions(remainder):
            yield (cell,) + suffix


def semantic_cover(cover: int) -> Tuple[int, ...]:
    chosen = indices(cover)
    degrees = [0] * 10
    covered = 0
    for index in chosen:
        if not 0 <= index < 210:
            fail("cover contains an out-of-range block index")
        covered |= QUAD_PAIR_MASKS[index]
        for point in QUADS[index]:
            degrees[point] += 1
    if covered != ALL_PAIRS:
        fail("family fails local pair coverage")
    return tuple(degrees)


def independently_enumerate_target(
    degree_vector: Tuple[int, ...]
) -> Iterator[int]:
    """Reconstruct one degree-vector fibre without importing the generator."""
    total, remainder = divmod(sum(degree_vector), 4)
    if remainder or total not in (8, 9):
        fail("invalid independent degree vector")
    threes = tuple(
        point for point, degree in enumerate(degree_vector) if degree == 3
    )
    if not threes:
        fail("independent fibre has no degree-three point")
    first = threes[0]
    neighbours = tuple(point for point in LOCAL if point != first)

    def search(
        chosen: int, covered: int, remaining: List[int], used: int
    ) -> Iterator[int]:
        slots = total - used
        if (
            slots < 0
            or sum(remaining) != 4 * slots
            or any(value < 0 or value > slots for value in remaining)
        ):
            return
        for point in threes:
            missing = tuple(
                other
                for other in LOCAL
                if other != point
                and not (
                    covered
                    >> PAIR_ID[tuple(sorted((point, other)))]
                    & 1
                )
            )
            if len(missing) != 3 * remaining[point]:
                return
        if used == total:
            if covered == ALL_PAIRS and not any(remaining):
                if semantic_cover(chosen) != degree_vector:
                    fail("independent enumerator emitted wrong degrees")
                yield chosen
            return

        point = next(
            (item for item in threes if remaining[item] > 0), None
        )
        if point is not None:
            missing = tuple(
                other
                for other in LOCAL
                if other != point
                and not (
                    covered
                    >> PAIR_ID[tuple(sorted((point, other)))]
                    & 1
                )
            )
            partition_count = remaining[point]
            for cells in triple_partitions(missing):
                if len(cells) != partition_count:
                    continue
                additions = []
                consumption = [0] * 10
                valid = True
                for cell in cells:
                    block = tuple(sorted((point,) + cell))
                    block_index = QUAD_ID[block]
                    if chosen >> block_index & 1:
                        valid = False
                        break
                    additions.append(block_index)
                    for vertex in block:
                        consumption[vertex] += 1
                if not valid or any(
                    consumption[vertex] > remaining[vertex]
                    for vertex in LOCAL
                ):
                    continue
                next_chosen = chosen
                next_covered = covered
                next_remaining = list(remaining)
                for block_index in additions:
                    next_chosen |= 1 << block_index
                    next_covered |= QUAD_PAIR_MASKS[block_index]
                    for vertex in QUADS[block_index]:
                        next_remaining[vertex] -= 1
                yield from search(
                    next_chosen,
                    next_covered,
                    next_remaining,
                    used + len(additions),
                )
            return

        active = tuple(
            vertex for vertex in LOCAL if remaining[vertex] > 0
        )
        candidates = tuple(
            QUAD_ID[block]
            for block in itertools.combinations(active, 4)
            if not (chosen >> QUAD_ID[block] & 1)
        )
        for completion in itertools.combinations(candidates, slots):
            consumption = [0] * 10
            next_covered = covered
            next_chosen = chosen
            for block_index in completion:
                next_chosen |= 1 << block_index
                next_covered |= QUAD_PAIR_MASKS[block_index]
                for vertex in QUADS[block_index]:
                    consumption[vertex] += 1
            if consumption == remaining and next_covered == ALL_PAIRS:
                if semantic_cover(next_chosen) != degree_vector:
                    fail("high-point completion has wrong degrees")
                yield next_chosen

    for cells in triple_partitions(neighbours):
        if len(cells) != 3:
            continue
        chosen = 0
        covered = 0
        remaining = list(degree_vector)
        for cell in cells:
            block = tuple(sorted((first,) + cell))
            block_index = QUAD_ID[block]
            chosen |= 1 << block_index
            covered |= QUAD_PAIR_MASKS[block_index]
            for point in block:
                remaining[point] -= 1
        yield from search(chosen, covered, remaining, 3)


def reconstruct_universes() -> Tuple[Set[int], Set[int], Dict[str, int]]:
    # An eight-cover has total point degree 32 and every point degree at
    # least three.  Hence its degree sequence is 5,3^9 or 4,4,3^8.
    eight = 0
    for exceptional in LOCAL:
        target = [3] * 10
        target[exceptional] = 5
        eight += sum(
            1 for _ in independently_enumerate_target(tuple(target))
        )
    for exceptional in itertools.combinations(LOCAL, 2):
        target = [3] * 10
        for point in exceptional:
            target[point] = 4
        eight += sum(
            1 for _ in independently_enumerate_target(tuple(target))
        )
    if eight != 0:
        fail("independent eight-cover exhaustion found a cover")

    all_nine: Set[int] = set()
    histogram: Dict[str, int] = {}
    emissions = 0
    for low in itertools.combinations(LOCAL, 4):
        target = tuple(3 if point in low else 4 for point in LOCAL)
        fibre = set(independently_enumerate_target(target))
        if len(fibre) != 1_710:
            fail(f"degree-three fibre {low} has size {len(fibre)}, not 1710")
        if all_nine.intersection(fibre):
            fail("independent degree-three fibres overlap")
        all_nine.update(fibre)
        emissions += len(fibre)
        histogram[",".join(map(str, low))] = len(fibre)
    if emissions != 359_100 or len(all_nine) != 359_100:
        fail("independent nine-cover universe count mismatch")
    admissible = {
        cover
        for cover in all_nine
        if semantic_cover(cover)[0] == 4
        and semantic_cover(cover)[1] == 4
    }
    if len(admissible) != 119_700:
        fail("independent partner-degree filter count mismatch")
    return all_nine, admissible, histogram


def compose(
    left: Tuple[int, ...], right: Tuple[int, ...]
) -> Tuple[int, ...]:
    return tuple(left[right[index]] for index in LOCAL)


def inverse(permutation: Tuple[int, ...]) -> Tuple[int, ...]:
    result = [0] * 10
    for source, target in enumerate(permutation):
        result[target] = source
    return tuple(result)


def generator_permutations() -> Tuple[Tuple[int, ...], ...]:
    output = []
    swap = list(LOCAL)
    swap[0], swap[1] = swap[1], swap[0]
    output.append(tuple(swap))
    for pair_index in range(4):
        flip = list(LOCAL)
        left = 2 + 2 * pair_index
        flip[left], flip[left + 1] = flip[left + 1], flip[left]
        output.append(tuple(flip))
    for pair_index in range(3):
        exchange = list(LOCAL)
        left = 2 + 2 * pair_index
        right = left + 2
        exchange[left], exchange[right] = exchange[right], exchange[left]
        exchange[left + 1], exchange[right + 1] = (
            exchange[right + 1],
            exchange[left + 1],
        )
        output.append(tuple(exchange))
    return tuple(output)


def bfs_group() -> Tuple[Tuple[int, ...], ...]:
    identity = LOCAL
    generators = generator_permutations()
    found = {identity}
    queue = [identity]
    while queue:
        current = queue.pop()
        for generator in generators:
            candidate = compose(generator, current)
            if candidate not in found:
                found.add(candidate)
                queue.append(candidate)
    if len(found) != 768:
        fail("BFS Gamma does not have order 768")
    for permutation in found:
        if tuple(sorted(permutation)) != LOCAL:
            fail("Gamma contains a non-permutation")
        if set(permutation[:2]) != {0, 1}:
            fail("Gamma does not preserve the distinguished pair")
        pair_images = {
            frozenset((permutation[2 + 2 * index], permutation[3 + 2 * index]))
            for index in range(4)
        }
        expected_pairs = {
            frozenset((2 + 2 * index, 3 + 2 * index))
            for index in range(4)
        }
        if pair_images != expected_pairs:
            fail("Gamma does not preserve the four matching pairs")
        if inverse(permutation) not in found:
            fail("Gamma lacks an inverse")
    for left in found:
        for right in found:
            if compose(left, right) not in found:
                fail("Gamma is not closed")
    return tuple(sorted(found))


def tables_for_group(
    group: Sequence[Tuple[int, ...]]
) -> Tuple[Tuple[int, ...], ...]:
    tables = []
    for permutation in group:
        table = tuple(
            QUAD_ID[tuple(sorted(permutation[point] for point in block))]
            for block in QUADS
        )
        if tuple(sorted(table)) != tuple(range(210)):
            fail("Gamma action table is not a permutation")
        tables.append(table)
    return tuple(tables)


def image_cover(cover: int, table: Sequence[int]) -> int:
    image = 0
    for block_index in indices(cover):
        image |= 1 << table[block_index]
    return image


def read_base(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        fail("base CNF must be a regular non-symlink file")
    raw = path.read_bytes()
    if sha(raw) != BASE_SHA:
        fail("base CNF SHA-256 mismatch")
    try:
        header, body = raw.split(b"\n", 1)
    except ValueError:
        fail("base CNF is missing its body")
    if header != BASE_HEADER or sha(body) != BODY_SHA:
        fail("base CNF header/body identity mismatch")
    return body


def verify_source(root: Path, record: Any, expected_name: str) -> None:
    if not isinstance(record, dict) or set(record) != {
        "bytes",
        "path",
        "sha256",
    }:
        fail(f"{expected_name}: source-record schema mismatch")
    if record["path"] != expected_name:
        fail(f"{expected_name}: source path mismatch")
    path = safe_file(root, expected_name)
    if (
        path.stat().st_size != record["bytes"]
        or file_sha(path) != record["sha256"]
    ):
        fail(f"{expected_name}: source identity mismatch")


def audit(root: Path, base_path: Path) -> Dict[str, Any]:
    if root.is_symlink() or not root.is_dir():
        fail("artifact root must be a regular non-symlink directory")
    manifest_path = safe_file(root, "manifest.json")
    manifest = strict_json(manifest_path)
    if set(manifest) != TOP_KEYS or manifest.get("model_version") != MODEL:
        fail("top-level manifest schema/model mismatch")
    expected_manifest_hash = sha(
        canonical(
            {
                key: value
                for key, value in manifest.items()
                if key != "manifest_sha256"
            }
        )
    )
    if manifest["manifest_sha256"] != expected_manifest_hash:
        fail("manifest self-hash mismatch")
    sources = manifest.get("sources")
    if not isinstance(sources, dict) or set(sources) != {
        "auditor",
        "generator",
        "python",
        "uses_third_party_packages",
    }:
        fail("source section schema mismatch")
    if sources["uses_third_party_packages"] is not False:
        fail("manifest does not declare pure-standard-library generation")
    verify_source(root, sources["generator"], "generate_fixed_link_classification.py")
    verify_source(root, sources["auditor"], "audit_fixed_link_classification.py")

    base_body = read_base(base_path)
    expected_base = {
        "expected_repository_path": (
            "certificates/global/compact_campaign/global_base.cnf"
        ),
        "variables": 122_519,
        "clauses": 356_407,
        "bytes": len(BASE_HEADER) + 1 + len(base_body),
        "sha256": BASE_SHA,
        "body_sha256": BODY_SHA,
    }
    if manifest["compact_base"] != expected_base:
        fail("manifest compact-base binding mismatch")

    all_covers, admissible, histogram = reconstruct_universes()
    enumeration = manifest["enumeration"]
    expected_enumeration = {
        "no_eight_cover": {
            "degree_patterns": 55,
            "degree_pattern_families": ["one degree 5", "two degrees 4"],
            "emitted_covers": 0,
        },
        "nine_block_cover_count": 359_100,
        "nine_block_cover_sha256": digest_covers(all_covers),
        "degree_three_set_count": 210,
        "covers_per_degree_three_set": 1_710,
        "degree_three_set_histogram_sha256": sha(canonical(histogram)),
        "admissible_partner_degree4_count": 119_700,
        "admissible_cover_sha256": digest_covers(admissible),
    }
    if enumeration != expected_enumeration:
        fail("manifest enumeration record mismatch")

    group = bfs_group()
    tables = tables_for_group(group)
    expected_group = {
        "name": "Gamma",
        "description": (
            "S2 on the two distinguished partners times C2 wr S4 "
            "on the four remaining matched pairs"
        ),
        "order": 768,
        "element_sha256": sha(canonical([list(item) for item in group])),
        "action_table_sha256": sha(
            canonical([list(table) for table in tables])
        ),
    }
    if manifest["group"] != expected_group:
        fail("manifest Gamma record mismatch")

    local_variables = []
    variable_map = []
    for local_index, local_block in enumerate(QUADS):
        global_block = tuple(
            sorted(
                PAIR_FIXED
                + tuple(LOCAL_TO_GLOBAL[point] for point in local_block)
            )
        )
        variable = SIX_ID[global_block]
        local_variables.append(variable)
        variable_map.append(
            {
                "local_block_index": local_index,
                "local_points": list(local_block),
                "global_variable": variable,
            }
        )
    if manifest["link_variable_map"] != variable_map:
        fail("link-variable map mismatch")
    containing = sorted((variable, index) for index, variable in enumerate(local_variables))
    expected_order = {
        "description": (
            "all 210 variables for blocks containing P, ascending by "
            "global primary variable; selected nine positive"
        ),
        "global_variables": [variable for variable, _ in containing],
    }
    if manifest["root_order"] != expected_order:
        fail("root-order record mismatch")

    entries = manifest["entries"]
    if not isinstance(entries, list) or len(entries) != 266:
        fail("manifest must contain exactly 266 entries")
    representatives = []
    seen: Set[int] = set()
    root_index = []
    orbit_histogram: Dict[str, int] = {}
    stabilizer_histogram: Dict[str, int] = {}
    for expected_index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != ENTRY_KEYS:
            fail(f"entry {expected_index}: schema mismatch")
        if entry["orbit_index"] != expected_index:
            fail(f"entry {expected_index}: orbit index mismatch")
        raw_words = entry["canonical_cover_words"]
        if (
            not isinstance(raw_words, list)
            or len(raw_words) != 4
            or any(
                not isinstance(value, int) or not 0 <= value <= MASK64
                for value in raw_words
            )
        ):
            fail(f"entry {expected_index}: invalid cover words")
        representative = sum(
            value << (64 * index) for index, value in enumerate(raw_words)
        )
        if representative not in admissible:
            fail(f"entry {expected_index}: representative not admissible")
        chosen = indices(representative)
        if entry["local_block_indices"] != list(chosen):
            fail(f"entry {expected_index}: local block list mismatch")
        if semantic_cover(representative)[0:2] != (4, 4):
            fail(f"entry {expected_index}: partner degrees are not four")

        orbit = {image_cover(representative, table) for table in tables}
        if not orbit <= admissible:
            fail(f"entry {expected_index}: orbit leaves universe")
        if min(orbit, key=words) != representative:
            fail(f"entry {expected_index}: representative is not canonical")
        stabilizer = sum(
            image_cover(representative, table) == representative
            for table in tables
        )
        if (
            entry["orbit_size"] != len(orbit)
            or entry["stabilizer_order"] != stabilizer
            or len(orbit) * stabilizer != 768
            or entry["orbit_member_sha256"] != digest_covers(orbit)
        ):
            fail(f"entry {expected_index}: orbit/stabilizer record mismatch")
        if seen.intersection(orbit):
            fail(f"entry {expected_index}: orbit overlaps an earlier orbit")
        seen.update(orbit)
        representatives.append(representative)
        orbit_key = str(len(orbit))
        stabilizer_key = str(stabilizer)
        orbit_histogram[orbit_key] = orbit_histogram.get(orbit_key, 0) + 1
        stabilizer_histogram[stabilizer_key] = (
            stabilizer_histogram.get(stabilizer_key, 0) + 1
        )

        selected_variables = {local_variables[index] for index in chosen}
        expected_units = [
            variable if variable in selected_variables else -variable
            for variable, _ in containing
        ]
        expected_links = []
        for local_index in chosen:
            local_block = QUADS[local_index]
            global_block = tuple(
                sorted(
                    PAIR_FIXED
                    + tuple(
                        LOCAL_TO_GLOBAL[point] for point in local_block
                    )
                )
            )
            expected_links.append(
                {
                    "local_block_index": local_index,
                    "local_points": list(local_block),
                    "global_block": list(global_block),
                    "global_variable": local_variables[local_index],
                }
            )
        if (
            entry["link_blocks"] != expected_links
            or entry["selected_global_variables"]
            != sorted(selected_variables)
            or entry["signed_root_units"] != expected_units
            or entry["positive_units"] != 9
            or entry["negative_units"] != 201
            or sum(value > 0 for value in expected_units) != 9
            or sum(value < 0 for value in expected_units) != 201
        ):
            fail(f"entry {expected_index}: lifted root semantics mismatch")
        root_path = safe_file(root, entry["root"])
        root_raw = root_path.read_bytes()
        expected_raw = "".join(
            f"{literal} 0\n" for literal in expected_units
        ).encode()
        if root_raw != expected_raw:
            fail(f"entry {expected_index}: root bytes mismatch")
        if (
            entry["root_bytes"] != len(root_raw)
            or entry["root_sha256"] != sha(root_raw)
            or entry["case_variables"] != 122_519
            or entry["case_clauses"] != 356_617
            or entry["case_bytes"]
            != len(CASE_HEADER) + len(base_body) + len(root_raw)
            or entry["case_cnf_sha256"]
            != sha(CASE_HEADER + base_body + root_raw)
        ):
            fail(f"entry {expected_index}: root/CNF identity mismatch")
        root_index.append(
            {
                "path": entry["root"],
                "bytes": entry["root_bytes"],
                "sha256": entry["root_sha256"],
            }
        )

    if representatives != sorted(representatives, key=words):
        fail("representative entries are not in canonical order")
    if seen != admissible or len(seen) != 119_700:
        fail("orbit union is not exactly the admissible universe")
    expected_partition = {
        "orbit_count": 266,
        "orbit_size_sum": 119_700,
        "orbit_size_histogram": orbit_histogram,
        "stabilizer_order_histogram": stabilizer_histogram,
    }
    if manifest["partition"] != expected_partition:
        fail("partition summary mismatch")
    if manifest["root_index_sha256"] != sha(canonical(root_index)):
        fail("root-index digest mismatch")
    representative_raw = "".join(
        "".join(f"{index} " for index in indices(representative)) + "\n"
        for representative in representatives
    ).encode("ascii")
    representative_record = {
        "path": "link_representatives.txt",
        "count": 266,
        "bytes": len(representative_raw),
        "sha256": REPRESENTATIVES_SHA,
        "format": (
            "one canonical representative per line; nine decimal local "
            "block indices, each followed by one ASCII space"
        ),
    }
    if manifest["representatives"] != representative_record:
        fail("representative-list manifest record mismatch")
    representative_file = safe_file(
        root, representative_record["path"]
    ).read_bytes()
    if (
        representative_file != representative_raw
        or sha(representative_file) != REPRESENTATIVES_SHA
    ):
        fail("stored representative list is not the exact canonical list")

    logical = {
        "model_version": MODEL,
        "manifest_sha256": manifest["manifest_sha256"],
        "no_eight_cover": True,
        "nine_block_covers": len(all_covers),
        "admissible_covers": len(admissible),
        "group_order": len(group),
        "orbits": len(entries),
        "orbit_union": len(seen),
        "roots_checked": len(root_index),
        "representatives_sha256": REPRESENTATIVES_SHA,
        "compact_base_sha256": BASE_SHA,
    }
    logical["logical_sha256"] = sha(canonical(logical))
    return logical


def atomic_json(path: Path, value: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()
    try:
        report = audit(
            arguments.artifact_dir.resolve(), arguments.base.resolve()
        )
        if arguments.report is not None:
            atomic_json(arguments.report.resolve(), report)
    except (AuditError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"FIXED-LINK AUDIT FAILED: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {"result": "FIXED-LINK AUDIT PASSED", **report},
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
