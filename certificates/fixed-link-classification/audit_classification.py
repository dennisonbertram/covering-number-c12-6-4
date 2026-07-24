#!/usr/bin/env python3
"""Pure-standard-library audit of the fixed-link classification."""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
import pathlib
import sys
from collections import Counter, defaultdict, deque
from typing import Iterable, Iterator, Sequence


if not __debug__:
    raise RuntimeError(
        "this proof verifier refuses Python -O because checks must remain enabled"
    )


EXPECTED_COVERS_SHA256 = (
    "52951ea29f8e249a739a6d4eef31d874e552f789cbe0f99d93722bd7437547d9"
)
EXPECTED_REPRESENTATIVES_SHA256 = (
    "369a844c4590d435fc24f82424a0775d51ce326d243aaf740d025c52c81d652b"
)
EXPECTED_BASE_SHA256 = (
    "637d9326388f77f933f3d066cd762d8c0ac4b2df0d2260d688e031d55959e7f0"
)
EXPECTED_CASE_HASH_MANIFEST_SHA256 = (
    "3352f4cfa1009d09fda4e7af6c5a06b4fd6821fd5437f7a707b357d8c31dc8be"
)

POINTS10 = tuple(range(10))
BLOCKS10 = tuple(itertools.combinations(POINTS10, 4))
BLOCK_INDEX10 = {block: index for index, block in enumerate(BLOCKS10)}
PAIRS10 = tuple(itertools.combinations(POINTS10, 2))
PAIR_INDEX10 = {pair: index for index, pair in enumerate(PAIRS10)}
ALL_PAIRS10 = (1 << len(PAIRS10)) - 1
BLOCK_PAIR_MASK10 = tuple(
    sum(1 << PAIR_INDEX10[pair] for pair in itertools.combinations(block, 2))
    for block in BLOCKS10
)


class AuditFailure(RuntimeError):
    """The fixed-link classification failed a release gate."""


def fail(message: str) -> None:
    raise AuditFailure(message)


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


def cover_word_key(mask: int) -> tuple[int, int, int, int]:
    word_mask = (1 << 64) - 1
    words = tuple((mask >> (64 * index)) & word_mask for index in range(4))
    return words  # type: ignore[return-value]


def mask_to_indices(mask: int) -> tuple[int, ...]:
    result: list[int] = []
    while mask:
        low = mask & -mask
        result.append(low.bit_length() - 1)
        mask ^= low
    return tuple(result)


def parse_covers(path: pathlib.Path) -> list[int]:
    if path.is_symlink() or not path.is_file():
        fail(f"cover file is not a regular non-symlink file: {path}")
    covers: list[int] = []
    with path.open("r", encoding="ascii", newline="") as handle:
        for line_number, line in enumerate(handle, 1):
            fields = line.split()
            require(
                len(fields) == 9,
                f"{path}:{line_number}: expected exactly nine block indices",
            )
            values = tuple(int(field) for field in fields)
            require(
                values == tuple(sorted(values)) and len(set(values)) == 9,
                f"{path}:{line_number}: indices are not sorted and distinct",
            )
            require(
                all(0 <= value < len(BLOCKS10) for value in values),
                f"{path}:{line_number}: block index outside 0..209",
            )
            pair_union = 0
            for value in values:
                pair_union |= BLOCK_PAIR_MASK10[value]
            require(
                pair_union == ALL_PAIRS10,
                f"{path}:{line_number}: row is not a pair cover",
            )
            covers.append(sum(1 << value for value in values))
    require(len(covers) == len(set(covers)), f"{path}: duplicate covers")
    return covers


def degrees(mask: int) -> tuple[int, ...]:
    result = [0] * 10
    for index in mask_to_indices(mask):
        for point in BLOCKS10[index]:
            result[point] += 1
    return tuple(result)


def triple_partitions(
    items: Sequence[int],
) -> Iterator[tuple[tuple[int, ...], ...]]:
    """Yield each unordered partition into triples exactly once."""
    if not items:
        yield ()
        return
    first = items[0]
    rest = items[1:]
    for pair in itertools.combinations(rest, 2):
        triple = tuple(sorted((first, *pair)))
        remaining = tuple(item for item in rest if item not in pair)
        for tail in triple_partitions(remaining):
            yield (triple, *tail)


def two_triple_partitions(
    items: Sequence[int],
) -> tuple[tuple[tuple[int, ...], ...], ...]:
    require(len(items) == 6, "two-triple partition requires six points")
    first = items[0]
    rest = items[1:]
    result = []
    for pair in itertools.combinations(rest, 2):
        left = tuple(sorted((first, *pair)))
        right = tuple(item for item in rest if item not in pair)
        result.append((left, right))
    require(len(result) == 10, "six points should have ten 3+3 partitions")
    return tuple(result)


def block_set_to_mask(blocks: Iterable[tuple[int, ...]]) -> int:
    return sum(1 << BLOCK_INDEX10[tuple(sorted(block))] for block in blocks)


def heavy_completion_table() -> dict[
    tuple[int, tuple[int, ...]], list[tuple[tuple[int, ...], ...]]
]:
    heavy = tuple(range(6))
    blocks = tuple(itertools.combinations(heavy, 4))
    result: dict[
        tuple[int, tuple[int, ...]], list[tuple[tuple[int, ...], ...]]
    ] = defaultdict(list)
    for bits in range(1 << len(blocks)):
        chosen = tuple(
            blocks[index]
            for index in range(len(blocks))
            if (bits >> index) & 1
        )
        degree = tuple(
            sum(point in block for block in chosen) for point in heavy
        )
        result[(len(chosen), degree)].append(chosen)
    require(
        sum(len(entries) for entries in result.values()) == 1 << len(blocks),
        "heavy-only subset table lost entries",
    )
    return result


def enumerate_fixed_heavy() -> tuple[set[int], dict[str, int]]:
    """Enumerate covers whose heavy set is exactly {0,...,5}."""
    heavy = tuple(range(6))
    light = (6, 7, 8, 9)
    anchor = 9
    completion_table = heavy_completion_table()
    constructions: Counter[int] = Counter()
    anchor_count = 0
    option_tuple_count = 0
    consistent_option_count = 0

    for partition in triple_partitions(tuple(range(9))):
        anchor_count += 1
        anchor_blocks = {
            tuple(sorted((anchor, *triple))) for triple in partition
        }
        options: dict[int, tuple[tuple[tuple[int, ...], ...], ...]] = {}
        for point in light[:-1]:
            incident = [block for block in anchor_blocks if point in block]
            require(
                len(incident) == 1,
                "anchor partition did not place a light point exactly once",
            )
            seen = set(incident[0]) - {point}
            remaining = tuple(
                q for q in POINTS10 if q != point and q not in seen
            )
            point_options = []
            for split in two_triple_partitions(remaining):
                point_options.append(
                    tuple(tuple(sorted((point, *triple))) for triple in split)
                )
            require(len(point_options) == 10, "light point has wrong option count")
            options[point] = tuple(point_options)

        option_lists = tuple(options[point] for point in light[:-1])
        for choices in itertools.product(*option_lists):
            option_tuple_count += 1
            chosen_by_point = {
                point: set(choice)
                for point, choice in zip(light[:-1], choices)
            }
            current = set(anchor_blocks)
            for choice in choices:
                current.update(choice)

            consistent = True
            for point in light[:-1]:
                expected = set(chosen_by_point[point])
                expected.update(
                    block for block in anchor_blocks if point in block
                )
                actual = {block for block in current if point in block}
                if actual != expected or len(actual) != 3:
                    consistent = False
                    break
            if not consistent:
                continue
            require(
                sum(anchor in block for block in current) == 3,
                "anchor degree changed",
            )
            consistent_option_count += 1

            needed = 9 - len(current)
            if needed < 0:
                continue
            current_heavy_degree = tuple(
                sum(point in block for block in current) for point in heavy
            )
            residual = tuple(4 - value for value in current_heavy_degree)
            if any(value < 0 for value in residual):
                continue
            for heavy_choice in completion_table.get((needed, residual), ()):
                candidate = set(current)
                candidate.update(heavy_choice)
                if len(candidate) != 9:
                    continue
                mask = block_set_to_mask(candidate)
                pair_union = 0
                for index in mask_to_indices(mask):
                    pair_union |= BLOCK_PAIR_MASK10[index]
                if pair_union != ALL_PAIRS10:
                    continue
                require(
                    degrees(mask) == (4, 4, 4, 4, 4, 4, 3, 3, 3, 3),
                    "fixed-heavy construction violated its degree sequence",
                )
                constructions[mask] += 1

    require(anchor_count == 280, f"expected 280 anchors, got {anchor_count}")
    require(
        option_tuple_count == 280_000,
        f"expected 280000 option tuples, got {option_tuple_count}",
    )
    require(
        all(value == 1 for value in constructions.values()),
        "fixed-heavy construction produced a duplicate",
    )
    require(
        len(constructions) == 1_710,
        f"expected 1710 fixed-heavy covers, got {len(constructions)}",
    )
    return set(constructions), {
        "anchor_partitions": anchor_count,
        "option_tuples": option_tuple_count,
        "consistent_option_tuples": consistent_option_count,
        "distinct_fixed_heavy_covers": len(constructions),
    }


def relabel_fixed_heavy(fixed: set[int]) -> set[int]:
    fixed_blocks = [
        tuple(BLOCKS10[index] for index in mask_to_indices(mask))
        for mask in fixed
    ]
    all_points = set(POINTS10)
    result: set[int] = set()
    for target_heavy in itertools.combinations(POINTS10, 6):
        target_light = tuple(sorted(all_points - set(target_heavy)))
        mapping = dict(zip(range(6), target_heavy))
        mapping.update(zip(range(6, 10), target_light))
        for cover in fixed_blocks:
            image = (
                tuple(sorted(mapping[point] for point in block))
                for block in cover
            )
            result.add(block_set_to_mask(image))
    require(
        len(result) == math.comb(10, 6) * len(fixed),
        "heavy-set relabeling had an unexpected collision",
    )
    return result


def transposition(first: int, second: int) -> tuple[int, ...]:
    result = list(range(10))
    result[first], result[second] = result[second], result[first]
    return tuple(result)


def duo_transposition(first: int, second: int) -> tuple[int, ...]:
    duos = ((2, 3), (4, 5), (6, 7), (8, 9))
    result = list(range(10))
    for offset in range(2):
        result[duos[first][offset]] = duos[second][offset]
        result[duos[second][offset]] = duos[first][offset]
    return tuple(result)


def compose(
    after: tuple[int, ...], before: tuple[int, ...]
) -> tuple[int, ...]:
    return tuple(after[before[point]] for point in range(10))


def build_stabilizer() -> tuple[
    tuple[tuple[int, ...], ...], tuple[tuple[int, ...], ...]
]:
    generators = [transposition(0, 1)]
    generators.extend(
        transposition(*duo)
        for duo in ((2, 3), (4, 5), (6, 7), (8, 9))
    )
    generators.extend(duo_transposition(i, i + 1) for i in range(3))
    generator_tuple = tuple(generators)

    identity = tuple(range(10))
    seen = {identity}
    queue = deque((identity,))
    while queue:
        permutation = queue.popleft()
        for generator in generator_tuple:
            image = compose(generator, permutation)
            if image not in seen:
                seen.add(image)
                queue.append(image)
    require(len(seen) == 768, f"expected group order 768, got {len(seen)}")

    duo_sets = {
        frozenset((2, 3)),
        frozenset((4, 5)),
        frozenset((6, 7)),
        frozenset((8, 9)),
    }
    for permutation in seen:
        require(
            {permutation[0], permutation[1]} == {0, 1},
            "group moved the distinguished partner pair",
        )
        images = {
            frozenset((permutation[a], permutation[b]))
            for a, b in ((2, 3), (4, 5), (6, 7), (8, 9))
        }
        require(images == duo_sets, "group moved the four-duo system")
    return tuple(sorted(seen)), generator_tuple


def block_image_maps(
    permutations: Sequence[tuple[int, ...]],
) -> tuple[tuple[int, ...], ...]:
    return tuple(
        tuple(
            BLOCK_INDEX10[
                tuple(sorted(permutation[point] for point in block))
            ]
            for block in BLOCKS10
        )
        for permutation in permutations
    )


def apply_block_map(mask: int, block_map: Sequence[int]) -> int:
    return sum(1 << block_map[index] for index in mask_to_indices(mask))


def partition_orbits(
    covers: Sequence[int],
    degree_by_cover: dict[int, tuple[int, ...]],
) -> tuple[list[int], dict[str, object]]:
    admissible = {
        mask for mask in covers if degree_by_cover[mask][:2] == (4, 4)
    }
    require(
        len(admissible) == 119_700,
        f"expected 119700 admissible links, got {len(admissible)}",
    )
    group, generators = build_stabilizer()
    generator_maps = block_image_maps(generators)
    seen: set[int] = set()
    representatives: list[int] = []
    orbit_sizes: list[int] = []
    stabilizer_histogram: Counter[int] = Counter()

    for seed in sorted(admissible, key=cover_word_key):
        if seed in seen:
            continue
        orbit = {seed}
        queue = deque((seed,))
        while queue:
            current = queue.popleft()
            for mapping in generator_maps:
                image = apply_block_map(current, mapping)
                require(image in admissible, "generator left admissible links")
                if image not in orbit:
                    orbit.add(image)
                    queue.append(image)
        require(not (seen & orbit), "two generated orbits overlap")
        require(
            min(orbit, key=cover_word_key) == seed,
            "representative is not canonical in 64-bit-word order",
        )
        require(768 % len(orbit) == 0, "orbit size does not divide 768")
        seen.update(orbit)
        representatives.append(seed)
        orbit_sizes.append(len(orbit))
        stabilizer_histogram[768 // len(orbit)] += 1

    require(seen == admissible, "orbit union is not the admissible universe")
    require(len(representatives) == 266, "expected exactly 266 orbits")

    full_maps = block_image_maps(group)
    for representative, orbit_size in zip(representatives, orbit_sizes):
        images = {
            apply_block_map(representative, mapping) for mapping in full_maps
        }
        require(
            len(images) == orbit_size,
            "full-group images disagree with generator traversal",
        )
        require(images <= admissible, "full group left admissible links")

    stats: dict[str, object] = {
        "admissible_count": len(admissible),
        "generator_count": len(generators),
        "group_order": len(group),
        "orbit_count": len(representatives),
        "orbit_size_sum": sum(orbit_sizes),
        "orbit_size_histogram": {
            str(key): value
            for key, value in sorted(Counter(orbit_sizes).items())
        },
        "stabilizer_order_histogram": {
            str(key): value
            for key, value in sorted(stabilizer_histogram.items())
        },
    }
    return representatives, stats


def write_representatives(
    path: pathlib.Path, representatives: Sequence[int]
) -> None:
    with path.open("w", encoding="ascii", newline="") as handle:
        for representative in representatives:
            for index in mask_to_indices(representative):
                handle.write(f"{index} ")
            handle.write("\n")


def validate_cases(
    representatives: Sequence[int],
    base_path: pathlib.Path,
    output_path: pathlib.Path,
) -> dict[str, object]:
    require(
        file_sha256(base_path) == EXPECTED_BASE_SHA256,
        "compact global base SHA-256 changed",
    )
    raw = base_path.read_bytes()
    newline = raw.find(b"\n")
    require(newline >= 0, "global base lacks a header newline")
    fields = raw[:newline].decode("ascii").split()
    require(
        len(fields) == 4 and fields[:2] == ["p", "cnf"],
        "invalid global-base header",
    )
    variables, clauses = int(fields[2]), int(fields[3])
    body = raw[newline + 1 :]
    body_lines = body.splitlines()
    require(len(body_lines) == clauses, "global-base clause count mismatch")
    require(
        all(line == b"0" or line.endswith(b" 0") for line in body_lines),
        "global base contains a malformed clause",
    )

    blocks12 = tuple(itertools.combinations(range(12), 6))
    variable12 = {
        frozenset(block): index + 1 for index, block in enumerate(blocks12)
    }
    pair = {0, 2}
    link_map = (1, 3, 4, 5, 6, 7, 8, 9, 10, 11)
    containing = tuple(
        variable12[frozenset(block)]
        for block in blocks12
        if pair <= set(block)
    )
    require(len(containing) == 210, "fixed pair should occur in 210 blocks")
    containing_set = set(containing)
    common_hash = hashlib.sha256()
    common_hash.update(f"p cnf {variables} {clauses + 210}\n".encode("ascii"))
    common_hash.update(body)
    case_records = []

    for case_index, representative in enumerate(representatives):
        selected = set()
        for local_index in mask_to_indices(representative):
            local_block = BLOCKS10[local_index]
            global_block = frozenset(
                pair | {link_map[point] for point in local_block}
            )
            require(len(global_block) == 6, "local block did not lift to size six")
            selected.add(variable12[global_block])
        require(len(selected) == 9, "link did not lift to nine distinct blocks")
        require(selected <= containing_set, "lifted block missed the fixed pair")
        units = b"".join(
            f"{variable if variable in selected else -variable} 0\n".encode(
                "ascii"
            )
            for variable in containing
        )
        unit_lines = units.splitlines()
        require(len(unit_lines) == 210, "case does not have 210 unit clauses")
        positive = sum(1 for line in unit_lines if not line.startswith(b"-"))
        require(positive == 9, "case does not have nine positive units")
        digest = common_hash.copy()
        digest.update(units)
        case_records.append(
            {
                "conceptual_cnf_sha256": digest.hexdigest(),
                "index": case_index,
                "negative_units": 201,
                "positive_units": 9,
                "selected_global_variables": sorted(selected),
                "unit_count": 210,
            }
        )

    output_path.write_text(
        json.dumps(case_records, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    require(
        file_sha256(output_path) == EXPECTED_CASE_HASH_MANIFEST_SHA256,
        "conceptual case-hash manifest changed",
    )
    return {
        "base_clauses": clauses,
        "base_sha256": EXPECTED_BASE_SHA256,
        "base_variables": variables,
        "case_clauses": clauses + 210,
        "case_count": len(case_records),
        "case_hash_manifest_sha256": EXPECTED_CASE_HASH_MANIFEST_SHA256,
        "case_variables": variables,
        "negative_units_per_case": 201,
        "positive_units_per_case": 9,
        "units_per_case": 210,
    }


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--covers", required=True, type=pathlib.Path)
    parser.add_argument("--base-cnf", required=True, type=pathlib.Path)
    parser.add_argument("--output-dir", required=True, type=pathlib.Path)
    parser.add_argument("--candidate-representatives", type=pathlib.Path)
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    require(len(BLOCKS10) == 210, "expected 210 local blocks")
    require(len(PAIRS10) == 45, "expected 45 local pairs")
    require(
        file_sha256(args.covers) == EXPECTED_COVERS_SHA256,
        "canonical cover-list SHA-256 changed",
    )
    require(
        not args.output_dir.is_symlink(),
        "output directory must not be a symbolic link",
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)

    covers = parse_covers(args.covers)
    require(len(covers) == 359_100, "expected 359100 distinct covers")
    degree_by_cover = {mask: degrees(mask) for mask in covers}
    degree_histogram = Counter(
        tuple(sorted(value)) for value in degree_by_cover.values()
    )
    expected_histogram = {
        (3, 3, 3, 3, 4, 4, 4, 4, 4, 4): 359_100
    }
    require(
        degree_histogram == expected_histogram,
        f"unexpected degree histogram: {degree_histogram}",
    )

    fixed, fixed_stats = enumerate_fixed_heavy()
    fixed_general = {
        mask
        for mask, value in degree_by_cover.items()
        if value == (4, 4, 4, 4, 4, 4, 3, 3, 3, 3)
    }
    require(fixed == fixed_general, "fixed-heavy enumerations disagree")
    require(
        relabel_fixed_heavy(fixed) == set(covers),
        "fixed-heavy relabeling does not reproduce all covers",
    )

    representatives, orbit_stats = partition_orbits(covers, degree_by_cover)
    rep_path = args.output_dir / "link_representatives.txt"
    write_representatives(rep_path, representatives)
    require(
        file_sha256(rep_path) == EXPECTED_REPRESENTATIVES_SHA256,
        "canonical representative SHA-256 changed",
    )
    if args.candidate_representatives is not None:
        candidate = args.candidate_representatives
        require(
            file_sha256(candidate) == EXPECTED_REPRESENTATIVES_SHA256,
            "candidate representative SHA-256 changed",
        )
        require(
            candidate.read_bytes() == rep_path.read_bytes(),
            "candidate representatives differ from regenerated representatives",
        )

    case_stats = validate_cases(
        representatives,
        args.base_cnf,
        args.output_dir / "conceptual_case_hashes.json",
    )
    report = {
        "enumeration": {
            "cover_count": len(covers),
            "cover_sha256": EXPECTED_COVERS_SHA256,
            "degree_histogram": {
                "3,3,3,3,4,4,4,4,4,4": 359_100,
            },
        },
        "fixed_heavy": fixed_stats,
        "global_cases": case_stats,
        "orbits": orbit_stats,
        "representatives": {
            "count": len(representatives),
            "sha256": EXPECTED_REPRESENTATIVES_SHA256,
        },
        "result": "PASS",
    }
    report_path = args.output_dir / "AUDIT_REPORT.json"
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AuditFailure as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
