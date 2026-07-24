#!/usr/bin/env python3
"""Deterministically verify the pinned 41-block C(12,6,4) covering.

This verifier uses only the Python standard library.  It checks the exact
file digest, strict block syntax, distinctness, all 495 required 4-subsets,
and pinned multiplicity histograms for subset sizes one through four.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import math
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


V = 12
K = 6
T = 4
EXPECTED_BLOCKS = 41
EXPECTED_SHA256 = "0f701d9c281ef611bb4c2d9366839aee205d462bdc9cf5dbd774d9a6701e72d1"
EXPECTED_HISTOGRAMS: Dict[int, Dict[int, int]] = {
    1: {20: 6, 21: 6},
    2: {9: 45, 10: 21},
    3: {3: 60, 4: 160},
    4: {1: 405, 2: 75, 4: 15},
}

Block = Tuple[int, ...]
Subset = Tuple[int, ...]


class VerificationError(Exception):
    pass


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def parse_blocks(path: Path) -> Tuple[List[Block], str]:
    raw = path.read_bytes()
    digest = sha256_bytes(raw)
    if digest != EXPECTED_SHA256:
        raise VerificationError(
            f"SHA-256 mismatch: expected {EXPECTED_SHA256}, got {digest}"
        )

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VerificationError(f"not valid UTF-8: {exc}") from exc

    blocks: List[Block] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if len(fields) != K:
            raise VerificationError(
                f"line {line_number}: expected {K} integers, found {len(fields)}"
            )
        try:
            block = tuple(int(field) for field in fields)
        except ValueError as exc:
            raise VerificationError(
                f"line {line_number}: every field must be an integer"
            ) from exc
        if block != tuple(sorted(block)):
            raise VerificationError(
                f"line {line_number}: block must be strictly increasing"
            )
        if len(set(block)) != K:
            raise VerificationError(
                f"line {line_number}: block contains a repeated point"
            )
        if any(point < 1 or point > V for point in block):
            raise VerificationError(
                f"line {line_number}: points must lie in 1,...,{V}"
            )
        blocks.append(block)

    if len(blocks) != EXPECTED_BLOCKS:
        raise VerificationError(
            f"expected {EXPECTED_BLOCKS} blocks, found {len(blocks)}"
        )
    if len(set(blocks)) != EXPECTED_BLOCKS:
        raise VerificationError("blocks are not distinct")
    if set(itertools.chain.from_iterable(blocks)) != set(range(1, V + 1)):
        raise VerificationError("the point set is not exactly 1,...,12")
    return blocks, digest


def multiplicities(blocks: Iterable[Block], size: int) -> Counter[Subset]:
    result: Counter[Subset] = Counter()
    for block in blocks:
        result.update(itertools.combinations(block, size))
    return result


def format_histogram(histogram: Dict[int, int]) -> str:
    return ",".join(
        f"{multiplicity}:{frequency}"
        for multiplicity, frequency in sorted(histogram.items())
    )


def verify(path: Path) -> Tuple[str, Dict[int, Dict[int, int]]]:
    blocks, digest = parse_blocks(path)
    observed_histograms: Dict[int, Dict[int, int]] = {}

    for size in range(1, T + 1):
        counts = multiplicities(blocks, size)
        universe = tuple(itertools.combinations(range(1, V + 1), size))
        if len(universe) != math.comb(V, size):
            raise VerificationError(f"internal universe-size failure for t={size}")
        values = [counts[subset_] for subset_ in universe]
        if min(values) < 1:
            missing = [subset_ for subset_, count in zip(universe, values) if count == 0]
            raise VerificationError(
                f"t={size}: {len(missing)} subsets are uncovered; first is {missing[0]}"
            )
        histogram = dict(sorted(Counter(values).items()))
        expected = EXPECTED_HISTOGRAMS[size]
        if histogram != expected:
            raise VerificationError(
                f"t={size}: expected histogram {expected}, got {histogram}"
            )
        if sum(multiplicity * frequency for multiplicity, frequency in histogram.items()) != (
            EXPECTED_BLOCKS * math.comb(K, size)
        ):
            raise VerificationError(f"t={size}: incidence total is inconsistent")
        observed_histograms[size] = histogram

    return digest, observed_histograms


def main() -> int:
    default_path = Path(__file__).resolve().parents[1] / "data" / "cover_41.txt"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", type=Path, default=default_path)
    args = parser.parse_args()

    try:
        digest, histograms = verify(args.path)
    except (OSError, VerificationError) as exc:
        print(f"VERIFICATION FAILED: {exc}", file=sys.stderr)
        return 1

    print("VERIFIED 41-block C(12,6,4) cover")
    print(f"sha256 {digest}")
    print(f"blocks {EXPECTED_BLOCKS} distinct")
    for size in range(1, T + 1):
        print(
            f"t={size} subsets={math.comb(V, size)} "
            f"histogram={format_histogram(histograms[size])}"
        )
    print(f"covered_4_subsets {math.comb(V, T)}/{math.comb(V, T)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
