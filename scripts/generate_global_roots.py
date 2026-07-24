#!/usr/bin/env python3
"""Generate compact proof CNFs for excluding a 40-block C(12,6,4).

The six degree-10 pairs are normalized to
    (0,1), (2,3), ..., (10,11).
All other point-pairs have degree 9 in any hypothetical 40-cover.

For proof search it is enough to encode the following necessary conditions:

* exactly 40 of the 924 six-subsets are selected;
* every normalized matching pair occurs at most 10 times and every other
  pair at most 9 times (the exact-40 count makes these all equalities);
* every triple occurs at most four times, by the separately certified
  C(10,4,2) local lemma;
* every quadruple is covered.

The lower triple bound is already implied by quadruple coverage and is
deliberately omitted.  This version is logically equivalent on 40-block
assignments to the larger exact-pair encoding, but yields substantially
smaller proof objects.

The matching stabilizer is transitive on type-0 and type-1 blocks.  Two
roots exhaust all type-count possibilities:

* root 0 fixes one type-0 block;
* root 1 forbids all type-0 blocks and fixes one type-1 block.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
from pathlib import Path

from pysat.card import CardEnc, EncType
from pysat.formula import CNF, IDPool


if not __debug__:
    raise RuntimeError("this proof generator refuses Python -O because it uses assertions")


POINTS = tuple(range(12))
MATCHED_PAIRS = tuple((2 * index, 2 * index + 1) for index in range(6))
MATCHED_EDGES = frozenset(MATCHED_PAIRS)
BLOCKS = tuple(itertools.combinations(POINTS, 6))
BLOCK_SETS = tuple(frozenset(block) for block in BLOCKS)


def block_type(block: tuple[int, ...]) -> int:
    block_set = frozenset(block)
    occupancies = tuple(
        len(block_set.intersection(pair)) for pair in MATCHED_PAIRS
    )
    full = sum(value == 2 for value in occupancies)
    empty = sum(value == 0 for value in occupancies)
    assert full == empty
    return full


BLOCK_TYPES = tuple(block_type(block) for block in BLOCKS)


def add_equals(
    cnf: CNF, pool: IDPool, literals: list[int], bound: int
) -> None:
    encoded = CardEnc.equals(
        lits=literals,
        bound=bound,
        vpool=pool,
        encoding=EncType.kmtotalizer,
    )
    cnf.extend(encoded.clauses)


def add_atmost(
    cnf: CNF, pool: IDPool, literals: list[int], bound: int
) -> None:
    encoded = CardEnc.atmost(
        lits=literals,
        bound=bound,
        vpool=pool,
        encoding=EncType.kmtotalizer,
    )
    cnf.extend(encoded.clauses)


def build(root: int) -> tuple[CNF, dict[str, object]]:
    if root not in (0, 1):
        raise ValueError("root must be 0 or 1")

    pool = IDPool()
    variables = tuple(pool.id(("block", block)) for block in BLOCKS)
    assert variables == tuple(range(1, len(BLOCKS) + 1))
    cnf = CNF()

    # Hypothesis under test.
    add_equals(cnf, pool, list(variables), 40)
    count_clause_end = len(cnf.clauses)

    # Pair upper bounds.  Their target sum is
    # 6*10 + 60*9 = 600 = 40*C(6,2), so exact block count forces equality.
    for edge in itertools.combinations(POINTS, 2):
        edge_set = frozenset(edge)
        literals = [
            variables[index]
            for index, block_set in enumerate(BLOCK_SETS)
            if edge_set <= block_set
        ]
        assert len(literals) == 210
        add_atmost(
            cnf,
            pool,
            literals,
            10 if edge in MATCHED_EDGES else 9,
        )
    pair_clause_end = len(cnf.clauses)

    # Local link upper bound.
    for triple in itertools.combinations(POINTS, 3):
        triple_set = frozenset(triple)
        literals = [
            variables[index]
            for index, block_set in enumerate(BLOCK_SETS)
            if triple_set <= block_set
        ]
        assert len(literals) == 84
        add_atmost(cnf, pool, literals, 4)
    triple_clause_end = len(cnf.clauses)

    # Literal quadruple coverage.
    for quad in itertools.combinations(POINTS, 4):
        quad_set = frozenset(quad)
        coverers = [
            variables[index]
            for index, block_set in enumerate(BLOCK_SETS)
            if quad_set <= block_set
        ]
        assert len(coverers) == 28
        cnf.append(coverers)
    base_clause_end = len(cnf.clauses)

    if root == 0:
        canonical = (0, 2, 4, 6, 8, 10)
        assert BLOCK_TYPES[BLOCKS.index(canonical)] == 0
        cnf.append([variables[BLOCKS.index(canonical)]])
    else:
        for index, kind in enumerate(BLOCK_TYPES):
            if kind == 0:
                cnf.append([-variables[index]])
        canonical = (0, 1, 4, 6, 8, 10)
        assert BLOCK_TYPES[BLOCKS.index(canonical)] == 1
        cnf.append([variables[BLOCKS.index(canonical)]])

    metadata = {
        "root": root,
        "primary_variables": len(variables),
        "variables": pool.top,
        "clauses": len(cnf.clauses),
        "canonical_block": canonical,
        "type_histogram": {
            str(kind): BLOCK_TYPES.count(kind) for kind in range(4)
        },
        "section_clause_counts": {
            "exact_block_count": count_clause_end,
            "pair_atmost": pair_clause_end - count_clause_end,
            "triple_atmost": triple_clause_end - pair_clause_end,
            "quad_coverage": base_clause_end - triple_clause_end,
            "base": base_clause_end,
            "root_units": len(cnf.clauses) - base_clause_end,
        },
    }
    return cnf, metadata


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=int, choices=(0, 1), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    args = parser.parse_args()

    cnf, metadata = build(args.root)
    cnf.to_file(str(args.output))
    metadata["cnf_sha256"] = hashlib.sha256(
        args.output.read_bytes()
    ).hexdigest()
    metadata["cnf_bytes"] = args.output.stat().st_size
    rendered = json.dumps(metadata, indent=2, sort_keys=True) + "\n"
    args.metadata.write_text(rendered)
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
