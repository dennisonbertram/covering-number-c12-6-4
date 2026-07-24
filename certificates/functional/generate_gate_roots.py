#!/usr/bin/env python3
"""Generate structurally audited prefix-counter roots for C(12,6,4).

This is an independent cardinality encoding of the compact two-root model.
It does not use PySAT.  Every auxiliary threshold variable is defined by the
equivalence

    s[i,j] <-> s[i-1,j] OR (s[i-1,j-1] AND x[i]).

Thus every primary assignment has exactly one auxiliary extension, and the
final threshold units have their literal cardinality meaning.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
from pathlib import Path
from typing import Iterable, Sequence, Union


if not __debug__:
    raise RuntimeError("this proof generator refuses Python -O because it uses assertions")


Atom = Union[int, bool]
POINTS = tuple(range(12))
MATCH = tuple((2 * i, 2 * i + 1) for i in range(6))
MATCH_SET = frozenset(MATCH)
BLOCKS = tuple(itertools.combinations(POINTS, 6))
BLOCK_SETS = tuple(frozenset(block) for block in BLOCKS)


def block_type(block: tuple[int, ...]) -> int:
    selected = frozenset(block)
    occupancies = tuple(len(selected & frozenset(pair)) for pair in MATCH)
    full = occupancies.count(2)
    assert full == occupancies.count(0)
    return full


KINDS = tuple(block_type(block) for block in BLOCKS)


class Builder:
    def __init__(self) -> None:
        self.next_var = 1
        self.clauses: list[tuple[int, ...]] = []
        self.sections: dict[str, tuple[int, int]] = {}
        self.gate_count = 0

    def new_var(self) -> int:
        result = self.next_var
        self.next_var += 1
        return result

    @staticmethod
    def neg(atom: Atom) -> Atom:
        if atom is True:
            return False
        if atom is False:
            return True
        return -atom

    def add_clause(self, atoms: Iterable[Atom]) -> None:
        clause: list[int] = []
        seen = set()
        for atom in atoms:
            if atom is True:
                return
            if atom is False:
                continue
            assert isinstance(atom, int) and not isinstance(atom, bool)
            if -atom in seen:
                return
            if atom not in seen:
                seen.add(atom)
                clause.append(atom)
        self.clauses.append(tuple(clause))

    def gate(
        self, output: int, above: Atom, diagonal: Atom, literal: int
    ) -> None:
        # output -> above OR diagonal
        self.add_clause((-output, above, diagonal))
        # output -> above OR literal
        self.add_clause((-output, above, literal))
        # above -> output
        self.add_clause((self.neg(above), output))
        # diagonal AND literal -> output
        self.add_clause((self.neg(diagonal), -literal, output))
        self.gate_count += 1

    def thresholds(
        self, name: str, literals: Sequence[int], limit: int
    ) -> list[Atom]:
        start = len(self.clauses)
        previous: list[Atom] = [True] + [False] * limit
        for literal in literals:
            current: list[Atom] = [True]
            for j in range(1, limit + 1):
                output = self.new_var()
                self.gate(output, previous[j], previous[j - 1], literal)
                current.append(output)
            previous = current
        self.sections[name] = (start, len(self.clauses))
        return previous

    def exactly(
        self, name: str, literals: Sequence[int], target: int
    ) -> None:
        start = len(self.clauses)
        final = self.thresholds(name + "_gates", literals, target + 1)
        assert isinstance(final[target], int)
        assert isinstance(final[target + 1], int)
        self.add_clause((final[target],))
        self.add_clause((-final[target + 1],))
        self.sections[name] = (start, len(self.clauses))

    def atmost(
        self, name: str, literals: Sequence[int], target: int
    ) -> None:
        start = len(self.clauses)
        final = self.thresholds(name + "_gates", literals, target + 1)
        assert isinstance(final[target + 1], int)
        self.add_clause((-final[target + 1],))
        self.sections[name] = (start, len(self.clauses))


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build(root: int) -> tuple[Builder, dict[str, object]]:
    if root not in (0, 1):
        raise ValueError(root)
    builder = Builder()
    variables = tuple(builder.new_var() for _ in BLOCKS)
    assert variables == tuple(range(1, 925))

    builder.exactly("exactly_40_blocks", variables, 40)

    pair_start = len(builder.clauses)
    for edge in itertools.combinations(POINTS, 2):
        edge_set = frozenset(edge)
        literals = tuple(
            variables[index]
            for index, block_set in enumerate(BLOCK_SETS)
            if edge_set <= block_set
        )
        assert len(literals) == 210
        target = 10 if edge in MATCH_SET else 9
        builder.atmost(
            "pair_" + "_".join(map(str, edge)) + "_atmost", literals, target
        )
    builder.sections["all_pair_atmost"] = (
        pair_start,
        len(builder.clauses),
    )

    triple_start = len(builder.clauses)
    for triple in itertools.combinations(POINTS, 3):
        triple_set = frozenset(triple)
        literals = tuple(
            variables[index]
            for index, block_set in enumerate(BLOCK_SETS)
            if triple_set <= block_set
        )
        assert len(literals) == 84
        builder.atmost(
            "triple_" + "_".join(map(str, triple)) + "_atmost",
            literals,
            4,
        )
    builder.sections["all_triple_atmost"] = (
        triple_start,
        len(builder.clauses),
    )

    coverage_start = len(builder.clauses)
    for quad in itertools.combinations(POINTS, 4):
        quad_set = frozenset(quad)
        coverers = tuple(
            variables[index]
            for index, block_set in enumerate(BLOCK_SETS)
            if quad_set <= block_set
        )
        assert len(coverers) == 28
        builder.add_clause(coverers)
    builder.sections["quad_coverage"] = (
        coverage_start,
        len(builder.clauses),
    )
    base_clauses = len(builder.clauses)

    root_start = len(builder.clauses)
    if root == 0:
        canonical = (0, 2, 4, 6, 8, 10)
        builder.add_clause((variables[BLOCKS.index(canonical)],))
    else:
        for index, kind in enumerate(KINDS):
            if kind == 0:
                builder.add_clause((-variables[index],))
        canonical = (0, 1, 4, 6, 8, 10)
        builder.add_clause((variables[BLOCKS.index(canonical)],))
    builder.sections["root_units"] = (root_start, len(builder.clauses))

    metadata = {
        "format": "c1264-functional-prefix-v1",
        "root": root,
        "canonical_block": list(canonical),
        "primary_variables": len(variables),
        "variables": builder.next_var - 1,
        "clauses": len(builder.clauses),
        "base_clauses": base_clauses,
        "gate_count": builder.gate_count,
        "type_histogram": {
            str(kind): KINDS.count(kind) for kind in range(4)
        },
        "sections_zero_based_half_open": {
            name: [bounds[0], bounds[1]]
            for name, bounds in builder.sections.items()
            if name
            in {
                "exactly_40_blocks",
                "all_pair_atmost",
                "all_triple_atmost",
                "quad_coverage",
                "root_units",
            }
        },
    }
    return builder, metadata


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=int, choices=(0, 1), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    args = parser.parse_args()

    builder, metadata = build(args.root)
    with args.output.open("w", encoding="ascii", newline="\n") as output:
        output.write("c C(12,6,4) functional prefix-counter root\n")
        output.write("c primary variables 1..924 are lexicographic 6-subsets\n")
        output.write(
            f"p cnf {builder.next_var - 1} {len(builder.clauses)}\n"
        )
        for clause in builder.clauses:
            output.write(" ".join(map(str, clause)) + " 0\n")

    metadata["cnf_bytes"] = args.output.stat().st_size
    metadata["cnf_sha256"] = file_sha256(args.output)
    args.metadata.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(metadata, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
