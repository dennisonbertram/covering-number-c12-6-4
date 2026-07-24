#!/usr/bin/env python3
"""Independently audit the degree-5 DIMACS instance and its semantic map."""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple, Union


if not __debug__:
    raise RuntimeError("this proof auditor refuses Python -O because it uses assertions")


Atom = Union[int, bool]
Clause = Tuple[int, ...]


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_dimacs(path: Path) -> Tuple[int, List[Clause]]:
    variable_count = clause_count = None
    clauses: List[Clause] = []
    with path.open("r", encoding="ascii") as source:
        for line in source:
            words = line.split()
            if not words or words[0] == "c":
                continue
            if words[0] == "p":
                assert words[:2] == ["p", "cnf"] and len(words) == 4
                variable_count, clause_count = map(int, words[2:])
                continue
            values = tuple(map(int, words))
            assert values and values[-1] == 0 and 0 not in values[:-1]
            clauses.append(values[:-1])
    assert variable_count is not None and clause_count == len(clauses)
    assert all(abs(literal) <= variable_count for clause in clauses for literal in clause)
    return variable_count, clauses


def neg(atom: Atom) -> Atom:
    if atom is True:
        return False
    if atom is False:
        return True
    return -atom


def simplify_clause(atoms: Iterable[Atom]) -> Clause | None:
    result: List[int] = []
    seen = set()
    for atom in atoms:
        if atom is True:
            return None
        if atom is False:
            continue
        assert isinstance(atom, int) and not isinstance(atom, bool)
        if -atom in seen:
            return None
        if atom not in seen:
            seen.add(atom)
            result.append(atom)
    return tuple(result)


def expected_gate_clauses(
    output: int, above: Atom, diagonal: Atom, literal: int
) -> List[Clause]:
    raw = [
        (-output, above, diagonal),
        (-output, above, literal),
        (neg(above), output),
        (neg(diagonal), -literal, output),
    ]
    return [clause for atoms in raw if (clause := simplify_clause(atoms)) is not None]


def clause_value(clause: Clause, assignment: Dict[int, bool]) -> bool:
    return any(
        assignment[abs(literal)] if literal > 0 else not assignment[abs(literal)]
        for literal in clause
    )


def audit_gate_truth_table(
    output: int, above: Atom, diagonal: Atom, literal: int, clauses: Sequence[Clause]
) -> None:
    variables = sorted(
        {
            atom
            for atom in (output, above, diagonal, literal)
            if isinstance(atom, int) and not isinstance(atom, bool)
        }
    )
    for values in itertools.product((False, True), repeat=len(variables)):
        assignment = dict(zip(variables, values))

        def value(atom: Atom) -> bool:
            return atom if isinstance(atom, bool) else assignment[atom]

        expected = value(output) == (
            value(above) or (value(diagonal) and value(literal))
        )
        actual = all(clause_value(clause, assignment) for clause in clauses)
        assert actual == expected


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("cnf", type=Path)
    parser.add_argument("map", type=Path)
    args = parser.parse_args()

    mapping = json.loads(args.map.read_text(encoding="utf-8"))
    assert mapping["format"] == "c12-degree5-cnf-map-v1"
    assert mapping["cnf_sha256"] == file_sha256(args.cnf)
    variable_count, clauses = read_dimacs(args.cnf)
    assert variable_count == mapping["variable_count"]
    assert len(clauses) == mapping["clause_count"]

    vertices = tuple(range(9))
    triples = tuple(itertools.combinations(vertices, 3))
    quads = tuple(itertools.combinations(vertices, 4))
    edges = tuple(itertools.combinations(vertices, 2))
    assert len(triples) == 84 and len(quads) == 126 and len(edges) == 36

    triple_rows = mapping["triples"]
    quad_rows = mapping["quads"]
    assert [tuple(row["set"]) for row in triple_rows] == list(triples)
    assert [tuple(row["set"]) for row in quad_rows] == list(quads)
    triple_vars = {tuple(row["set"]): row["variable"] for row in triple_rows}
    quad_vars = {tuple(row["set"]): row["variable"] for row in quad_rows}
    assert list(triple_vars.values()) == list(range(1, 85))
    assert list(quad_vars.values()) == list(range(85, 211))

    sections = {
        name: tuple(bounds)
        for name, bounds in mapping["sections_zero_based_half_open"].items()
    }
    cards = {card["name"]: card for card in mapping["cards"]}
    used_auxiliaries = set()

    def audit_gate_sequence(
        name: str, expected_literals: List[int], limit: int, gate_rows: List[dict]
    ) -> Tuple[List[Atom], List[Clause]]:
        previous: List[Atom] = [True] + [False] * limit
        expected_section: List[Clause] = []
        gates = iter(gate_rows)
        for i, literal in enumerate(expected_literals, start=1):
            current: List[Atom] = [True]
            for j in range(1, limit + 1):
                gate = next(gates)
                assert gate["i"] == i and gate["j"] == j
                assert gate["literal"] == literal
                assert gate["above"] == previous[j]
                assert gate["diagonal"] == previous[j - 1]
                output = gate["output"]
                assert output > 210 and output not in used_auxiliaries
                used_auxiliaries.add(output)
                gate_clauses = expected_gate_clauses(
                    output, previous[j], previous[j - 1], literal
                )
                audit_gate_truth_table(
                    output, previous[j], previous[j - 1], literal, gate_clauses
                )
                expected_section.extend(gate_clauses)
                current.append(output)
            previous = current
        try:
            next(gates)
            raise AssertionError(f"extra gate in {name}")
        except StopIteration:
            pass
        return previous, expected_section

    def audit_exactly(name: str, expected_literals: List[int], target: int) -> None:
        card = cards[name]
        assert card["literals"] == expected_literals
        assert card["target"] == target
        limit = target + 1
        previous, expected_section = audit_gate_sequence(
            name, expected_literals, limit, card["gates"]
        )
        assert card["final_atleast_target"] == previous[target]
        assert card["final_atleast_target_plus_one"] == previous[target + 1]
        expected_section.append((previous[target],))
        expected_section.append((-previous[target + 1],))
        start, end = sections[name]
        assert clauses[start:end] == expected_section

        # The audited gate equivalences already prove the prefix recurrence.
        # This arithmetic loop is only an additional recurrence-level sanity
        # check; it is not the semantic justification by itself.
        for count in range(len(expected_literals) + 1):
            prefix = 0
            final = [True] + [False] * limit
            for position in range(len(expected_literals)):
                prefix += position < count
                final = [True] + [prefix >= j for j in range(1, limit + 1)]
            assert (final[target] and not final[target + 1]) == (count == target)

    audit_exactly("exactly_five_triples", list(range(1, 85)), 5)
    audit_exactly("exactly_four_quads", list(range(85, 211)), 4)

    fixed_expected = [(triple_vars[(0, 1, 2)],)]
    start, end = sections["fixed_triple_012"]
    assert clauses[start:end] == fixed_expected

    vertex_expected = [
        tuple(variable for triple, variable in triple_vars.items() if v in triple)
        for v in vertices
    ]
    start, end = sections["triple_vertex_union"]
    assert clauses[start:end] == vertex_expected
    assert all(len(clause) == 28 for clause in vertex_expected)

    edge_expected = []
    for edge in edges:
        edge_set = set(edge)
        edge_expected.append(
            tuple(
                variable
                for triple, variable in triple_vars.items()
                if edge_set.issubset(triple)
            )
            + tuple(
                variable
                for quad, variable in quad_vars.items()
                if edge_set.issubset(quad)
            )
        )
    start, end = sections["edge_coverage"]
    assert clauses[start:end] == edge_expected
    assert all(len(clause) == 7 + 21 for clause in edge_expected)

    threshold_rows = {row["name"]: row for row in mapping["thresholds"]}
    excess_bits: List[int] = []
    atleast_five_bits: List[int] = []
    for edge, incident in zip(edges, edge_expected):
        name = f"edge_{''.join(map(str, edge))}_degree"
        row = threshold_rows[name]
        assert row["limit"] == 5 and row["literals"] == list(incident)
        outputs, expected_section = audit_gate_sequence(
            name, list(incident), 5, row["gates"]
        )
        assert row["outputs"] == outputs[1:]
        start, end = sections[name]
        assert clauses[start:end] == expected_section
        excess_bits.extend(outputs[2:5])  # degree >= 2, 3, 4
        atleast_five_bits.append(outputs[5])
    assert len(threshold_rows) == 36 and len(excess_bits) == 108

    start, end = sections["edge_at_most_four_units"]
    assert clauses[start:end] == [(-literal,) for literal in atleast_five_bits]
    audit_exactly("exactly_three_edge_excess_units", excess_bits, 3)
    assert set(cards) == {
        "exactly_five_triples",
        "exactly_four_quads",
        "exactly_three_edge_excess_units",
    }

    # Verify the mathematical redundancy, independently of the CNF layout:
    # exact set counts give 39 incidences, coverage gives at least 36, hence
    # total excess is exactly 3.  No edge can have degree five.
    assert 5 * 3 + 4 * 6 == 39
    assert len(edges) == 36
    assert 39 - 36 == 3

    assert used_auxiliaries == set(range(211, variable_count + 1))

    all_section_indices = []
    for start, end in sections.values():
        all_section_indices.extend(range(start, end))
    assert sorted(all_section_indices) == list(range(len(clauses)))

    print("AUDIT VERIFIED")
    print("semantic_primary_variables 210")
    print("triples 84")
    print("quads 126")
    print("fixed_triple 012")
    print("selected_triples exactly_5")
    print("selected_quads exactly_4")
    print("triple_union_vertices 9")
    print("covered_edges 36")
    print(f"auxiliary_variables {len(used_auxiliaries)}")
    print(f"variables {variable_count}")
    print(f"clauses {len(clauses)}")
    print(f"cnf_sha256 {file_sha256(args.cnf)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
