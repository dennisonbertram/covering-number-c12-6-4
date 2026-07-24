#!/usr/bin/env python3
"""Generate a deterministic DIMACS instance for the C(10,4,2) degree-5 lemma.

Primary variables select five distinct triples and four distinct quadruples
on {0,...,8}.  Triple 012 is fixed, the selected triples meet every vertex,
and the nine selected sets collectively cover every edge.

The exact-cardinality constraints use a fully equivalent unary prefix
recurrence.  For literals x_1,...,x_n, s[i,j] means that at least j of the
first i literals are true:

    s[i,j] <-> s[i-1,j] OR (s[i-1,j-1] AND x_i).

We construct s through j=k+1 and assert s[n,k] and NOT s[n,k+1].
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
from pathlib import Path
from typing import Dict, List, Sequence, Tuple, Union


if not __debug__:
    raise RuntimeError("this proof generator refuses Python -O because it uses assertions")


Atom = Union[int, bool]
Triple = Tuple[int, int, int]
Quad = Tuple[int, int, int, int]


class Builder:
    def __init__(self) -> None:
        self.next_var = 1
        self.clauses: List[Tuple[int, ...]] = []
        self.labels: Dict[int, str] = {}
        self.cards: List[dict] = []
        self.thresholds: List[dict] = []
        self.sections: Dict[str, Tuple[int, int]] = {}

    def new_var(self, label: str) -> int:
        result = self.next_var
        self.next_var += 1
        self.labels[result] = label
        return result

    def add_clause(self, *atoms: Atom) -> None:
        """Add one clause, simplifying Boolean constants."""
        clause: List[int] = []
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

    @staticmethod
    def neg(atom: Atom) -> Atom:
        if atom is True:
            return False
        if atom is False:
            return True
        return -atom

    def add_recurrence_gate(
        self, output: int, above: Atom, diagonal: Atom, literal: int
    ) -> None:
        """Encode output <-> above OR (diagonal AND literal)."""
        # output -> above OR diagonal
        self.add_clause(-output, above, diagonal)
        # output -> above OR literal
        self.add_clause(-output, above, literal)
        # above -> output
        self.add_clause(self.neg(above), output)
        # diagonal AND literal -> output
        self.add_clause(self.neg(diagonal), -literal, output)

    def exactly(self, name: str, literals: Sequence[int], target: int) -> None:
        assert 0 <= target < len(literals)
        start = len(self.clauses)
        limit = target + 1
        previous, gates = self.add_threshold_gates(name, literals, limit)
        assert isinstance(previous[target], int)
        assert isinstance(previous[target + 1], int)
        self.add_clause(previous[target])
        self.add_clause(-previous[target + 1])
        self.sections[name] = (start, len(self.clauses))
        self.cards.append(
            {
                "name": name,
                "target": target,
                "literals": list(literals),
                "gates": gates,
                "final_atleast_target": previous[target],
                "final_atleast_target_plus_one": previous[target + 1],
            }
        )

    def add_threshold_gates(
        self, name: str, literals: Sequence[int], limit: int
    ) -> Tuple[List[Atom], List[dict]]:
        previous: List[Atom] = [True] + [False] * limit
        gates = []
        for i, literal in enumerate(literals, start=1):
            current: List[Atom] = [True]
            for j in range(1, limit + 1):
                output = self.new_var(f"{name}:atleast:{i}:{j}")
                above = previous[j]
                diagonal = previous[j - 1]
                self.add_recurrence_gate(output, above, diagonal, literal)
                gates.append(
                    {
                        "i": i,
                        "j": j,
                        "output": output,
                        "above": above,
                        "diagonal": diagonal,
                        "literal": literal,
                    }
                )
                current.append(output)
            previous = current
        return previous, gates

    def thresholds_for(
        self, name: str, literals: Sequence[int], limit: int
    ) -> List[int]:
        """Return exact threshold bits [at-least-1,...,at-least-limit]."""
        start = len(self.clauses)
        previous, gates = self.add_threshold_gates(name, literals, limit)
        outputs = previous[1:]
        assert all(isinstance(output, int) for output in outputs)
        self.sections[name] = (start, len(self.clauses))
        self.thresholds.append(
            {
                "name": name,
                "limit": limit,
                "literals": list(literals),
                "gates": gates,
                "outputs": outputs,
            }
        )
        return outputs  # type: ignore[return-value]


def fmt_set(values: Sequence[int]) -> str:
    return "".join(str(value) for value in values)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("cnf", type=Path)
    parser.add_argument("map", type=Path)
    args = parser.parse_args()

    vertices = tuple(range(9))
    triples: Tuple[Triple, ...] = tuple(itertools.combinations(vertices, 3))
    quads: Tuple[Quad, ...] = tuple(itertools.combinations(vertices, 4))
    edges = tuple(itertools.combinations(vertices, 2))
    assert len(triples) == 84
    assert len(quads) == 126
    assert len(edges) == 36

    builder = Builder()
    triple_vars = {
        triple: builder.new_var(f"triple:{fmt_set(triple)}")
        for triple in triples
    }
    quad_vars = {
        quad: builder.new_var(f"quad:{fmt_set(quad)}") for quad in quads
    }
    assert list(triple_vars.values()) == list(range(1, 85))
    assert list(quad_vars.values()) == list(range(85, 211))

    builder.exactly("exactly_five_triples", list(triple_vars.values()), 5)
    builder.exactly("exactly_four_quads", list(quad_vars.values()), 4)

    fixed_start = len(builder.clauses)
    builder.add_clause(triple_vars[(0, 1, 2)])
    builder.sections["fixed_triple_012"] = (fixed_start, len(builder.clauses))

    vertex_start = len(builder.clauses)
    for vertex in vertices:
        builder.add_clause(
            *(variable for triple, variable in triple_vars.items() if vertex in triple)
        )
    builder.sections["triple_vertex_union"] = (vertex_start, len(builder.clauses))

    edge_start = len(builder.clauses)
    incident_by_edge = {}
    for edge in edges:
        edge_set = set(edge)
        incident = tuple(
            (
                variable
                for triple, variable in triple_vars.items()
                if edge_set.issubset(triple)
            )
        ) + tuple(
            (
                variable
                for quad, variable in quad_vars.items()
                if edge_set.issubset(quad)
            )
        )
        assert len(incident) == 28
        incident_by_edge[edge] = incident
        builder.add_clause(*incident)
    builder.sections["edge_coverage"] = (edge_start, len(builder.clauses))

    # Redundant but proof-strengthening edge-incidence identity.  Five
    # triples and four quads contribute 5*3+4*6=39 edge incidences.  Since
    # all 36 edges are covered, exactly three incidences are repeats.  Thus
    # every edge has degree at most four, and the 108 threshold bits
    # [degree >= 2], [degree >= 3], [degree >= 4] contain exactly three ones.
    edge_excess_bits = []
    edge_atleast_five_bits = []
    for edge in edges:
        edge_name = f"edge_{fmt_set(edge)}_degree"
        thresholds = builder.thresholds_for(edge_name, incident_by_edge[edge], 5)
        edge_excess_bits.extend(thresholds[1:4])
        edge_atleast_five_bits.append(thresholds[4])
    edge_at_most_four_start = len(builder.clauses)
    for atleast_five in edge_atleast_five_bits:
        builder.add_clause(-atleast_five)
    builder.sections["edge_at_most_four_units"] = (
        edge_at_most_four_start,
        len(builder.clauses),
    )
    assert len(edge_excess_bits) == 108
    builder.exactly("exactly_three_edge_excess_units", edge_excess_bits, 3)

    args.cnf.parent.mkdir(parents=True, exist_ok=True)
    with args.cnf.open("w", encoding="ascii", newline="\n") as output:
        output.write("c C(10,4,2) degree-5 finite lemma\n")
        output.write("c primary variables 1..84 triples, 85..210 quads\n")
        output.write(f"p cnf {builder.next_var - 1} {len(builder.clauses)}\n")
        for clause in builder.clauses:
            output.write(" ".join(map(str, clause)) + " 0\n")

    mapping = {
        "format": "c12-degree5-cnf-map-v1",
        "vertices": list(vertices),
        "triples": [
            {"set": list(triple), "variable": variable}
            for triple, variable in triple_vars.items()
        ],
        "quads": [
            {"set": list(quad), "variable": variable}
            for quad, variable in quad_vars.items()
        ],
        "cards": builder.cards,
        "thresholds": builder.thresholds,
        "sections_zero_based_half_open": {
            name: [start, end] for name, (start, end) in builder.sections.items()
        },
        "variable_count": builder.next_var - 1,
        "clause_count": len(builder.clauses),
        "cnf_filename": args.cnf.name,
        "cnf_sha256": sha256(args.cnf),
    }
    args.map.write_text(
        json.dumps(mapping, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    print(f"triples {len(triples)}")
    print(f"quads {len(quads)}")
    print(f"edges {len(edges)}")
    print(f"variables {builder.next_var - 1}")
    print(f"clauses {len(builder.clauses)}")
    print(f"cnf_sha256 {mapping['cnf_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
