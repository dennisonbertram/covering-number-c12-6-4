#!/usr/bin/env python3
"""Independent structural audit of the functional prefix-counter roots.

The audit does not import the generator or PySAT.  It reconstructs every
primary variable and every one of the 270,144 auxiliary gates, truth-table
checks each equivalence, compares every CNF clause in order, checks both root
orbits and all matching-type profiles, and pins the complete files by hash.

Because each gate is an equivalence and the initial threshold row is fixed,
induction on the input prefix proves that every primary assignment has one
and only one extension and that s[i,j] means "at least j of x[1..i]."  This
directly establishes completeness of the cardinality encoding.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple, Union


Atom = Union[int, bool]
Clause = Tuple[int, ...]
POINTS = tuple(range(12))
MATCH = tuple((2 * i, 2 * i + 1) for i in range(6))
MATCH_SET = frozenset(MATCH)
BLOCKS = tuple(itertools.combinations(POINTS, 6))
BLOCK_SETS = tuple(frozenset(block) for block in BLOCKS)
BLOCK_INDEX = {block: index for index, block in enumerate(BLOCKS)}

PRIMARY = 924
TOTAL_VARS = 271_068
GATE_COUNT = 270_144
BASE_CLAUSES = 1_044_768
SECTION_BOUNDS = (
    (0, 150_533),
    (150_533, 694_913),
    (694_913, 1_044_273),
    (1_044_273, 1_044_768),
)
SECTION_HASHES = (
    "bce743dc630a90161ac74c26063777c4674901b5da4f2dfaeb30626dc49d3bea",
    "496cae355f1dce26f6ec16d12b050f067b6ef93d2db50920b5adcc3e05583c5c",
    "f1983d7c9df5832879279ccac4d8ada530cd87f1e04733304de579c25a3c37d4",
    "381d8e308ae3cc608ab74288477f1506c882b6af2eb2b0be891f94bb44612538",
)
SECTION_SHAPES = (
    {1: 42, 2: 38_808, 3: 111_683},
    {1: 666, 2: 153_720, 3: 389_994},
    {1: 1_100, 2: 110_880, 3: 237_380},
    {28: 495},
)
BASE_SHA256 = (
    "fc7e5de081b3805cd8c77f27c581b6fd6ab3a97b92a2928c3d60fafd2fb76e73"
)
ROOTS = {
    0: {
        "cnf": "gate_root0.cnf",
        "metadata": "gate_root0.json",
        "canonical": (0, 2, 4, 6, 8, 10),
        "clauses": 1_044_769,
        "bytes": 20_583_663,
        "sha256": (
            "f9c410e41c441be0a6dd5b08e6d1bb8f29f2afb9bb74ef9388f264f3d1187829"
        ),
        "root_units": 1,
    },
    1: {
        "cnf": "gate_root1.cnf",
        "metadata": "gate_root1.json",
        "canonical": (0, 1, 4, 6, 8, 10),
        "clauses": 1_044_833,
        "bytes": 20_584_111,
        "sha256": (
            "b9a6d72b7ba836419d36e51dbc1e6c46fa58fcde3e0712204cb257f5e8205143"
        ),
        "root_units": 65,
    },
}


class AuditError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise AuditError(message)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def kind(block: Tuple[int, ...]) -> int:
    selected = frozenset(block)
    occupancies = tuple(len(selected & frozenset(pair)) for pair in MATCH)
    full = occupancies.count(2)
    if full != occupancies.count(0):
        fail(f"internal type identity failed for {block}")
    return full


KINDS = tuple(kind(block) for block in BLOCKS)
TYPE_HISTOGRAM = {str(d): KINDS.count(d) for d in range(4)}
TYPE0_VARS = tuple(i + 1 for i, d in enumerate(KINDS) if d == 0)


def matching_orbit(block: Tuple[int, ...]) -> frozenset:
    images = set()
    for permutation in itertools.permutations(range(6)):
        for flips in range(64):
            images.add(
                tuple(
                    sorted(
                        2 * permutation[point // 2]
                        + (
                            (point & 1)
                            ^ ((flips >> (point // 2)) & 1)
                        )
                        for point in block
                    )
                )
            )
    return frozenset(images)


def audit_root_math() -> Dict[str, Any]:
    if len(BLOCKS) != PRIMARY:
        fail("six-subset count is not 924")
    if TYPE_HISTOGRAM != {"0": 64, "1": 480, "2": 360, "3": 20}:
        fail(f"unexpected type histogram {TYPE_HISTOGRAM}")
    orbit_sizes = {}
    for root in (0, 1):
        canonical = ROOTS[root]["canonical"]
        expected = frozenset(
            block for block, d in zip(BLOCKS, KINDS) if d == root
        )
        actual = matching_orbit(canonical)
        if actual != expected:
            fail(f"root {root} orbit mismatch")
        orbit_sizes[root] = len(actual)

    profiles = []
    for n0 in range(41):
        for n1 in range(41 - n0):
            for n2 in range(41 - n0 - n1):
                n3 = 40 - n0 - n1 - n2
                if n1 + 2 * n2 + 3 * n3 == 60:
                    profiles.append((n0, n1, n2, n3))
    if len(profiles) != 221:
        fail(f"expected 221 profiles, got {len(profiles)}")
    if any(n0 == 0 and n1 == 0 for n0, n1, _, _ in profiles):
        fail("two-root split misses a profile")
    if 6 * 10 + 60 * 9 != 40 * math.comb(6, 2):
        fail("pair-ceiling aggregate identity failed")
    return {
        "type_profiles": len(profiles),
        "root0_profiles": sum(n0 > 0 for n0, _, _, _ in profiles),
        "root1_profiles": sum(n0 == 0 for n0, _, _, _ in profiles),
        "orbit_sizes": orbit_sizes,
        "type_histogram": TYPE_HISTOGRAM,
    }


def neg(atom: Atom) -> Atom:
    if atom is True:
        return False
    if atom is False:
        return True
    return -atom


def simplify(atoms: Iterable[Atom]) -> Clause | None:
    out: List[int] = []
    seen = set()
    for atom in atoms:
        if atom is True:
            return None
        if atom is False:
            continue
        if not isinstance(atom, int) or isinstance(atom, bool):
            fail("internal non-literal")
        if -atom in seen:
            return None
        if atom not in seen:
            seen.add(atom)
            out.append(atom)
    return tuple(out)


def gate_clauses(
    output: int, above: Atom, diagonal: Atom, literal: int
) -> List[Clause]:
    raw = (
        (-output, above, diagonal),
        (-output, above, literal),
        (neg(above), output),
        (neg(diagonal), -literal, output),
    )
    return [
        clause
        for atoms in raw
        if (clause := simplify(atoms)) is not None
    ]


def clause_value(clause: Clause, assignment: Dict[int, bool]) -> bool:
    return any(
        assignment[abs(literal)] if literal > 0 else not assignment[abs(literal)]
        for literal in clause
    )


def truth_table_gate(
    output: int,
    above: Atom,
    diagonal: Atom,
    literal: int,
    clauses: Sequence[Clause],
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
        if actual != expected:
            fail("recurrence gate truth table failed")


class Reconstruction:
    def __init__(self) -> None:
        self.next_var = 925
        self.clauses: List[Clause] = []
        self.gates = 0
        self.used_aux = set()

    def add(self, atoms: Iterable[Atom]) -> None:
        clause = simplify(atoms)
        if clause is not None:
            self.clauses.append(clause)

    def new_aux(self) -> int:
        result = self.next_var
        self.next_var += 1
        if result in self.used_aux:
            fail(f"auxiliary variable {result} reused")
        self.used_aux.add(result)
        return result

    def thresholds(
        self, literals: Sequence[int], limit: int
    ) -> List[Atom]:
        previous: List[Atom] = [True] + [False] * limit
        for literal in literals:
            current: List[Atom] = [True]
            for j in range(1, limit + 1):
                output = self.new_aux()
                clauses = gate_clauses(
                    output, previous[j], previous[j - 1], literal
                )
                truth_table_gate(
                    output, previous[j], previous[j - 1], literal, clauses
                )
                self.clauses.extend(clauses)
                self.gates += 1
                current.append(output)
            previous = current
        return previous

    def exactly(self, literals: Sequence[int], target: int) -> None:
        final = self.thresholds(literals, target + 1)
        self.add((final[target],))
        self.add((-final[target + 1],))

    def atmost(self, literals: Sequence[int], target: int) -> None:
        final = self.thresholds(literals, target + 1)
        self.add((-final[target + 1],))


def root_units(root: int) -> Tuple[Clause, ...]:
    canonical = BLOCK_INDEX[ROOTS[root]["canonical"]] + 1
    if root == 0:
        return ((canonical,),)
    return tuple((-variable,) for variable in TYPE0_VARS) + ((canonical,),)


def reconstruct(root: int) -> Tuple[Reconstruction, List[Tuple[int, int]]]:
    state = Reconstruction()
    sections = []

    start = len(state.clauses)
    state.exactly(tuple(range(1, PRIMARY + 1)), 40)
    sections.append((start, len(state.clauses)))

    start = len(state.clauses)
    for edge in itertools.combinations(POINTS, 2):
        e = frozenset(edge)
        literals = tuple(
            index + 1
            for index, block_set in enumerate(BLOCK_SETS)
            if e <= block_set
        )
        if len(literals) != 210:
            fail(f"edge {edge}: containing-block count changed")
        state.atmost(literals, 10 if edge in MATCH_SET else 9)
    sections.append((start, len(state.clauses)))

    start = len(state.clauses)
    for triple in itertools.combinations(POINTS, 3):
        t = frozenset(triple)
        literals = tuple(
            index + 1
            for index, block_set in enumerate(BLOCK_SETS)
            if t <= block_set
        )
        if len(literals) != 84:
            fail(f"triple {triple}: containing-block count changed")
        state.atmost(literals, 4)
    sections.append((start, len(state.clauses)))

    start = len(state.clauses)
    for quad in itertools.combinations(POINTS, 4):
        q = frozenset(quad)
        coverers = tuple(
            index + 1
            for index, block_set in enumerate(BLOCK_SETS)
            if q <= block_set
        )
        if len(coverers) != 28:
            fail(f"quad {quad}: coverer count changed")
        state.add(coverers)
    sections.append((start, len(state.clauses)))

    if len(state.clauses) != BASE_CLAUSES:
        fail(f"reconstructed base has {len(state.clauses)} clauses")
    for unit in root_units(root):
        state.add(unit)
    return state, sections


def read_dimacs(path: Path) -> Tuple[int, List[Clause], bytes]:
    raw_file = path.read_bytes()
    variables = clause_count = None
    clauses: List[Clause] = []
    expected_comments = (
        b"c C(12,6,4) functional prefix-counter root",
        b"c primary variables 1..924 are lexicographic 6-subsets",
    )
    comments = []
    for line_number, raw in enumerate(raw_file.splitlines(), start=1):
        words = raw.split()
        if not words:
            fail(f"{path}:{line_number}: blank line")
        if words[0] == b"c":
            comments.append(raw)
            continue
        if words[0] == b"p":
            if variables is not None or clauses:
                fail(f"{path}:{line_number}: misplaced header")
            if len(words) != 4 or words[:2] != [b"p", b"cnf"]:
                fail(f"{path}:{line_number}: malformed header")
            variables, clause_count = map(int, words[2:])
            continue
        if variables is None:
            fail(f"{path}:{line_number}: clause before header")
        try:
            values = tuple(map(int, words))
        except ValueError as error:
            fail(f"{path}:{line_number}: non-integer: {error}")
        if not values or values[-1] != 0 or 0 in values[:-1]:
            fail(f"{path}:{line_number}: bad clause terminator")
        clause = values[:-1]
        if not clause:
            fail(f"{path}:{line_number}: unexpected empty clause")
        if len({abs(literal) for literal in clause}) != len(clause):
            fail(f"{path}:{line_number}: duplicate/complementary variable")
        if any(abs(literal) > variables for literal in clause):
            fail(f"{path}:{line_number}: literal exceeds header")
        clauses.append(clause)
    if tuple(comments) != expected_comments:
        fail(f"{path}: comments changed")
    if clause_count != len(clauses):
        fail(f"{path}: header clause count mismatch")
    return variables, clauses, raw_file


def expected_metadata(root: int) -> Dict[str, Any]:
    item = ROOTS[root]
    return {
        "base_clauses": BASE_CLAUSES,
        "canonical_block": list(item["canonical"]),
        "clauses": item["clauses"],
        "cnf_bytes": item["bytes"],
        "cnf_sha256": item["sha256"],
        "format": "c1264-functional-prefix-v1",
        "gate_count": GATE_COUNT,
        "primary_variables": PRIMARY,
        "root": root,
        "sections_zero_based_half_open": {
            "all_pair_atmost": list(SECTION_BOUNDS[1]),
            "all_triple_atmost": list(SECTION_BOUNDS[2]),
            "exactly_40_blocks": list(SECTION_BOUNDS[0]),
            "quad_coverage": list(SECTION_BOUNDS[3]),
            "root_units": [BASE_CLAUSES, item["clauses"]],
        },
        "type_histogram": TYPE_HISTOGRAM,
        "variables": TOTAL_VARS,
    }


def audit_one(directory: Path, root: int) -> Dict[str, Any]:
    item = ROOTS[root]
    path = directory / item["cnf"]
    metadata_path = directory / item["metadata"]
    if path.is_symlink() or metadata_path.is_symlink():
        fail("symlink artifact rejected")
    variables, actual, raw = read_dimacs(path)
    state, sections = reconstruct(root)
    if variables != TOTAL_VARS:
        fail(f"{path}: variable count {variables} != {TOTAL_VARS}")
    if actual != state.clauses:
        for index, (left, right) in enumerate(zip(actual, state.clauses)):
            if left != right:
                fail(
                    f"{path}: first clause mismatch at {index}: "
                    f"{left} != {right}"
                )
        fail(f"{path}: clause-list length mismatch")
    if state.next_var - 1 != TOTAL_VARS:
        fail("auxiliary reconstruction did not end at pinned variable")
    if state.gates != GATE_COUNT:
        fail("gate count mismatch")
    if state.used_aux != set(range(PRIMARY + 1, TOTAL_VARS + 1)):
        fail("auxiliary variables are not exactly 925..271068")
    if sections != list(SECTION_BOUNDS):
        fail(f"section boundaries changed: {sections}")
    if len(raw) != item["bytes"] or sha256(raw) != item["sha256"]:
        fail(f"{path}: pinned bytes/hash mismatch")

    for index, (start, end) in enumerate(SECTION_BOUNDS):
        section_raw = b"".join(
            (" ".join(map(str, clause)) + " 0\n").encode()
            for clause in state.clauses[start:end]
        )
        if sha256(section_raw) != SECTION_HASHES[index]:
            fail(f"{path}: section {index} hash mismatch")
        shapes = Counter(len(clause) for clause in state.clauses[start:end])
        if dict(shapes) != SECTION_SHAPES[index]:
            fail(f"{path}: section {index} shape mismatch")
    base_raw = b"".join(
        (" ".join(map(str, clause)) + " 0\n").encode()
        for clause in state.clauses[:BASE_CLAUSES]
    )
    if sha256(base_raw) != BASE_SHA256:
        fail(f"{path}: base hash mismatch")

    try:
        metadata = json.loads(metadata_path.read_text())
    except Exception as error:
        fail(f"{metadata_path}: invalid JSON: {error}")
    if canonical_json(metadata) != canonical_json(expected_metadata(root)):
        fail(f"{metadata_path}: metadata mismatch")
    return {
        "root": root,
        "variables": variables,
        "clauses": len(actual),
        "gate_count": state.gates,
        "bytes": len(raw),
        "sha256": sha256(raw),
        "base_sha256": BASE_SHA256,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--artifact-dir",
        type=Path,
        default=Path(__file__).resolve().parent,
    )
    args = parser.parse_args()
    try:
        mathematics = audit_root_math()
        roots = [
            audit_one(args.artifact_dir.resolve(), root) for root in (0, 1)
        ]
    except (AuditError, OSError) as error:
        print(f"FUNCTIONAL ROOT AUDIT FAILED: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "result": "FUNCTIONAL ROOT AUDIT PASSED",
                "mathematics": mathematics,
                "roots": roots,
                "semantic_argument": (
                    "Every gate was truth-table checked as an equivalence; "
                    "prefix induction gives a unique auxiliary extension."
                ),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
