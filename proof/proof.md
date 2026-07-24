# A computer-assisted determination of \(C(12,6,4)\)

**Dennison Bertram**  
24 July 2026

## Abstract

Let \(C(v,k,t)\) be the minimum size of a family of \(k\)-subsets of a
\(v\)-set that contains every \(t\)-subset. We prove, with independently
checkable SAT certificates, that

\[
C(12,6,4)=41.
\]

The published upper bound is a 41-block cover. For the lower bound, a
hypothetical 40-block cover is forced into a rigid equality case. Its six
pair-degree excesses form a perfect matching and every triple has degree
three or four. Fixing one nonmatching pair, the nine blocks through it form
an optimal \((10,4,2)\) covering in which two specified points have degree
four. There are 119,700 such labelled links, forming 266 orbits under the
order-768 stabilizer of the matching and the fixed pair. A deterministic
enumerator and a structurally different independent auditor establish this
partition. Each canonical link gives one SAT instance; all 266 are
unsatisfiable, with every LRAT proof independently replayed by two checkers.
The only auxiliary mathematical ingredient is the small local theorem
\(C(10,4,2)=9\), together with the fact that every point in a nine-block
optimum has degree three or four. Its sole finite case is supplied both as a
short exhaustive program and as a replayed LRAT certificate.

## 1. Definitions and certificate convention

A \((v,k,t)\) covering is a family \(\mathcal B\) of \(k\)-subsets ("blocks")
of a \(v\)-element point set such that every \(t\)-subset lies in at least one
block. Repeated blocks can be discarded, so blocks may be assumed distinct.
The covering number \(C(v,k,t)\) is the least possible
\(|\mathcal B|\).

For a subset \(S\) of the point set, write

\[
r_S=\left|\{B\in\mathcal B:S\subseteq B\}\right|.
\]

For a point \(x\), write \(r_x\); for a pair \(xy\), write
\(\lambda_{xy}=r_{\{x,y\}}\).

The finite unsatisfiability claims below are not accepted merely because a
solver reports `UNSAT`. For each claim:

1. a deterministic generator writes a pinned DIMACS CNF;
2. a separate fail-closed auditor reconstructs its mathematical objects and
   its cardinality clauses;
3. CaDiCaL writes a DRAT proof;
4. `drat-trim` checks the DRAT proof and exports LRAT; and
5. the independent `lrat-check` program checks that LRAT file against the
   pinned CNF; and
6. the CakeML-extracted `cake_lpr` checker replays the same LRAT bytes.

Every source file, instance, result log, and distributable certificate used
for a finite claim is covered by a SHA-256 manifest. The manifests are tied
to the published Git commit and release; as usual, a manifest does not hash
itself.

## 2. The local theorem

### Lemma 1

\[
C(10,4,2)=9.
\]

Moreover, in every nine-block \((10,4,2)\) covering, every point has degree
three or four. Consequently its degree multiset is
\(4^6,3^4\).

### Proof

First suppose eight blocks cover all pairs. A block through a point covers
only three of the nine pairs incident with that point, so every point has
degree at least three. Since the degree sum is \(8\cdot4=32\), the degree
sequence is either

\[
5,3^9
\qquad\text{or}\qquad
4^2,3^8.
\]

If \(r_x=3\), then

\[
\sum_{y\ne x}\lambda_{xy}=3r_x=9.
\]

All nine terms are positive, hence every one is equal to one.

In the first degree pattern, let \(a\) be the degree-five point. Every other
point has degree three, so \(\lambda_{ay}=1\) for all nine \(y\ne a\).
This gives \(\sum_{y\ne a}\lambda_{ay}=9\), contradicting
\(3r_a=15\).

In the second pattern, let \(a,b\) be the degree-four points and let \(L\)
be the other eight points. Then

\[
12=3r_a=\lambda_{ab}+\sum_{y\in L}\lambda_{ay}
          =\lambda_{ab}+8,
\]

so \(\lambda_{ab}=4\). Thus all four blocks through \(a\) contain \(b\);
after deleting \(a,b\), their four pairs partition \(L\). The remaining
four blocks lie in \(L\), and every point of \(L\) occurs twice in them.
The four already covered pairs leave \(24\) uncovered pairs in \(L\), exactly
the total pair capacity of four 4-subsets. Hence those four blocks may not
repeat a pair, so any two of them intersect in at most one point. On the other
hand, counting their pairwise intersections by points gives

\[
\sum_{1\le i<j\le4}|B_i\cap B_j|
  =\sum_{y\in L}\binom22=8,
\]

whereas six pairs of blocks with intersections at most one give a total at
most six. This contradiction excludes eight blocks, and therefore every
smaller cover as well.

The following nine blocks give the matching upper bound:

```text
0 1 5 6
2 3 4 6
6 7 8 9
1 2 3 7
0 4 5 7
0 2 5 8
0 3 5 9
1 2 4 9
1 3 4 8
```

A direct check covers all \(45\) pairs. Thus \(C(10,4,2)=9\).

It remains to bound degrees in a nine-block optimum. Suppose a point \(x\)
has degree \(r\). Delete \(x\). Its \(r\) incident blocks become triples on
a nine-point set \(Y\), and the remaining \(9-r\) blocks are quadruples.
The triples leave at least

\[
\binom92-3r=36-3r
\]

uncovered edges, while the quadruples have total edge capacity
\(6(9-r)\). For \(r=7,8,9\), this would respectively require

\[
15\le12,\qquad 12\le6,\qquad 9\le0,
\]

all impossible.

Let \(r=6\). Equality is forced in the preceding capacity count: the six
triples have disjoint edge sets, and the three quadruples partition the
remaining 18 edges. For \(y\in Y\), let \(n_y\) and \(m_y\) count incident
triples and quadruples. Then

\[
8-2n_y=3m_y.
\]

Every \(y\in Y\) lies in an incident triple, because the original pair
\(\{x,y\}\) must be covered. Hence \(n_y\ge1\), and the only possibilities are
\((n_y,m_y)=(1,2)\) and \((4,0)\). Since
\(\sum_y n_y=18\), exactly three points are of the latter type. Call them
heavy. If \(k_i\) is the number of heavy points in the \(i\)-th triple, then
\(\sum_i k_i=12\). Disjointness of triple edges gives

\[
\sum_i\binom{k_i}{2}\le\binom32=3,
\]

but \(\binom{k}{2}\ge k-1\) for \(0\le k\le3\), and therefore

\[
\sum_i\binom{k_i}{2}\ge \sum_i(k_i-1)=12-6=6.
\]

This contradiction excludes degree six.

For \(r=5\), deleting \(x\) leaves five distinct triples whose union is
\(Y\), together with four quadruples that must cover every edge of \(K_9\)
not already covered by the triples. By \(S_9\)-symmetry, fix one triple as
\(\{0,1,2\}\). The verifier
enumerates all

\[
\binom{83}{4}=1,837,620
\]

choices of the other four triples. For each of the 411,300 choices whose
vertex union is \(Y\), a complete recursive search tests whether at most four
quadruples cover every residual edge. It deliberately permits repeated
quadruples, so it searches a superset of the valid completions. No completion
exists. The same finite claim is encoded independently as a CNF and certified
by replayed DRAT and LRAT proofs; the precise certificate record is in
Section 5.

Thus every point has degree at most four. Every point has degree at least
three, and

\[
36=\sum_xr_x=4n_4+3(10-n_4)
\]

gives \(n_4=6\). This proves the lemma. \(\square\)

## 3. The equality case for 40 blocks

The Schönheim inequalities and Lemma 1 give

\[
C(11,5,3)
\ge
\left\lceil\frac{11}{5}C(10,4,2)\right\rceil
=20
\]

so the value 20 used here is a direct consequence of Lemma 1, not an
external assumption. Consequently,

\[
C(12,6,4)
\ge
\left\lceil\frac{12}{6}C(11,5,3)\right\rceil
\ge40.
\]

Suppose for contradiction that a 40-block \((12,6,4)\) cover
\(\mathcal B\) exists. It has no repeated block: deleting one copy of a
repeated block would leave a cover with at most 39 blocks, contradicting the
lower bound just proved. More generally, any cover with fewer than 40
distinct blocks could be padded with unused 6-subsets to obtain a cover with
40 distinct blocks. Thus excluding the latter excludes every smaller or
multiset cover as well.

### 3.1 Point and pair degrees

The blocks through a pair, after deleting that pair, form a
\((10,4,2)\) cover. Because the original blocks are distinct, their
pair-deleted 4-subsets are distinct as well. Lemma 1 gives
\(\lambda_{xy}\ge9\) for every pair.

At a fixed point \(x\),

\[
5r_x=\sum_{y\ne x}\lambda_{xy}\ge11\cdot9=99.
\]

Integrality gives \(r_x\ge20\). Since

\[
\sum_x r_x=40\cdot6=240=12\cdot20,
\]

every point has degree exactly 20.

The total pair incidence is

\[
\sum_{\{x,y\}}\lambda_{xy}=40\binom62=600,
\]

only six above the baseline \(66\cdot9=594\). At a fixed point \(x\),

\[
\sum_{y\ne x}\lambda_{xy}=5r_x=100,
\]

only one above the local baseline \(11\cdot9=99\). Therefore the
nonnegative integral excesses \(\lambda_{xy}-9\) form a weighted graph of
degree one at every vertex. They are exactly the six edges of a perfect
matching \(M\), each with excess one. Consequently,

\[
\lambda_{xy}=
\begin{cases}
10,&xy\in M,\\
9,&xy\notin M.
\end{cases}
\]

Relabel the points so that

\[
M=\{\{0,1\},\{2,3\},\{4,5\},\{6,7\},\{8,9\},\{10,11\}\}.
\]

### 3.2 Triple degrees

Every triple \(T\) has degree at least three. Indeed, the nine quadruples
\(T\cup\{z\}\) must all be covered, while one 6-block containing \(T\)
covers only three choices of \(z\).

Every triple has degree at most four. Among its three pairs, at least one is
not in the matching \(M\). Choose such a pair \(P\subset T\). Exactly nine
blocks contain \(P\). Deleting \(P\) from them produces nine distinct
4-subsets and hence a nine-block \((10,4,2)\) covering: every pair \(Q\)
among the other ten points is covered because the original quadruple
\(P\cup Q\) is covered. The third point of \(T\) has degree \(r_T\) in this
local cover. Lemma 1 therefore gives \(r_T\in\{3,4\}\).

The degree-four triples satisfy a useful exact identity. For any pair \(P\),

\[
\sum_{z\notin P} r_{P\cup\{z\}}=4\lambda_P,
\]

because each block through \(P\) supplies four choices of its third point.
If \(P\in M\), the right side is 40, and all ten summands are at most four.
Thus every triple containing a matching pair has degree four. These 60
triples are distinct. If \(P\notin M\), the right side is 36, and the ten
summands are each three or four. Hence exactly six of them have degree four.

Globally, if \(N_4\) is the number of degree-four triples, then

\[
800=40\binom63=\sum_T r_T=3\binom{12}{3}+N_4,
\]

so \(N_4=140\). Therefore exactly 80 of the 160 triples containing no
matching pair have degree four.

### 3.3 A distinguished pair link

Fix the nonmatching pair

\[
P=\{0,2\}.
\]

Exactly nine blocks contain \(P\). Delete \(P\) from each of them. The result
is a family

\[
\mathcal L_P\subseteq\binom{V\setminus P}{4}
\]

of nine distinct 4-subsets. It covers every pair of the remaining ten
points: for \(Q\in\binom{V\setminus P}{2}\), any block covering the
quadruple \(P\cup Q\) contains \(P\), and its image in \(\mathcal L_P\)
contains \(Q\). Thus \(\mathcal L_P\) is an optimal \((10,4,2)\) covering.

The degree of \(y\in V\setminus P\) in this link is the global triple degree
\(r_{P\cup\{y\}}\). In particular, points 1 and 3 have link degree four,
because \(\{0,1,2\}\) and \(\{0,2,3\}\) each contain a matching edge.
Lemma 1 says that the link-degree multiset is \(4^6,3^4\). Consequently every
hypothetical 40-cover determines a nine-block \((10,4,2)\) link in which the
two specified partner points 1 and 3 both belong to the six-point degree-four
set.

## 4. The global finite exclusion

### 4.1 The shared Boolean formula

For each 6-subset \(B\) of the 12 points, introduce a Boolean variable
\(x_B\). The shared formula asserts:

\[
\sum_B x_B=40;
\]

\[
\sum_{B\supseteq P}x_B\le
\begin{cases}
10,&P\in M,\\
9,&P\notin M
\end{cases}
\quad\text{for every pair }P;
\]

\[
\sum_{B\supseteq T}x_B\le4
\quad\text{for every triple }T;
\]

and

\[
\sum_{B\supseteq Q}x_B\ge1
\quad\text{for every quadruple }Q.
\]

The pair ceilings lose no equality information. Their right-hand sides sum
to

\[
6\cdot10+60\cdot9=600,
\]

while any 40 selected blocks have exactly
\(40\binom62=600\) pair incidences. Thus every ceiling is attained.

Every hypothetical 40-cover therefore gives a satisfying assignment of this
shared formula.

### 4.2 The audited compact cardinality encoding

The exhaustive campaign uses the Python-SAT k-modulo-totalizer at pinned
commit `7abb1d6fdafe1d75fe3e5cdfb48f7e07a8a76efd`. The proof package does not
treat that implementation as an unexamined oracle. A standard-library-only
Python transcription independently reconstructs all auxiliary identifiers
and all clauses of the production base byte for byte, without importing
Python-SAT or a SAT solver.

For a unary vector \(Y\), let \(\pi(Y)\) be the length of its true prefix.
At a modulo node of radix \(p\), with upper and lower vectors \(U,L\), decode

\[
D(U,L)=p\,\pi(U)+\pi(L).
\]

Induction over the totalizer tree proves that every satisfying auxiliary
assignment has decoded value at least the number of true input literals; an
overflow past a truncated upper vector makes the clauses inconsistent. The
root comparator forces \(D(U,L)\) at most the requested bound. Conversely,
when the bound holds, assigning every node the exact quotient and remainder
of its subtree count satisfies every merge and comparator clause. Hence the
existential projection of an `AtMost` encoding is exactly the intended
inequality. Complementing the inputs proves `AtLeast`, and the pinned wrapper
uses disjoint consecutive auxiliaries for the two halves of equality.

The independent auditor reconstructs the production sections for exactly 40
blocks, the 66 pair ceilings, the 220 triple ceilings, and the 495 quadruple
coverage clauses. It obtains 122,519 variables and 356,407 clauses, with
full-file SHA-256
`637d9326388f77f933f3d066cd762d8c0ac4b2df0d2260d688e031d55959e7f0`.
It also performs 5,376 small exhaustive primary-assignment checks with its
own DPLL routine. Separately, a logic-free C++ adapter compiled against the
pinned official headers agrees with the transcription on 115 vectors
containing 123,220 clauses, including the complete equality section.

As an independent encoding cross-check, the repository also constructs the
same shared primary formula using full-equivalence prefix gates

\[
s_{i,j}\longleftrightarrow
s_{i-1,j}\lor(s_{i-1,j-1}\land x_i).
\]

A separate auditor truth-table-checks every gate and reconstructs the two
coarse symmetry roots. This functional base has 271,068 variables and
1,044,768 clauses; its clause-body SHA-256 is
`fc7e5de081b3805cd8c77f27c581b6fd6ab3a97b92a2928c3d60fafd2fb76e73`.
These functional artifacts are an encoding-level corroborating check; the
exhaustive lower bound uses the compact fixed-link roots and their receipts.

### 4.3 Exhausting the distinguished links

Let \(\Gamma=\operatorname{Stab}(M,P)\), where \(P=\{0,2\}\) is fixed as an
unordered pair. An element of \(\Gamma\) may swap the two matching pairs
\(\{0,1\}\) and \(\{2,3\}\), may arbitrarily permute the other four matching
pairs, and may independently swap the endpoints of those four pairs. Hence

\[
|\Gamma|=2\cdot4!\cdot2^4=768.
\]

This group acts on the ten points outside \(P\), preserving the condition
that points 1 and 3 have link degree four.

The production enumerator lists every nine-block \((10,4,2)\) covering and
then takes \(\Gamma\)-orbits of the admissible ones. A separately written
auditor reconstructs the same finite set in two structurally different ways.
First, a canonical minimum-uncovered-pair search over the 210 possible
4-subsets finds exactly 359,100 labelled nine-block covers.

Second, fix the six degree-four points \(H\); the other four points have
degree three. Choose one degree-three point as an anchor. Its three incident
blocks, after deleting the anchor, partition the other nine points into three
triples, giving 280 possibilities. For each of the other three degree-three
points, the remaining six points admit ten unordered splits into two triples.
The auditor tests all 280,000 option tuples, checks consistency, and supplies
all compatible heavy-only blocks. It obtains exactly 1,710 distinct covers for
each fixed \(H\). Relabelling over the \(\binom{10}{6}=210\) heavy sets
produces

\[
1,710\binom{10}{6}=359,100
\]

distinct covers, exactly the same set as the canonical search. The two
specified partner points are heavy in

\[
1,710\binom84=119,700
\]

of them.

The auditor constructs the order-768 closure of explicit generators and
partitions these 119,700 links by generator traversal. It then cross-checks
every resulting orbit against all 768 group images. The result is 266
disjoint orbits whose sizes sum to 119,700. The orbit-size histogram is

| orbit size | 12 | 16 | 24 | 48 | 96 | 128 | 192 | 256 | 384 | 768 |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| number | 1 | 1 | 5 | 12 | 30 | 2 | 60 | 1 | 37 | 117 |

Equivalently, the stabilizer orders are

| stabilizer order | 1 | 2 | 3 | 4 | 6 | 8 | 16 | 32 | 48 | 64 |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| number | 117 | 37 | 1 | 60 | 2 | 30 | 12 | 5 | 1 | 1 |

The canonical representative list has SHA-256
`369a844c4590d435fc24f82424a0775d51ce326d243aaf740d025c52c81d652b`.
The independent enumerator and auditor produce the same bytes.

### 4.4 The 266 certified roots

For a canonical link \(\mathcal L\), append one unit clause for each of the
210 possible blocks through \(P\): nine positive units select the blocks
\(P\cup L\) with \(L\in\mathcal L\), and the other 201 units are negative.
Thus each root has the same 122,519 variables and 356,617 clauses. The
independent auditor reconstructs all 210 units directly from each link,
checks that the nine positive blocks are distinct and cover all 45 pairs in
the link, and binds the resulting clause bytes to the audited shared base.

Every hypothetical 40-cover gives an admissible link by Section 3.3. Some
element of \(\Gamma\) maps that link to one of the 266 canonical
representatives. Applying the same relabelling to the whole cover preserves
the shared formula and \(P\), so the relabelled cover would satisfy the
corresponding root. The 266 roots are therefore exhaustive.

For every root, CaDiCaL produces a DRAT proof. `drat-trim` replays it and
exports LRAT. Both the independent C `lrat-check` implementation and the
CakeML-extracted `cake_lpr` checker then accept the same LRAT bytes against
the pinned CNF. A fail-closed aggregate auditor requires the exact case set
\(\{0,\ldots,265\}\), recomputes each CNF from the shared base and its 210
units, verifies all file identities, and rejects a missing, duplicated,
misindexed, or hash-mismatched receipt.

All 266 roots are UNSAT. Therefore no 40-block \((12,6,4)\) cover exists.

## 5. Certificate record

No digest in this table is populated from an unverified or partial proof.

| Claim | Variables | Clauses | Pinned identity | Checked proof |
|---|---:|---:|---|---|
| Local degree-five exclusion | 6,816 | 24,835 | `bcb0b4138a34e0fc8b795f24d18d97e98f9d6a8e9f5b90c26e51f9e548a5ba32` | DRAT, C LRAT, and CakeML LRAT verified |
| Compact shared global base | 122,519 | 356,407 | `637d9326388f77f933f3d066cd762d8c0ac4b2df0d2260d688e031d55959e7f0` | semantic and byte audit verified |
| Functional encoding cross-check | 271,068 | 1,044,768 | `fc7e5de081b3805cd8c77f27c581b6fd6ab3a97b92a2928c3d60fafd2fb76e73` | gate audit verified |
| Fixed-link classification | — | — | `369a844c4590d435fc24f82424a0775d51ce326d243aaf740d025c52c81d652b` | independent 359,100/119,700/266 partition audit verified |
| 266 fixed-link roots | 122,519 each | 356,617 each | `8735ea4aedb5d30fc1fa65ff289f4357bec14d354a993270a620254d30ff575a` | DRAT, C LRAT, and CakeML LRAT verified for every root |

The functional encoding is not substituted for any compact fixed-link root.
The fixed-link proof archives have SHA-256 identities
`67acd4729329ad4656b5a94e8a472b11a14a5c81fccaa468448f12957663af4a`
(DRAT) and
`c45ea9e621db38f4e25f290cb664352c0b80f1839ad475b422098b12fbbbd615`
(LRAT). Their deterministic member index and the aggregate above are bound by
the release-assets logical identity
`499c345b3d48666b67b17df2dda79b6f7af5e7fa7c05668900eb9cd7b5bee2f6`.

## 6. The 41-block upper bound

The La Jolla Covering Repository publishes a 41-block
\((12,6,4)\) cover. The exact block list is included in
`data/cover_41.txt`. The independent verifier checks that:

- there are 41 distinct blocks of size six on 12 points;
- every one of the \(\binom{12}{4}=495\) quadruples is covered; and
- the multiplicity histograms agree with the pinned verification record.

Thus \(C(12,6,4)\le41\). Section 4 gives
\(C(12,6,4)\ge41\), and therefore

\[
\boxed{C(12,6,4)=41}.
\]

## 7. Scope and review

This is a computer-assisted proof, not a claim that the result has already
passed journal peer review. The theorem depends only on the human reductions,
the small auditable generators, and the replayed proof certificates. CP-SAT,
Gurobi, and exploratory searches in the evidence directory are corroborating
checks and are not used as proof.

The accompanying search record documents the authoritative repository state,
indexed-web and GitHub searches, and a direct seven-day X API search. That
record supports a novelty check; it cannot prove universal absence from
unindexed pages or from X's unavailable full archive.

## 8. References

1. J. Schönheim, "On coverings," *Pacific Journal of Mathematics* **14**
   (1964), 1405-1411.
   [doi:10.2140/pjm.1964.14.1405](https://doi.org/10.2140/pjm.1964.14.1405).
2. D. Gordon, *La Jolla Covering Repository*, entry for
   \(C(12,6,4)\), accessed 24 July 2026.
   [cover entry](https://ljcr.dmgordon.org/cover/show_cover.php?v=12&k=6&t=4).
3. D. Gordon, *La Jolla Coverings Repository*, dataset version 1.2,
   24 April 2026.
   [doi:10.5281/zenodo.19735294](https://doi.org/10.5281/zenodo.19735294).

## 9. Computational disclosure

Dennison Bertram directed and published this work. OpenAI Codex assisted with
problem selection, proof exploration, implementation, certificate
orchestration, auditing, and drafting. Claude Fable was used as an
adversarial reviewer at xhigh effort. Claude Opus 5 was separately used at
xhigh effort for an adversarial certificate audit and an independent search
for new mathematical structure. No language-model assertion is used as proof:
the finite claims are represented by deterministic source, pinned instances,
hash manifests, and independently replayable certificates. The complete
review record and tool provenance accompany this note.
