#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <iostream>
#include <unordered_set>
#include <vector>

// Exhaustively certify that a nine-block C(10,4,2) cannot have a point x
// of degree five.
//
// Delete x.  Its five incident blocks become five distinct triples on nine
// vertices.  Their vertex-union is all nine vertices because every pair xy
// was covered.  The other four blocks become quadruples.  Together, the five
// triples and four quadruples must cover every edge of K_9.
//
// By S_9 symmetry, one of the five triples may be fixed as {0,1,2}.  We
// enumerate every unordered choice of the other four distinct triples and,
// for each vertex-covering family, test by complete recursion whether its
// residual edges can be covered by at most four quadruples.
//
// The quadruple recursion deliberately permits repetitions.  This enlarges
// the search space, so an UNSAT result remains a valid certificate for the
// original problem, where blocks are distinct.

struct SetData {
  uint16_t vertices;
  uint64_t edges;
};

static int edge_id[9][9];
static uint64_t all_edges;
static std::vector<SetData> triples;
static std::vector<SetData> quads;
static std::array<std::vector<int>, 36> quads_by_edge;
static std::unordered_set<uint64_t> impossible_cache[5];
static std::vector<int> current_quads;
static std::vector<int> answer_quads;

static uint64_t edge_mask(const std::vector<int>& vertices) {
  uint64_t mask = 0;
  for (size_t i = 0; i < vertices.size(); ++i)
    for (size_t j = i + 1; j < vertices.size(); ++j)
      mask |= uint64_t{1} << edge_id[vertices[i]][vertices[j]];
  return mask;
}

// Return true exactly when "uncovered" can be covered by at most "remaining"
// quadruples, with repetitions allowed.
static bool cover_by_quads(uint64_t uncovered, int remaining) {
  if (uncovered == 0) {
    answer_quads = current_quads;
    return true;
  }
  if (remaining == 0) return false;
  if (std::popcount(uncovered) > 6 * remaining) return false;
  if (impossible_cache[remaining].contains(uncovered)) return false;

  // Choose an uncovered edge whose best available quadruple covers as few
  // currently uncovered edges as possible.  This fail-first rule changes
  // only the order of an otherwise exhaustive recursion.
  int chosen_edge = -1;
  int chosen_best_gain = 99;
  for (int edge = 0; edge < 36; ++edge) {
    if (!(uncovered & (uint64_t{1} << edge))) continue;
    int best_gain = 0;
    for (int qi : quads_by_edge[edge])
      best_gain =
          std::max(best_gain,
                   std::popcount(uncovered & quads[qi].edges));
    if (best_gain < chosen_best_gain) {
      chosen_best_gain = best_gain;
      chosen_edge = edge;
    }
  }

  auto candidates = quads_by_edge[chosen_edge];
  std::sort(candidates.begin(), candidates.end(), [&](int a, int b) {
    return std::popcount(uncovered & quads[a].edges) >
           std::popcount(uncovered & quads[b].edges);
  });
  for (int qi : candidates) {
    const uint64_t next = uncovered & ~quads[qi].edges;
    if (next == uncovered) continue;
    current_quads.push_back(qi);
    if (cover_by_quads(next, remaining - 1)) return true;
    current_quads.pop_back();
  }

  impossible_cache[remaining].insert(uncovered);
  return false;
}

int main() {
  int next_edge = 0;
  for (int i = 0; i < 9; ++i)
    for (int j = i + 1; j < 9; ++j)
      edge_id[i][j] = edge_id[j][i] = next_edge++;
  if (next_edge != 36) return 2;
  all_edges = (uint64_t{1} << 36) - 1;

  for (int a = 0; a < 9; ++a)
    for (int b = a + 1; b < 9; ++b)
      for (int c = b + 1; c < 9; ++c) {
        const std::vector<int> vertices{a, b, c};
        triples.push_back(
            {uint16_t((1u << a) | (1u << b) | (1u << c)),
             edge_mask(vertices)});
      }

  for (int a = 0; a < 9; ++a)
    for (int b = a + 1; b < 9; ++b)
      for (int c = b + 1; c < 9; ++c)
        for (int d = c + 1; d < 9; ++d) {
          const std::vector<int> vertices{a, b, c, d};
          const int qi = static_cast<int>(quads.size());
          quads.push_back(
              {uint16_t((1u << a) | (1u << b) | (1u << c) |
                        (1u << d)),
               edge_mask(vertices)});
          for (int edge = 0; edge < 36; ++edge)
            if (quads.back().edges & (uint64_t{1} << edge))
              quads_by_edge[edge].push_back(qi);
        }

  if (triples.size() != 84 || quads.size() != 126) return 2;

  int fixed = -1;
  const uint16_t fixed_vertices = (1u << 0) | (1u << 1) | (1u << 2);
  for (int i = 0; i < static_cast<int>(triples.size()); ++i)
    if (triples[i].vertices == fixed_vertices) fixed = i;
  if (fixed < 0) return 2;

  uint64_t triple_families = 0;
  uint64_t vertex_covering_families = 0;
  for (int a = 0; a < static_cast<int>(triples.size()); ++a) {
    if (a == fixed) continue;
    for (int b = a + 1; b < static_cast<int>(triples.size()); ++b) {
      if (b == fixed) continue;
      for (int c = b + 1; c < static_cast<int>(triples.size()); ++c) {
        if (c == fixed) continue;
        for (int d = c + 1; d < static_cast<int>(triples.size()); ++d) {
          if (d == fixed) continue;
          ++triple_families;
          const uint16_t vertex_union =
              triples[fixed].vertices | triples[a].vertices |
              triples[b].vertices | triples[c].vertices |
              triples[d].vertices;
          if (vertex_union != (1u << 9) - 1) continue;
          ++vertex_covering_families;

          const uint64_t covered =
              triples[fixed].edges | triples[a].edges | triples[b].edges |
              triples[c].edges | triples[d].edges;
          const uint64_t uncovered = all_edges & ~covered;
          current_quads.clear();
          answer_quads.clear();
          if (cover_by_quads(uncovered, 4)) {
            std::cout << "COUNTEREXAMPLE FOUND\n";
            std::cout << "triple_indices " << fixed << " " << a << " " << b
                      << " " << c << " " << d << "\n";
            std::cout << "quad_indices";
            for (int qi : answer_quads) std::cout << " " << qi;
            std::cout << "\n";
            return 1;
          }
        }
      }
    }
  }

  // C(83,4): every four-subset of the 83 non-fixed triples.
  if (triple_families != 1'837'620) return 2;

  std::cout << "VERIFIED UNSAT degree-5 case\n";
  std::cout << "triple_families " << triple_families << "\n";
  std::cout << "vertex_covering_families " << vertex_covering_families
            << "\n";
  for (int remaining = 1; remaining <= 4; ++remaining)
    std::cout << "false_cache_" << remaining << " "
              << impossible_cache[remaining].size() << "\n";
  return 0;
}
