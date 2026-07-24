#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using U64 = std::uint64_t;
using Cover = std::array<U64, 4>;

namespace {

constexpr int POINTS = 10;
constexpr int PAIRS = 45;
constexpr int BLOCKS = 210;

std::array<std::array<int, POINTS>, POINTS> pair_id{};
std::array<std::array<int, 4>, BLOCKS> block_points{};
std::array<U64, BLOCKS> block_pairs{};
std::array<std::vector<int>, PAIRS> blocks_by_pair;

std::array<int, 9> selected{};
std::vector<Cover> solutions;
std::uint64_t calls = 0;
int target_blocks = 9;
int maximum_waste = 9;

inline int popcount(U64 x) {
  return __builtin_popcountll(x);
}

inline bool bit_is_set(const Cover &bits, int index) {
  return (bits[index >> 6] >> (index & 63)) & 1ULL;
}

inline void set_bit(Cover &bits, int index) {
  bits[index >> 6] |= 1ULL << (index & 63);
}

void record_solution() {
  Cover cover{};
  for (int i = 0; i < target_blocks; ++i) {
    set_bit(cover, selected[i]);
  }
  solutions.push_back(cover);
}

void search(U64 uncovered, int depth, int waste, const Cover &forbidden) {
  ++calls;
  if (uncovered == 0) {
    if (depth == target_blocks) {
      record_solution();
    }
    return;
  }
  if (depth == target_blocks) {
    return;
  }
  if (popcount(uncovered) > 6 * (target_blocks - depth)) {
    return;
  }

  // A fail-fast availability check is independent of the branching rule.
  U64 pending = uncovered;
  while (pending) {
    const int p = __builtin_ctzll(pending);
    bool available = false;
    for (int block : blocks_by_pair[p]) {
      if (!bit_is_set(forbidden, block)) {
        available = true;
        break;
      }
    }
    if (!available) {
      return;
    }
    pending &= pending - 1;
  }

  // Canonical witness rule: let p be the least uncovered pair. In a completed
  // cover, the next witness is the least-indexed not-yet-selected block that
  // covers p. A branch choosing block b therefore forbids all smaller blocks
  // covering p. This produces every set once, rather than generating ordered
  // covers and deduplicating them.
  const int pivot = __builtin_ctzll(uncovered);
  Cover branch_forbidden = forbidden;
  for (int block : blocks_by_pair[pivot]) {
    if (bit_is_set(forbidden, block)) {
      continue;
    }
    const int added_waste = popcount(block_pairs[block] & ~uncovered);
    if (waste + added_waste <= maximum_waste) {
      selected[depth] = block;
      search(uncovered & ~block_pairs[block], depth + 1,
             waste + added_waste, branch_forbidden);
    }
    // Later branches choose a larger witness, so this candidate is forbidden
    // in their completions. It remains allowed inside the branch just run.
    set_bit(branch_forbidden, block);
  }
}

void initialize() {
  int p = 0;
  for (int a = 0; a < POINTS; ++a) {
    for (int b = a + 1; b < POINTS; ++b) {
      pair_id[a][b] = pair_id[b][a] = p++;
    }
  }

  int index = 0;
  for (int a = 0; a < POINTS; ++a) {
    for (int b = a + 1; b < POINTS; ++b) {
      for (int c = b + 1; c < POINTS; ++c) {
        for (int d = c + 1; d < POINTS; ++d) {
          block_points[index] = {a, b, c, d};
          U64 mask = 0;
          const int q[4] = {a, b, c, d};
          for (int i = 0; i < 4; ++i) {
            for (int j = i + 1; j < 4; ++j) {
              const int id = pair_id[q[i]][q[j]];
              mask |= 1ULL << id;
              blocks_by_pair[id].push_back(index);
            }
          }
          block_pairs[index] = mask;
          ++index;
        }
      }
    }
  }
  if (p != PAIRS || index != BLOCKS) {
    std::abort();
  }
}

void write_covers(const std::string &path) {
  std::sort(solutions.begin(), solutions.end());
  const auto duplicate =
      std::adjacent_find(solutions.begin(), solutions.end());
  if (duplicate != solutions.end()) {
    std::cerr << "internal error: canonical enumeration produced a duplicate\n";
    std::exit(2);
  }

  std::ofstream out(path, std::ios::binary);
  for (const Cover &cover : solutions) {
    for (int block = 0; block < BLOCKS; ++block) {
      if (bit_is_set(cover, block)) {
        out << block << ' ';
      }
    }
    out << '\n';
  }
}

}  // namespace

int main(int argc, char **argv) {
  if (argc != 3) {
    std::cerr << "usage: canonical_enum TARGET_BLOCKS OUTPUT\n";
    return 2;
  }
  target_blocks = std::stoi(argv[1]);
  if (target_blocks < 1 || target_blocks > 9) {
    std::cerr << "TARGET_BLOCKS must be in 1..9\n";
    return 2;
  }
  maximum_waste = 6 * target_blocks - PAIRS;
  if (maximum_waste < 0) {
    std::cout << "target=" << target_blocks
              << " solutions=0 calls=0 elapsed_seconds=0\n";
    std::ofstream(argv[2], std::ios::binary);
    return 0;
  }

  initialize();
  const auto start = std::chrono::steady_clock::now();
  Cover forbidden{};
  search((1ULL << PAIRS) - 1, 0, 0, forbidden);
  write_covers(argv[2]);
  const auto stop = std::chrono::steady_clock::now();
  const double seconds =
      std::chrono::duration<double>(stop - start).count();
  std::cout << "target=" << target_blocks
            << " solutions=" << solutions.size()
            << " calls=" << calls
            << " elapsed_seconds=" << seconds << '\n';
  return 0;
}
