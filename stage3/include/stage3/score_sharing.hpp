#pragma once

#include <cstdint>
#include <vector>

namespace ctfpsi::stage3 {
using RingElem = std::uint64_t;
struct AdditiveShares {
  std::vector<RingElem> party0;
  std::vector<RingElem> party1;
};
}  // namespace ctfpsi::stage3

