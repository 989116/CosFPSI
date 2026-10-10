#pragma once

#include <array>
#include <cstdint>
#include <limits>
#include <vector>

namespace ctfpsi::common {

using CandidateId = std::uint32_t;
using CandidateList = std::vector<CandidateId>;

using BinaryFingerprint = std::vector<bool>;
using DenseVector = std::vector<double>;
using DenseMatrix = std::vector<DenseVector>;

using ByteBlock = std::array<std::uint8_t, 16>;

struct BfvPackRef {
  std::uint32_t pack_id = std::numeric_limits<std::uint32_t>::max();
  std::uint32_t lane = 0;

  bool IsValid() const {
    return pack_id != std::numeric_limits<std::uint32_t>::max();
  }

  bool operator==(const BfvPackRef& other) const {
    return pack_id == other.pack_id && lane == other.lane;
  }
};

}  // namespace ctfpsi::common


