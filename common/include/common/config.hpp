#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>

#include "common/types.hpp"

namespace ctfpsi::common::config {
namespace stage1 {
inline constexpr std::size_t kNumStripes = 16;
inline constexpr std::size_t kNeighborRadius = 8;
inline constexpr std::size_t kNumBlocks = kNumStripes;
inline constexpr bool kEnableL2NormalizeBeforeSimHash = true;
inline constexpr std::size_t kSimHashBits = 64;
inline constexpr std::uint32_t kProjectionSeed = 20260327u;
inline constexpr double kCosineThreshold = 0.75;
inline constexpr double kHammingSigmaMargin = 2.0;
inline constexpr double kTargetRecall = 0.99;
inline constexpr std::size_t kMinBlockRadius = 1;
inline constexpr std::size_t kMaxBlockRadius = 0;
inline constexpr std::size_t kRbokvsValueLengthBlocks = 4;
inline constexpr double kRbokvsEpsilon = 0.10;
inline constexpr std::uint64_t kRbokvsStatSecParam = 40;
inline constexpr std::uint64_t kRbokvsSeedHi = 0x53494d4648455255ULL;
inline constexpr std::uint64_t kRbokvsSeedLo = 0x52424f4b56533031ULL;
inline constexpr std::size_t kPayloadZeroPaddingBytes = 32;
inline constexpr std::uint32_t kPayloadVersion = 2;
}  // namespace stage1

inline constexpr std::size_t kCandidateCapC0 = 0;
inline constexpr CandidateId kDummyId = std::numeric_limits<CandidateId>::max();
}  // namespace ctfpsi::common::config

