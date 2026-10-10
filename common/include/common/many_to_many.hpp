#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include "common/types.hpp"

namespace ctfpsi::common {

using QueryId = std::uint32_t;
using PairToken = std::uint64_t;
using CandidateHandle = std::uint64_t;

inline constexpr QueryId kInvalidQueryId =
    std::numeric_limits<QueryId>::max();
inline constexpr PairToken kInvalidPairToken = 0;
inline constexpr CandidateHandle kInvalidCandidateHandle = 0;

struct QueryCandidatePair {
  // query_id is receiver-local routing metadata. Protocol messages should use
  // pair_token rather than exposing this database-independent local index.
  QueryId query_id = kInvalidQueryId;
  // candidate_id is the in-process canonical identifier. A separated sender
  // deployment resolves candidate_handle in its own local handle table.
  CandidateId candidate_id = std::numeric_limits<CandidateId>::max();
  PairToken pair_token = kInvalidPairToken;
  CandidateHandle candidate_handle = kInvalidCandidateHandle;
  bool valid = false;
};

struct PairRelation {
  std::vector<QueryCandidatePair> pairs;
  bool overflow = false;
  std::size_t required_pair_count = 0;
  std::string overflow_reason;
};

}  // namespace ctfpsi::common


