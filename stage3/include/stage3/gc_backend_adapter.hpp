#pragma once

#include "stage3/batched_comparison_backend.hpp"

namespace ctfpsi::stage3 {

class BatchedYaoBackend final : public BatchedComparisonBackend {
 public:
  BatchedCompareResult Compare(const BatchedCompareRequest& request) const override;
};

}  // namespace ctfpsi::stage3

