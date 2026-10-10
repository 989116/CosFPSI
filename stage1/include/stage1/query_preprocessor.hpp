#pragma once

#include <cstddef>

#include "common/types.hpp"

namespace ctfpsi::stage1 {

struct QueryBundle {
  common::BinaryFingerprint simhash_bits;
  common::DenseVector dense_query;
  common::DenseVector normalized_query;
};

class QueryPreprocessor {
 public:
  QueryBundle Prepare(const common::DenseVector& raw_query) const;
  QueryBundle Prepare(const common::DenseVector& raw_query,
                      std::size_t simhash_bits) const;
};

}  // namespace ctfpsi::stage1
