#pragma once

#include <vector>

#include "common/types.hpp"
#include "stage1/query_preprocessor.hpp"

namespace ctfpsi::pipeline {

struct ManyToManyInput {
  std::vector<common::BinaryFingerprint> sender_fingerprints;
  common::DenseMatrix sender_vectors;
  std::vector<stage1::QueryBundle> query_bundles;
  common::DenseMatrix query_vectors;
};

}  // namespace ctfpsi::pipeline

