#pragma once

#include <cstddef>
#include <string>

namespace ctfpsi::stage1 {

struct Stage1ThresholdParameterInput {
  double cosine_threshold = 0.75;
  std::size_t simhash_bits = 32;
  std::size_t num_blocks = 16;
  double hamming_sigma_margin = 2.0;
  // Positive values select an exact Binomial(L, acos(tau)/pi) quantile.
  // A positive target selects the binomial-quantile recall policy.
  double target_recall = 0.0;
  std::size_t min_block_radius = 1;
  std::size_t max_block_radius = 0;  // 0 means no explicit cap.
};

struct Stage1ThresholdParameters {
  bool ok = false;
  std::string error;

  double cosine_threshold = 0.0;
  double theta_radians = 0.0;
  double mismatch_probability = 0.0;
  double hamming_mean = 0.0;
  double hamming_stddev = 0.0;
  double target_recall = 0.0;
  double estimated_recall_at_threshold = 0.0;

  std::size_t simhash_bits = 0;
  std::size_t num_blocks = 0;
  std::size_t hamming_threshold = 0;
  std::size_t block_radius = 0;
  bool block_radius_recall_safe = false;

  std::string recall_policy;
};

Stage1ThresholdParameters DeriveStage1ThresholdParameters(const Stage1ThresholdParameterInput& input);

// Analytical probability that a random-hyperplane fingerprint pair with the
// supplied cosine similarity falls inside a fixed Hamming radius.
double EstimateStage1HammingAcceptanceProbability(
    std::size_t simhash_bits,
    std::size_t hamming_threshold,
    double cosine_similarity);

}  // namespace ctfpsi::stage1
