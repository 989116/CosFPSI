#include "stage1/threshold_parameterization.hpp"

#include <algorithm>
#include <cmath>
#include <limits>

namespace ctfpsi::stage1 {
namespace {

constexpr double kPi = 3.141592653589793238462643383279502884;

std::size_t ClampToSizeT(double x, std::size_t lower, std::size_t upper) {
  if (x <= static_cast<double>(lower)) {
    return lower;
  }
  if (x >= static_cast<double>(upper)) {
    return upper;
  }
  return static_cast<std::size_t>(x);
}

double BinomialCdf(std::size_t n, double p, std::size_t h) {
  if (h >= n || p <= 0.0) return 1.0;
  if (p >= 1.0) return h >= n ? 1.0 : 0.0;
  long double sum = 0.0L;
  for (std::size_t k = 0; k <= h; ++k) {
    const long double log_probability =
        std::lgamma(static_cast<long double>(n + 1)) -
        std::lgamma(static_cast<long double>(k + 1)) -
        std::lgamma(static_cast<long double>(n - k + 1)) +
        static_cast<long double>(k) * std::log(p) +
        static_cast<long double>(n - k) * std::log1p(-p);
    sum += std::exp(log_probability);
  }
  return std::clamp(static_cast<double>(sum), 0.0, 1.0);
}

std::size_t BinomialQuantile(std::size_t n, double p, double target) {
  for (std::size_t h = 0; h <= n; ++h) {
    if (BinomialCdf(n, p, h) >= target) return h;
  }
  return n;
}

}  // namespace

Stage1ThresholdParameters DeriveStage1ThresholdParameters(const Stage1ThresholdParameterInput& input) {
  Stage1ThresholdParameters out;

  if (input.simhash_bits == 0) {
    out.error = "simhash_bits must be > 0.";
    return out;
  }
  if (input.num_blocks == 0) {
    out.error = "num_blocks must be > 0.";
    return out;
  }

  const double tau = std::clamp(input.cosine_threshold, -1.0, 1.0);
  const double theta = std::acos(tau);
  const double p = std::clamp(theta / kPi, 0.0, 1.0);
  const double l = static_cast<double>(input.simhash_bits);
  const double mean = l * p;
  const double variance = l * p * (1.0 - p);
  const double stdev = variance > 0.0 ? std::sqrt(variance) : 0.0;

  const double requested_recall =
      std::clamp(input.target_recall, 0.0, 1.0);
  std::size_t h = 0;
  if (requested_recall > 0.0) {
    h = BinomialQuantile(input.simhash_bits, p, requested_recall);
  } else {
    const double sigma_margin = std::max(0.0, input.hamming_sigma_margin);
    const double h_raw = std::ceil(mean + sigma_margin * stdev);
    h = ClampToSizeT(h_raw, 0, input.simhash_bits);
  }

  // Block radius policy: r = ceil(H / m), so m * r >= H for recall safety.
  const std::size_t m = input.num_blocks;
  const std::size_t r_uncapped = (h + m - 1) / m;

  std::size_t r = std::max(input.min_block_radius, r_uncapped);
  if (input.max_block_radius > 0) {
    r = std::min(r, input.max_block_radius);
  }
  const bool radius_recall_safe = r * m >= h;
  if (!radius_recall_safe) {
    out.error = "max_block_radius violates the Stage1 recall contract";
    return out;
  }

  out.ok = true;
  out.cosine_threshold = tau;
  out.theta_radians = theta;
  out.mismatch_probability = p;
  out.hamming_mean = mean;
  out.hamming_stddev = stdev;
  out.target_recall = requested_recall;
  out.estimated_recall_at_threshold =
      BinomialCdf(input.simhash_bits, p, h);
  out.simhash_bits = input.simhash_bits;
  out.num_blocks = input.num_blocks;
  out.hamming_threshold = h;
  out.block_radius = r;
  out.block_radius_recall_safe = radius_recall_safe;
  out.recall_policy = requested_recall > 0.0
      ? "H=BinomialQuantile(L,acos(tau)/pi,target_recall), r=ceil(H/m)"
      : "H=ceil(L*p+sigma*sqrt(L*p*(1-p))), r=ceil(H/m)";

  return out;
}

double EstimateStage1HammingAcceptanceProbability(
    std::size_t simhash_bits,
    std::size_t hamming_threshold,
    double cosine_similarity) {
  if (simhash_bits == 0) return 0.0;
  const double tau = std::clamp(cosine_similarity, -1.0, 1.0);
  const double p = std::acos(tau) / kPi;
  return BinomialCdf(simhash_bits, p, hamming_threshold);
}

}  // namespace ctfpsi::stage1
