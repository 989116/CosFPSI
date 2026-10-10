#include "stage1/query_preprocessor.hpp"

#include <cmath>
#include <cstddef>
#include <cstdint>

#include "common/config.hpp"

namespace ctfpsi::stage1 {
namespace {

std::uint64_t Mix64(std::uint64_t x) {
  x += 0x9e3779b97f4a7c15ULL;
  x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
  x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
  return x ^ (x >> 31);
}

double ProjectionSign(std::size_t bit_idx, std::size_t dim_idx) {
  const std::uint64_t seed =
      (static_cast<std::uint64_t>(common::config::stage1::kProjectionSeed) << 32) ^
      static_cast<std::uint64_t>(bit_idx * 1315423911ULL + dim_idx * 2654435761ULL + 17ULL);
  return (Mix64(seed) & 1ULL) == 0ULL ? -1.0 : 1.0;
}

common::DenseVector Normalize(const common::DenseVector& in) {
  common::DenseVector out = in;
  double norm2 = 0.0;
  for (const double x : out) {
    norm2 += x * x;
  }
  const double norm = std::sqrt(norm2);
  if (norm > 1e-12) {
    for (double& x : out) {
      x /= norm;
    }
  }
  return out;
}

}  // namespace

QueryBundle QueryPreprocessor::Prepare(const common::DenseVector& raw_query) const {
  return Prepare(raw_query, common::config::stage1::kSimHashBits);
}

QueryBundle QueryPreprocessor::Prepare(
    const common::DenseVector& raw_query,
    std::size_t simhash_bits) const {
  QueryBundle bundle;
  bundle.dense_query = raw_query;

  if (common::config::stage1::kEnableL2NormalizeBeforeSimHash) {
    bundle.normalized_query = Normalize(raw_query);
  } else {
    bundle.normalized_query = raw_query;
  }

  bundle.simhash_bits.assign(simhash_bits, false);

  for (std::size_t bit = 0; bit < simhash_bits; ++bit) {
    double proj = 0.0;
    for (std::size_t d = 0; d < bundle.normalized_query.size(); ++d) {
      proj += bundle.normalized_query[d] * ProjectionSign(bit, d);
    }
    bundle.simhash_bits[bit] = (proj >= 0.0);
  }

  return bundle;
}

}  // namespace ctfpsi::stage1
