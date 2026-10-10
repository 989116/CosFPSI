#include "stage2/exact_he_masked_score.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <numeric>
#include <set>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#ifndef CTFPSI_HAS_OPENFHE
#define CTFPSI_HAS_OPENFHE 0
#endif

#if CTFPSI_HAS_OPENFHE
#include "openfhe.h"
#include <openssl/rand.h>
#endif

namespace ctfpsi::stage2 {
namespace {

using Clock = std::chrono::steady_clock;

std::uint64_t NextExactHeSessionId() {
  static std::atomic<std::uint64_t> next_id{1};
  return next_id.fetch_add(1, std::memory_order_relaxed);
}

double MillisSince(const Clock::time_point& start) {
  return std::chrono::duration<double, std::milli>(Clock::now() - start)
      .count();
}

#if CTFPSI_HAS_OPENFHE
void FillUniformMod(
    std::vector<std::int64_t>* output,
    std::uint32_t modulus) {
  if (output == nullptr || modulus == 0) {
    throw std::invalid_argument("BFV mask sampler received invalid output/modulus");
  }
  const std::uint64_t range = std::uint64_t{1} << 32;
  const std::uint64_t limit = (range / modulus) * modulus;
  thread_local std::vector<std::uint32_t> words;
  words.resize(output->size());
  std::size_t filled = 0;
  while (filled < output->size()) {
    const std::size_t requested = output->size() - filled;
    if (requested > static_cast<std::size_t>(std::numeric_limits<int>::max()) /
                        sizeof(std::uint32_t)) {
      throw std::overflow_error("BFV mask batch exceeds RAND_bytes input range");
    }
    if (RAND_bytes(
            reinterpret_cast<unsigned char*>(words.data()),
            static_cast<int>(requested * sizeof(std::uint32_t))) != 1) {
      throw std::runtime_error("OpenSSL RAND_bytes failed while sampling BFV masks");
    }
    for (std::size_t i = 0; i < requested && filled < output->size(); ++i) {
      const std::uint32_t word = words[i];
      if (static_cast<std::uint64_t>(word) < limit) {
        (*output)[filled++] = static_cast<std::int64_t>(word % modulus);
      }
    }
  }
}

std::uint32_t CanonicalResidue(std::int64_t value, std::uint32_t modulus) {
  std::int64_t residue = value % static_cast<std::int64_t>(modulus);
  if (residue < 0) {
    residue += modulus;
  }
  return static_cast<std::uint32_t>(residue);
}

std::size_t EstimateDcrtCiphertextPayloadBytes(
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ciphertext) {
  if (!ciphertext) {
    return 0;
  }
  std::size_t bytes = 0;
  for (const auto& element : ciphertext->GetElements()) {
    for (const auto& tower : element.GetAllElements()) {
      bytes += static_cast<std::size_t>(tower.GetLength()) *
               sizeof(std::uint64_t);
    }
  }
  return bytes;
}

std::size_t DcrtCiphertextTowerCount(
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ciphertext) {
  if (!ciphertext || ciphertext->GetElements().empty()) {
    return 0;
  }
  return ciphertext->GetElements().front().GetNumOfElements();
}

double Log2Add(double lhs, double rhs) {
  if (!std::isfinite(lhs)) return rhs;
  if (!std::isfinite(rhs)) return lhs;
  const double hi = std::max(lhs, rhs);
  const double lo = std::min(lhs, rhs);
  return hi + std::log2(1.0 + std::exp2(lo - hi));
}

struct BfvCircuitPrivacyAudit {
  bool supported = false;
  std::string error_message;
  double encryption_error_stddev = 0.0;
  std::size_t initial_tower_count = 0;
  double ciphertext_modulus_log2 = 0.0;
  double final_modulus_log2 = 0.0;
  double divisor_log2 = 0.0;
  double homomorphic_noise_bound_log2 = 0.0;
  double required_divisor_log2 = 0.0;
  double security_margin_bits = 0.0;
  double gaussian_tail_failure_log2 = 0.0;
  double boundary_failure_log2 = 0.0;
  double joint_failure_log2 = 0.0;
  double correctness_required_modulus_log2 = 0.0;
  double correctness_margin_bits = 0.0;
};

BfvCircuitPrivacyAudit AuditBfvCircuitPrivacy(
    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& cc,
    const ExactHeMaskedScoreConfig& config) {
  using namespace lbcrypto;
  BfvCircuitPrivacyAudit audit;
  const auto params = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(
      cc->GetCryptoParameters());
  if (!params) {
    audit.error_message = "BFV circuit privacy requires BFVRNS parameters";
    return audit;
  }
  if (!config.compress_masked_score_ciphertext ||
      config.masked_score_towers_left != 1) {
    audit.error_message =
        "BFV circuit-privacy parameter checks require divide-and-round compression to one tower";
    return audit;
  }
  if (params->GetEncryptionTechnique() != STANDARD ||
      params->GetMultiplicationTechnique() != HPSPOVERQLEVELED ||
      params->GetKeySwitchTechnique() != BV) {
    audit.error_message =
        "BFV circuit-privacy parameter checks require STANDARD encryption, HPSPOVERQLEVELED multiplication, and BV key switching";
    return audit;
  }
  if (config.circuit_privacy_statistical_security_bits == 0 ||
      config.circuit_privacy_max_decryption_queries == 0 ||
      config.circuit_privacy_error_coefficient_bound == 0 ||
      config.circuit_privacy_modulus_bits == 0) {
    audit.error_message = "BFV circuit privacy parameters must be non-zero";
    return audit;
  }

  const auto& towers = params->GetElementParams()->GetParams();
  audit.initial_tower_count = towers.size();
  if (towers.size() < 2) {
    audit.error_message =
        "BFV circuit privacy requires at least one modulus tower to divide out";
    return audit;
  }
  std::vector<double> tower_log2;
  tower_log2.reserve(towers.size());
  for (const auto& tower : towers) {
    tower_log2.push_back(
        std::log2(tower->GetModulus().ConvertToDouble()));
  }
  audit.ciphertext_modulus_log2 =
      std::accumulate(tower_log2.begin(), tower_log2.end(), 0.0);
  audit.final_modulus_log2 = tower_log2.front();
  audit.divisor_log2 =
      std::accumulate(tower_log2.begin() + 1, tower_log2.end(), 0.0);
  audit.encryption_error_stddev = params->GetDistributionParameter();

  const double n = static_cast<double>(params->GetElementParams()->GetRingDimension());
  const double p = static_cast<double>(config.plaintext_modulus);
  const double error_bound =
      static_cast<double>(config.circuit_privacy_error_coefficient_bound);
  const double fresh_error_log2 =
      std::log2(error_bound) + std::log2(2.0 * n + 1.0);
  const double plaintext_poly_bound_log2 = std::log2(std::floor(p / 2.0));
  double evaluated_error_log2 =
      std::log2(n) + plaintext_poly_bound_log2 + fresh_error_log2;

  std::size_t decomposition_digits = 0;
  std::uint32_t decomposition_digit_bits =
      config.circuit_privacy_key_switch_digit_bits;
  for (const auto& tower : towers) {
    const std::uint32_t bits = tower->GetModulus().GetMSB();
    if (config.circuit_privacy_key_switch_digit_bits == 0) {
      ++decomposition_digits;
      decomposition_digit_bits = std::max(decomposition_digit_bits, bits);
    } else {
      decomposition_digits +=
          (bits + config.circuit_privacy_key_switch_digit_bits - 1) /
          config.circuit_privacy_key_switch_digit_bits;
    }
  }
  const double key_switch_error_log2 =
      std::log2(n) + std::log2(static_cast<double>(decomposition_digits)) +
      static_cast<double>(decomposition_digit_bits) +
      std::log2(error_bound);
  std::size_t rotation_count = 0;
  for (std::size_t shift = 1; shift < config.dimension; shift <<= 1) {
    ++rotation_count;
  }
  for (std::size_t i = 0; i < rotation_count; ++i) {
    evaluated_error_log2 =
        Log2Add(evaluated_error_log2 + 1.0, key_switch_error_log2);
  }
  audit.homomorphic_noise_bound_log2 =
      Log2Add(evaluated_error_log2, fresh_error_log2);

  const double query_union_bits = std::ceil(std::log2(
      static_cast<double>(config.circuit_privacy_max_decryption_queries)));
  const double per_ciphertext_security =
      static_cast<double>(config.circuit_privacy_statistical_security_bits) +
      1.0 + query_union_bits;
  const double inner_log2 = Log2Add(
      Log2Add(std::log2(2.0 * n) + 2.0 * std::log2(error_bound),
              std::log2(error_bound)),
      audit.homomorphic_noise_bound_log2);
  const double theorem_numerator_log2 = std::log2(2.0 * n) + inner_log2;
  audit.required_divisor_log2 = theorem_numerator_log2 + per_ciphertext_security;
  audit.security_margin_bits =
      audit.divisor_log2 - audit.required_divisor_log2;
  audit.boundary_failure_log2 =
      theorem_numerator_log2 - audit.divisor_log2 + query_union_bits;

  // Condition on all relevant Gaussian coefficients lying in [-B,B].
  // The union includes the public key, all permitted input/zero encryptions,
  // and every public rotation-key digit used by this fixed circuit.
  const long double max_queries = static_cast<long double>(
      config.circuit_privacy_max_decryption_queries);
  const long double gaussian_coefficients =
      static_cast<long double>(n) *
      (1.0L + 4.0L * max_queries +
       2.0L * rotation_count * decomposition_digits);
  const long double sigma = audit.encryption_error_stddev;
  const long double one_coefficient_tail_log2 =
      1.0L - (static_cast<long double>(error_bound) * error_bound) /
                 (2.0L * sigma * sigma * std::log(2.0L));
  audit.gaussian_tail_failure_log2 = static_cast<double>(
      std::log2(gaussian_coefficients) + one_coefficient_tail_log2);
  audit.joint_failure_log2 = Log2Add(
      audit.boundary_failure_log2, audit.gaussian_tail_failure_log2);

  const std::uint64_t q0 = towers.front()->GetModulus().ConvertToInt();
  const long double correctness_required =
      2.0L * p * n * error_bound + 2.0L * p +
      static_cast<long double>(q0 % config.plaintext_modulus);
  audit.correctness_required_modulus_log2 =
      static_cast<double>(std::log2(correctness_required));
  audit.correctness_margin_bits =
      audit.final_modulus_log2 - audit.correctness_required_modulus_log2;

  const double target_joint_failure =
      -static_cast<double>(config.circuit_privacy_statistical_security_bits);
  if (audit.security_margin_bits < 0.0) {
    audit.error_message =
        "BFV circuit privacy divisor is too small for the public homomorphic-noise bound";
    return audit;
  }
  if (audit.gaussian_tail_failure_log2 >
      -static_cast<double>(config.circuit_privacy_statistical_security_bits) - 1.0) {
    audit.error_message =
        "BFV Gaussian coefficient bound is too small for the configured query budget";
    return audit;
  }
  if (audit.joint_failure_log2 > target_joint_failure) {
    audit.error_message =
        "BFV circuit privacy joint statistical failure exceeds the configured target";
    return audit;
  }
  if (audit.correctness_margin_bits <= 0.0) {
    audit.error_message =
        "compressed BFV modulus has no correctness margin after circuit privacy";
    return audit;
  }
  audit.supported = true;
  return audit;
}

void CopyCircuitPrivacyAudit(
    const ExactHeMaskedScoreConfig& config,
    const BfvCircuitPrivacyAudit& audit,
    ExactHeMaskedScoreResult* result) {
  result->circuit_privacy_distribution =
      "fresh BFV encryption of zero with divide-and-round";
  result->noise_flooding_distribution = "not used";
  result->noise_flooding_stddev_applicable = false;
  result->encryption_error_stddev = audit.encryption_error_stddev;
  result->circuit_privacy_statistical_security_bits =
      config.circuit_privacy_statistical_security_bits;
  result->circuit_privacy_max_decryption_queries =
      config.circuit_privacy_max_decryption_queries;
  result->circuit_privacy_error_coefficient_bound =
      config.circuit_privacy_error_coefficient_bound;
  result->circuit_privacy_context_depth =
      config.circuit_privacy_context_depth;
  result->circuit_privacy_modulus_bits =
      config.circuit_privacy_modulus_bits;
  result->circuit_privacy_key_switch_digit_bits =
      config.circuit_privacy_key_switch_digit_bits;
  result->circuit_privacy_initial_tower_count = audit.initial_tower_count;
  result->ciphertext_modulus_log2 = audit.ciphertext_modulus_log2;
  result->circuit_privacy_divisor_log2 = audit.divisor_log2;
  result->homomorphic_noise_bound_log2 =
      audit.homomorphic_noise_bound_log2;
  result->circuit_privacy_required_divisor_log2 =
      audit.required_divisor_log2;
  result->circuit_privacy_security_margin_bits = audit.security_margin_bits;
  result->gaussian_tail_failure_log2 = audit.gaussian_tail_failure_log2;
  result->circuit_privacy_boundary_failure_log2 =
      audit.boundary_failure_log2;
  result->circuit_privacy_joint_failure_log2 = audit.joint_failure_log2;
  result->final_ciphertext_modulus_log2 = audit.final_modulus_log2;
  result->correctness_required_modulus_log2 =
      audit.correctness_required_modulus_log2;
  result->correctness_margin_bits = audit.correctness_margin_bits;
  result->circuit_privacy_parameter_check_passed = audit.supported;
  result->circuit_privacy_correctness_check_passed =
      audit.correctness_margin_bits > 0.0;
}

bool CircuitPrivacySessionConfigMatches(
    const ExactHeMaskedScoreConfig& session,
    const ExactHeMaskedScoreConfig& requested) {
  return session.plaintext_modulus == requested.plaintext_modulus &&
         session.dimension == requested.dimension &&
         session.compress_masked_score_ciphertext ==
             requested.compress_masked_score_ciphertext &&
         session.masked_score_towers_left ==
             requested.masked_score_towers_left &&
         session.require_circuit_privacy_checks ==
             requested.require_circuit_privacy_checks &&
         session.circuit_privacy_statistical_security_bits ==
             requested.circuit_privacy_statistical_security_bits &&
         session.circuit_privacy_max_decryption_queries ==
             requested.circuit_privacy_max_decryption_queries &&
         session.circuit_privacy_error_coefficient_bound ==
             requested.circuit_privacy_error_coefficient_bound &&
         session.circuit_privacy_context_depth ==
             requested.circuit_privacy_context_depth &&
         session.circuit_privacy_modulus_bits ==
             requested.circuit_privacy_modulus_bits &&
         session.circuit_privacy_key_switch_digit_bits ==
             requested.circuit_privacy_key_switch_digit_bits;
}

void CompressMaskedScoreCiphertext(
    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& cc,
    const ExactHeMaskedScoreConfig& config,
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>* ciphertext,
    ExactHeMaskedScoreResult* result) {
  if (ciphertext == nullptr || !*ciphertext || result == nullptr) {
    throw std::invalid_argument("masked BFV compression received invalid state");
  }

  const std::size_t before_bytes =
      EstimateDcrtCiphertextPayloadBytes(*ciphertext);
  const std::size_t before_towers = DcrtCiphertextTowerCount(*ciphertext);
  result->masked_score_ciphertext_bytes_before_compression += before_bytes;
  result->masked_score_towers_before_compression = std::max(
      result->masked_score_towers_before_compression, before_towers);

  if (config.compress_masked_score_ciphertext) {
    if (config.masked_score_towers_left == 0) {
      throw std::invalid_argument(
          "masked BFV compression must retain at least one RNS tower");
    }
    if (before_towers > config.masked_score_towers_left) {
      *ciphertext = cc->Compress(
          *ciphertext, config.masked_score_towers_left);
      if (!*ciphertext) {
        throw std::runtime_error("OpenFHE returned an empty compressed BFV ciphertext");
      }
      result->masked_score_ciphertext_compressed = true;
    }
  }

  const std::size_t after_towers = DcrtCiphertextTowerCount(*ciphertext);
  result->masked_score_towers_after_compression = std::max(
      result->masked_score_towers_after_compression, after_towers);
  result->masked_score_ciphertext_bytes +=
      EstimateDcrtCiphertextPayloadBytes(*ciphertext);
  result->masked_score_ciphertext_bytes_estimated = true;
}

#endif

std::uint32_t RequiredCompareBits(std::uint32_t modulus) {
  std::uint64_t bound = static_cast<std::uint64_t>(modulus) * 2 - 1;
  std::uint32_t bits = 0;
  while (bound != 0) {
    ++bits;
    bound >>= 1;
  }
  return std::max<std::uint32_t>(2, bits);
}

}  // namespace

struct PreparedExactHeCandidatePayloads::Impl {
#if CTFPSI_HAS_OPENFHE
  std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> ciphertext_packs;
#endif
  std::uint64_t session_id = 0;
};

PreparedExactHeCandidatePayloads::PreparedExactHeCandidatePayloads()
    : impl_(std::make_shared<Impl>()) {}
PreparedExactHeCandidatePayloads::~PreparedExactHeCandidatePayloads() = default;
PreparedExactHeCandidatePayloads::PreparedExactHeCandidatePayloads(
    const PreparedExactHeCandidatePayloads&) = default;
PreparedExactHeCandidatePayloads& PreparedExactHeCandidatePayloads::operator=(
    const PreparedExactHeCandidatePayloads&) = default;
PreparedExactHeCandidatePayloads::PreparedExactHeCandidatePayloads(
    PreparedExactHeCandidatePayloads&&) noexcept = default;
PreparedExactHeCandidatePayloads& PreparedExactHeCandidatePayloads::operator=(
    PreparedExactHeCandidatePayloads&&) noexcept = default;

struct ExactHeMaskedScoreSession::Impl {
  explicit Impl(const ExactHeMaskedScoreConfig& requested)
      : config(requested), session_id(NextExactHeSessionId()) {
#if !CTFPSI_HAS_OPENFHE
    error_message = "OpenFHE is unavailable";
#else
    try {
      using namespace lbcrypto;
      const auto begin = Clock::now();
      CCParams<CryptoContextBFVRNS> parameters;
      parameters.SetPlaintextModulus(config.plaintext_modulus);
      parameters.SetMultiplicativeDepth(
          config.circuit_privacy_context_depth);
      parameters.SetScalingModSize(config.circuit_privacy_modulus_bits);
      parameters.SetDigitSize(config.circuit_privacy_key_switch_digit_bits);
      parameters.SetKeySwitchTechnique(BV);
      parameters.SetEncryptionTechnique(STANDARD);
      parameters.SetMultiplicationTechnique(HPSPOVERQLEVELED);
      parameters.SetSecurityLevel(HEStd_128_classic);
      cc = GenCryptoContext(parameters);
      cc->Enable(PKE);
      cc->Enable(KEYSWITCH);
      cc->Enable(LEVELEDSHE);
      keys = cc->KeyGen();
      if (!keys.good()) {
        error_message = "OpenFHE BFV key generation failed";
        return;
      }
      slot_count = cc->GetRingDimension();
      context_creation_count = 1;
      key_generation_count = 1;
      circuit_privacy_audit = AuditBfvCircuitPrivacy(cc, config);
      if (config.require_circuit_privacy_checks &&
          !circuit_privacy_audit.supported) {
        error_message = "BFV circuit privacy parameter check failed: " +
                        circuit_privacy_audit.error_message;
        return;
      }
      initialization_ms = MillisSince(begin);
    } catch (const std::exception& ex) {
      error_message = std::string("exact BFV session setup failed: ") + ex.what();
    }
#endif
  }

  ExactHeMaskedScoreConfig config;
  const std::uint64_t session_id;
  std::string error_message;
  double initialization_ms = 0.0;
  double rotation_preparation_ms = 0.0;
  std::size_t slot_count = 0;
  std::size_t context_creation_count = 0;
  std::size_t key_generation_count = 0;
  std::size_t run_count = 0;
  std::uint64_t released_ciphertext_count = 0;
#if CTFPSI_HAS_OPENFHE
  BfvCircuitPrivacyAudit circuit_privacy_audit;
  lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cc;
  lbcrypto::KeyPair<lbcrypto::DCRTPoly> keys;
  std::set<std::int32_t> generated_rotations;
#endif
};

ExactHeMaskedScoreSession::ExactHeMaskedScoreSession(
    const ExactHeMaskedScoreConfig& config)
    : impl_(std::make_unique<Impl>(config)) {}

ExactHeMaskedScoreSession::~ExactHeMaskedScoreSession() = default;
ExactHeMaskedScoreSession::ExactHeMaskedScoreSession(
    ExactHeMaskedScoreSession&&) noexcept = default;
ExactHeMaskedScoreSession& ExactHeMaskedScoreSession::operator=(
    ExactHeMaskedScoreSession&&) noexcept = default;

void ExactHeMaskedScoreSession::PrepareRotations(
    std::size_t dimension, const std::vector<std::size_t>& lane_counts) {
#if CTFPSI_HAS_OPENFHE
  if (!impl_ || !impl_->error_message.empty()) return;
  std::vector<std::int32_t> missing;
  for (const std::size_t lanes : lane_counts) {
    for (std::size_t shift = 1; shift < dimension; shift <<= 1) {
      const std::size_t rotation = shift * lanes;
      if (rotation > static_cast<std::size_t>(
                         std::numeric_limits<std::int32_t>::max())) {
        throw std::overflow_error("packed BFV rotation exceeds int32 range");
      }
      const auto value = static_cast<std::int32_t>(rotation);
      if (impl_->generated_rotations.insert(value).second) {
        missing.push_back(value);
      }
    }
  }
  if (!missing.empty()) {
    const auto begin = Clock::now();
    impl_->cc->EvalRotateKeyGen(impl_->keys.secretKey, missing);
    impl_->rotation_preparation_ms += MillisSince(begin);
  }
#else
  (void)dimension;
  (void)lane_counts;
#endif
}

double ExactHeMaskedScoreSession::InitializationMs() const {
  return impl_ ? impl_->initialization_ms : 0.0;
}

double ExactHeMaskedScoreSession::RotationPreparationMs() const {
  return impl_ ? impl_->rotation_preparation_ms : 0.0;
}

std::size_t ExactHeMaskedScoreSession::ContextCreationCount() const {
  return impl_ ? impl_->context_creation_count : 0;
}

std::size_t ExactHeMaskedScoreSession::KeyGenerationCount() const {
  return impl_ ? impl_->key_generation_count : 0;
}

std::size_t ExactHeMaskedScoreSession::SlotCount() const {
  return impl_ ? impl_->slot_count : 0;
}

const std::string& ExactHeMaskedScoreSession::SetupErrorMessage() const {
  static const std::string missing = "missing exact BFV session";
  return impl_ ? impl_->error_message : missing;
}

PreparedExactHeCandidatePayloads
ExactHeMaskedScoreSession::PrepareSenderCandidatePacks(
    const std::vector<std::vector<std::int64_t>>& candidates,
    std::size_t candidates_per_pack) {
  PreparedExactHeCandidatePayloads result;
#if !CTFPSI_HAS_OPENFHE
  result.error_message = "OpenFHE is unavailable";
  return result;
#else
  if (!impl_ || !impl_->error_message.empty()) {
    result.error_message = impl_ ? impl_->error_message : "missing exact BFV session";
    return result;
  }
  if (candidates.empty() || candidates.front().empty() ||
      candidates_per_pack == 0 ||
      impl_->config.candidate_replication_factor == 0) {
    result.error_message = "candidate preparation requires non-empty vectors and pack width";
    return result;
  }
  const std::size_t dimension = candidates.front().size();
  if (dimension < 4 || (dimension & (dimension - 1)) != 0) {
    result.error_message = "exact BFV candidate dimension must be a power of two >= 4";
    return result;
  }
  for (const auto& candidate : candidates) {
    if (candidate.size() != dimension) {
      result.error_message = "exact BFV candidates must have one common dimension";
      return result;
    }
  }
  if (dimension * candidates_per_pack > impl_->slot_count) {
    result.error_message = "exact BFV candidate pack exceeds available slots";
    return result;
  }

  try {
    PrepareRotations(dimension, {candidates_per_pack});
    result.impl_->session_id = impl_->session_id;
    result.candidate_count = candidates.size();
    result.candidates_per_pack = candidates_per_pack;
    result.candidate_replication_factor =
        impl_->config.candidate_replication_factor;
    result.dimension = dimension;
    result.slot_count = impl_->slot_count;
    result.plaintext_modulus = impl_->config.plaintext_modulus;
    result.candidate_pack_refs.resize(candidates.size());
    result.candidate_replica_pack_refs.resize(candidates.size());
    if (candidates.size() >
        std::numeric_limits<std::size_t>::max() /
            result.candidate_replication_factor) {
      result.error_message = "exact BFV candidate replication size overflow";
      return result;
    }
    const std::size_t requested_placements =
        candidates.size() * result.candidate_replication_factor;
    const std::size_t pack_count =
        (requested_placements + candidates_per_pack - 1) /
        candidates_per_pack;
    result.impl_->ciphertext_packs.reserve(pack_count);

    const auto encrypt_begin = Clock::now();
    for (std::size_t pack = 0; pack < pack_count; ++pack) {
      std::vector<std::int64_t> packed(impl_->slot_count, 0);
      for (std::size_t lane = 0; lane < candidates_per_pack; ++lane) {
        const std::size_t placement = pack * candidates_per_pack + lane;
        std::size_t candidate_id = candidates.size();
        bool primary = false;
        if (placement < requested_placements) {
          candidate_id = placement / result.candidate_replication_factor;
          primary = placement % result.candidate_replication_factor == 0;
        } else {
          // Deterministically fill public spare slots without consulting the
          // private query-candidate relation.
          candidate_id = (placement - requested_placements) % candidates.size();
        }
        if (primary) {
          result.candidate_pack_refs[candidate_id] = ExactHeCandidatePackRef{
              static_cast<std::uint32_t>(pack),
              static_cast<std::uint32_t>(lane)};
        } else {
          result.candidate_replica_pack_refs[candidate_id].push_back(
              ExactHeCandidatePackRef{static_cast<std::uint32_t>(pack),
                                      static_cast<std::uint32_t>(lane)});
          ++result.replica_slot_count;
        }
        if (candidate_id >= candidates.size()) continue;
        ++result.populated_slot_count;
        for (std::size_t k = 0; k < dimension; ++k) {
          packed[k * candidates_per_pack + lane] =
              candidates[candidate_id][k];
        }
      }
      auto plaintext = impl_->cc->MakePackedPlaintext(packed);
      auto ciphertext = impl_->cc->Encrypt(impl_->keys.publicKey, plaintext);
      if (!ciphertext) {
        result.error_message = "OpenFHE returned an empty BFV candidate pack";
        result.impl_->ciphertext_packs.clear();
        return result;
      }
      result.ciphertext_payload_bytes +=
          EstimateDcrtCiphertextPayloadBytes(ciphertext);
      result.impl_->ciphertext_packs.push_back(std::move(ciphertext));
    }
    result.encrypt_ms = MillisSince(encrypt_begin);
    result.ciphertext_pack_count =
        result.impl_->ciphertext_packs.size();
    result.ok = true;
    return result;
  } catch (const std::exception& ex) {
    result.error_message =
        std::string("exact BFV candidate preparation failed: ") + ex.what();
    return result;
  }
#endif
}

ExactHeMaskedScoreResult ExactHeMaskedScoreSession::RunPreparedPairRelation(
    const ExactHePreparedPairBatchInput& input,
    const PreparedExactHeCandidatePayloads& prepared,
    const ExactHeMaskedScoreConfig& config) {
  ExactHeMaskedScoreResult result;
  result.plaintext_modulus = config.plaintext_modulus;
  result.threshold = config.threshold;
  result.compare_bits = RequiredCompareBits(config.plaintext_modulus);
  result.dimension = prepared.dimension;
  result.slot_count = prepared.slot_count;
  result.session_reused = impl_ && impl_->run_count != 0;
  result.used_prepared_candidate_packs = true;
  result.requested_round_parallelism = config.round_parallelism;
  result.ciphertext_sanitization_mode =
      "uniform plaintext mask, fresh encryption of zero, and divide-and-round";
  result.context_creation_count = ContextCreationCount();
  result.key_generation_count = KeyGenerationCount();
#if !CTFPSI_HAS_OPENFHE
  result.error_message = "OpenFHE is unavailable";
  return result;
#else
  if (!impl_ || !impl_->error_message.empty()) {
    result.error_message = impl_ ? impl_->error_message : "missing exact BFV session";
    return result;
  }
  if (!CircuitPrivacySessionConfigMatches(impl_->config, config)) {
    result.error_message =
        "exact BFV circuit privacy parameters differ from the session setup";
    return result;
  }
  CopyCircuitPrivacyAudit(config, impl_->circuit_privacy_audit, &result);
  if (!prepared.ok || !prepared.impl_ ||
      prepared.impl_->session_id != impl_->session_id) {
    result.error_message = "prepared BFV candidate packs belong to another or invalid session";
    return result;
  }
  if (prepared.plaintext_modulus != config.plaintext_modulus ||
      prepared.dimension != config.dimension ||
      prepared.candidates_per_pack == 0 ||
      prepared.candidate_replication_factor !=
          config.candidate_replication_factor) {
    result.error_message = "prepared BFV candidate pack configuration mismatch";
    return result;
  }
  if (config.threshold < 0 ||
      config.threshold >= static_cast<std::int64_t>(config.plaintext_modulus / 2)) {
    result.error_message = "prepared BFV threshold must be non-negative and centered";
    return result;
  }
  if (config.round_parallelism == 0) {
    result.error_message = "prepared BFV round parallelism must be non-zero";
    return result;
  }
  if (input.relation.overflow) {
    result.error_message = "prepared BFV pair relation is marked overflowed";
    return result;
  }
  result.stage1_pack_routing_present = !input.pair_pack_refs.empty();
  if (result.stage1_pack_routing_present &&
      input.pair_pack_refs.size() != input.relation.pairs.size()) {
    result.error_message =
        "Stage1 BFV pack routing must align one-to-one with the pair relation";
    return result;
  }

  using LaneQueues = std::vector<std::vector<std::size_t>>;
  std::vector<LaneQueues> pack_queues(
      prepared.ciphertext_pack_count,
      LaneQueues(prepared.candidates_per_pack));
  for (std::size_t pair_index = 0;
       pair_index < input.relation.pairs.size(); ++pair_index) {
    const auto& pair = input.relation.pairs[pair_index];
    if (!pair.valid) continue;
    if (pair.query_id >= input.queries.size() ||
        input.queries[pair.query_id].size() != prepared.dimension ||
        pair.candidate_id >= prepared.candidate_pack_refs.size()) {
      result.error_message = "prepared BFV pair references an invalid query or candidate";
      return result;
    }
    const auto& prepared_primary_ref =
        prepared.candidate_pack_refs[pair.candidate_id];
    ExactHeCandidatePackRef primary_ref = prepared_primary_ref;
    if (result.stage1_pack_routing_present) {
      const auto& recovered_ref = input.pair_pack_refs[pair_index];
      if (!recovered_ref.IsValid() ||
          recovered_ref.pack_id != prepared_primary_ref.pack_id ||
          recovered_ref.lane != prepared_primary_ref.lane) {
        result.error_message =
            "Stage1 authenticated BFV pack routing does not match the prepared sender pack";
        return result;
      }
      primary_ref.pack_id = recovered_ref.pack_id;
      primary_ref.lane = recovered_ref.lane;
    }
    if (!primary_ref.IsValid() || primary_ref.pack_id >= pack_queues.size() ||
        primary_ref.lane >= prepared.candidates_per_pack) {
      result.error_message = "prepared BFV pair has an invalid pack reference";
      return result;
    }
    ExactHeCandidatePackRef selected_ref = primary_ref;
    std::size_t selected_load =
        pack_queues[selected_ref.pack_id][selected_ref.lane].size();
    for (const auto& replica_ref :
         prepared.candidate_replica_pack_refs[pair.candidate_id]) {
      if (!replica_ref.IsValid() || replica_ref.pack_id >= pack_queues.size() ||
          replica_ref.lane >= prepared.candidates_per_pack) {
        result.error_message =
            "prepared BFV candidate has an invalid replica pack reference";
        return result;
      }
      const std::size_t replica_load =
          pack_queues[replica_ref.pack_id][replica_ref.lane].size();
      if (replica_load < selected_load) {
        selected_ref = replica_ref;
        selected_load = replica_load;
      }
    }
    if (selected_ref.pack_id != primary_ref.pack_id ||
        selected_ref.lane != primary_ref.lane) {
      ++result.pairs_using_replica;
    }
    pack_queues[selected_ref.pack_id][selected_ref.lane].push_back(pair_index);
  }

  try {
    const std::size_t lanes = prepared.candidates_per_pack;
    const std::size_t dimension = prepared.dimension;
    PrepareRotations(dimension, {lanes});
    std::vector<std::int32_t> rotations;
    for (std::size_t shift = 1; shift < dimension; shift <<= 1) {
      rotations.push_back(static_cast<std::int32_t>(shift * lanes));
    }
    std::size_t total_rounds = 0;
    for (const auto& queues : pack_queues) {
      std::size_t rounds = 0;
      for (const auto& queue : queues) rounds = std::max(rounds, queue.size());
      total_rounds += rounds;
    }
    if (total_rounds > std::numeric_limits<std::size_t>::max() / lanes) {
      throw std::overflow_error("prepared BFV schedule size overflow");
    }
    const std::size_t total_lane_slots = total_rounds * lanes;
    const auto release_count = static_cast<std::uint64_t>(total_rounds);
    result.circuit_privacy_ciphertext_count = release_count;
    result.circuit_privacy_cumulative_ciphertext_count =
        impl_->released_ciphertext_count;
    result.circuit_privacy_remaining_decryption_budget =
        impl_->released_ciphertext_count >=
                config.circuit_privacy_max_decryption_queries
            ? 0
            : config.circuit_privacy_max_decryption_queries -
                  impl_->released_ciphertext_count;
    result.circuit_privacy_query_bound_check_passed =
        impl_->released_ciphertext_count <=
            config.circuit_privacy_max_decryption_queries &&
        release_count <=
            config.circuit_privacy_max_decryption_queries -
                impl_->released_ciphertext_count;
    if (config.require_circuit_privacy_checks &&
        !result.circuit_privacy_query_bound_check_passed) {
      result.error_message =
          "BFV circuit privacy ciphertext count exceeds the public adaptive-decryption budget";
      return result;
    }
    if (release_count > std::numeric_limits<std::uint64_t>::max() -
                            impl_->released_ciphertext_count) {
      result.error_message = "BFV circuit privacy release counter overflow";
      return result;
    }
    // Reserve the complete release budget before any ciphertext is exposed.
    // A later failure therefore cannot accidentally make the same key budget
    // available again.
    impl_->released_ciphertext_count += release_count;
    result.circuit_privacy_cumulative_ciphertext_count =
        impl_->released_ciphertext_count;
    result.circuit_privacy_remaining_decryption_budget =
        impl_->released_ciphertext_count >=
                config.circuit_privacy_max_decryption_queries
            ? 0
            : config.circuit_privacy_max_decryption_queries -
                  impl_->released_ciphertext_count;
    result.scheduled_relation.pairs.reserve(total_lane_slots);
    result.dummy_mask.reserve(total_lane_slots);
    result.sender_masked_shares.reserve(total_lane_slots);
    result.receiver_mask_shares.reserve(total_lane_slots);
    if (config.collect_round_traces) {
      result.packed_round_traces.reserve(total_rounds);
    }

    struct RoundJob {
      std::size_t pack_id = 0;
      std::size_t round_id = 0;
      std::size_t lane_offset = 0;
    };
    struct RoundOutput {
      bool ok = false;
      std::string error_message;
      std::vector<std::uint32_t> sender_shares;
      std::vector<std::uint32_t> receiver_shares;
      ExactHeMaskedScoreResult metrics;
      double worker_ms = 0.0;
    };
    std::vector<RoundJob> jobs;
    jobs.reserve(total_rounds);

    // Freeze the complete pack-major schedule before starting workers. This
    // preserves the scheduled pair-token and padding order.
    for (std::size_t pack_id = 0; pack_id < pack_queues.size(); ++pack_id) {
      const auto& queues = pack_queues[pack_id];
      std::size_t rounds = 0;
      for (const auto& queue : queues) rounds = std::max(rounds, queue.size());
      if (rounds == 0) continue;
      ++result.candidate_pack_count;
      if (rounds > 1) result.candidate_ciphertext_reuse_count += rounds - 1;
      result.candidate_ciphertext_bytes += EstimateDcrtCiphertextPayloadBytes(
          prepared.impl_->ciphertext_packs[pack_id]);
      result.candidate_ciphertext_bytes_estimated = true;

      for (std::size_t round = 0; round < rounds; ++round) {
        const std::size_t lane_offset = result.scheduled_relation.pairs.size();
        ExactHePackedRoundTrace trace;
        if (config.collect_round_traces) {
          trace.pack_id = static_cast<std::uint32_t>(pack_id);
          trace.round_id = round;
          trace.query_ids.assign(lanes, common::kInvalidQueryId);
          trace.candidate_ids.assign(
              lanes, std::numeric_limits<common::CandidateId>::max());
          trace.pair_tokens.assign(lanes, common::kInvalidPairToken);
          trace.valid.assign(lanes, 0);
        }
        common::QueryId first_query = common::kInvalidQueryId;
        bool mixed_queries = false;
        for (std::size_t lane = 0; lane < lanes; ++lane) {
          common::QueryCandidatePair scheduled;
          if (round < queues[lane].size()) {
            scheduled = input.relation.pairs[queues[lane][round]];
            if (config.collect_round_traces) {
              trace.query_ids[lane] = scheduled.query_id;
              trace.candidate_ids[lane] = scheduled.candidate_id;
              trace.pair_tokens[lane] = scheduled.pair_token;
              trace.valid[lane] = 1;
            }
            if (first_query == common::kInvalidQueryId) {
              first_query = scheduled.query_id;
            } else if (first_query != scheduled.query_id) {
              mixed_queries = true;
            }
          } else {
            scheduled.query_id = common::kInvalidQueryId;
            scheduled.candidate_id =
                std::numeric_limits<common::CandidateId>::max();
            scheduled.pair_token = common::kInvalidPairToken;
            scheduled.candidate_handle = common::kInvalidCandidateHandle;
            scheduled.valid = false;
          }
          result.scheduled_relation.pairs.push_back(scheduled);
          result.dummy_mask.push_back(scheduled.valid ? 0 : 1);
        }
        if (mixed_queries) ++result.mixed_query_round_count;
        if (config.collect_round_traces) {
          result.packed_round_traces.push_back(std::move(trace));
        }
        jobs.push_back(RoundJob{pack_id, round, lane_offset});
      }
    }

    const std::size_t hardware_threads = std::max<std::size_t>(
        1, static_cast<std::size_t>(std::thread::hardware_concurrency()));
    const std::size_t effective_parallelism = jobs.empty()
        ? 1
        : std::min({config.round_parallelism, hardware_threads, jobs.size()});
    result.effective_round_parallelism = effective_parallelism;
    result.parallel_round_execution_used = effective_parallelism > 1;

    std::vector<RoundOutput> round_outputs(jobs.size());
    std::vector<std::string> worker_errors(effective_parallelism);
    std::atomic<std::size_t> next_job{0};
    std::atomic<bool> worker_failed{false};
    const auto round_wall_begin = Clock::now();
    auto run_worker = [&](std::size_t worker_id) {
      try {
        std::vector<std::int64_t> zero(impl_->slot_count, 0);
        auto zero_plaintext = impl_->cc->MakePackedPlaintext(zero);
        std::vector<std::int64_t> packed_query(impl_->slot_count, 0);
        std::vector<std::int64_t> masks(impl_->slot_count, 0);
        while (!worker_failed.load(std::memory_order_relaxed)) {
          const std::size_t job_index =
              next_job.fetch_add(1, std::memory_order_relaxed);
          if (job_index >= jobs.size()) break;
          const auto& job = jobs[job_index];
          auto& output = round_outputs[job_index];
          const auto worker_begin = Clock::now();
          try {
            std::fill(packed_query.begin(), packed_query.end(), 0);
            for (std::size_t lane = 0; lane < lanes; ++lane) {
              const auto& scheduled =
                  result.scheduled_relation.pairs[job.lane_offset + lane];
              if (!scheduled.valid) continue;
              for (std::size_t k = 0; k < dimension; ++k) {
                packed_query[k * lanes + lane] =
                    input.queries[scheduled.query_id][k];
              }
            }

            const auto evaluate_begin = Clock::now();
            auto query_plaintext = impl_->cc->MakePackedPlaintext(packed_query);
            auto encrypted_scores = impl_->cc->EvalMult(
                prepared.impl_->ciphertext_packs[job.pack_id], query_plaintext);
            for (const std::int32_t rotation : rotations) {
              auto rotated = impl_->cc->EvalRotate(encrypted_scores, rotation);
              impl_->cc->EvalAddInPlace(encrypted_scores, rotated);
              ++output.metrics.rotation_count;
            }
            output.metrics.evaluate_ms = MillisSince(evaluate_begin);

            const auto mask_begin = Clock::now();
            FillUniformMod(&masks, config.plaintext_modulus);
            auto mask_plaintext = impl_->cc->MakePackedPlaintext(masks);
            impl_->cc->EvalAddInPlace(encrypted_scores, mask_plaintext);
            auto encrypted_zero = impl_->cc->Encrypt(
                impl_->keys.publicKey, zero_plaintext);
            impl_->cc->EvalAddInPlace(encrypted_scores, encrypted_zero);
            auto masked_scores = std::move(encrypted_scores);
            output.metrics.mask_ms = MillisSince(mask_begin);
            CompressMaskedScoreCiphertext(
                impl_->cc, config, &masked_scores, &output.metrics);

            const auto decrypt_begin = Clock::now();
            lbcrypto::Plaintext decrypted;
            impl_->cc->Decrypt(impl_->keys.secretKey, masked_scores, &decrypted);
            decrypted->SetLength(lanes);
            const auto& values = decrypted->GetPackedValue();
            output.metrics.decrypt_ms = MillisSince(decrypt_begin);
            if (values.size() < lanes) {
              throw std::runtime_error(
                  "prepared BFV decrypt returned too few lanes");
            }
            output.sender_shares.resize(lanes);
            output.receiver_shares.resize(lanes);
            for (std::size_t lane = 0; lane < lanes; ++lane) {
              const std::uint32_t u =
                  CanonicalResidue(values[lane], config.plaintext_modulus);
              const std::uint32_t rho =
                  static_cast<std::uint32_t>(masks[lane]);
              output.sender_shares[lane] = u;
              output.receiver_shares[lane] =
                  rho == 0 ? 0 : config.plaintext_modulus - rho;
            }
            output.worker_ms = MillisSince(worker_begin);
            output.ok = true;
          } catch (const std::exception& ex) {
            output.error_message = ex.what();
            worker_failed.store(true, std::memory_order_relaxed);
          }
        }
      } catch (const std::exception& ex) {
        worker_errors[worker_id] = ex.what();
        worker_failed.store(true, std::memory_order_relaxed);
      }
    };

    if (effective_parallelism == 1) {
      run_worker(0);
    } else {
      std::vector<std::thread> workers;
      workers.reserve(effective_parallelism);
      for (std::size_t worker = 0; worker < effective_parallelism; ++worker) {
        workers.emplace_back(run_worker, worker);
      }
      for (auto& worker : workers) worker.join();
    }
    result.round_processing_wall_ms = MillisSince(round_wall_begin);

    for (const auto& error : worker_errors) {
      if (!error.empty()) {
        throw std::runtime_error("BFV round worker setup failed: " + error);
      }
    }
    for (std::size_t index = 0; index < round_outputs.size(); ++index) {
      const auto& output = round_outputs[index];
      if (!output.ok) {
        throw std::runtime_error(
            "BFV round " + std::to_string(index) + " failed: " +
            (output.error_message.empty() ? "cancelled after another worker failure"
                                          : output.error_message));
      }
      result.sender_masked_shares.insert(
          result.sender_masked_shares.end(), output.sender_shares.begin(),
          output.sender_shares.end());
      result.receiver_mask_shares.insert(
          result.receiver_mask_shares.end(), output.receiver_shares.begin(),
          output.receiver_shares.end());
      result.evaluate_ms += output.metrics.evaluate_ms;
      result.mask_ms += output.metrics.mask_ms;
      result.decrypt_ms += output.metrics.decrypt_ms;
      result.aggregate_round_worker_ms += output.worker_ms;
      result.rotation_count += output.metrics.rotation_count;
      result.masked_score_ciphertext_bytes_before_compression +=
          output.metrics.masked_score_ciphertext_bytes_before_compression;
      result.masked_score_ciphertext_bytes +=
          output.metrics.masked_score_ciphertext_bytes;
      result.masked_score_towers_before_compression = std::max(
          result.masked_score_towers_before_compression,
          output.metrics.masked_score_towers_before_compression);
      result.masked_score_towers_after_compression = std::max(
          result.masked_score_towers_after_compression,
          output.metrics.masked_score_towers_after_compression);
      result.masked_score_ciphertext_compressed =
          result.masked_score_ciphertext_compressed ||
          output.metrics.masked_score_ciphertext_compressed;
      result.masked_score_ciphertext_bytes_estimated =
          result.masked_score_ciphertext_bytes_estimated ||
          output.metrics.masked_score_ciphertext_bytes_estimated;
    }
    result.pack_round_count = jobs.size();
    result.ciphertext_count = jobs.size();
    result.lane_count = result.sender_masked_shares.size();
    if (result.pack_round_count >
        std::numeric_limits<std::size_t>::max() / impl_->slot_count) {
      throw std::overflow_error("prepared BFV masked slot count overflow");
    }
    result.masked_slot_count = impl_->slot_count * result.pack_round_count;
    result.all_slots_masked = true;
    result.message_mask_uniform_mod_t = true;
    result.fresh_zero_rerandomization = true;
    result.divide_and_round_circuit_privacy_applied =
        result.masked_score_ciphertext_compressed &&
        result.masked_score_towers_after_compression == 1;
    result.circuit_privacy_parameter_checks_passed =
        config.require_circuit_privacy_checks &&
        impl_->circuit_privacy_audit.supported &&
        result.circuit_privacy_query_bound_check_passed &&
        result.divide_and_round_circuit_privacy_applied;
    if (config.require_circuit_privacy_checks &&
        !result.circuit_privacy_parameter_checks_passed) {
      result.error_message =
          "BFV circuit privacy postcondition failed before ciphertext release";
      return result;
    }
    result.stage1_pack_routing_verified =
        result.stage1_pack_routing_present;
    result.ok = true;
    ++impl_->run_count;
    return result;
  } catch (const std::exception& ex) {
    result.error_message =
        std::string("prepared BFV pair evaluation failed: ") + ex.what();
    return result;
  }
#endif
}

}  // namespace ctfpsi::stage2
