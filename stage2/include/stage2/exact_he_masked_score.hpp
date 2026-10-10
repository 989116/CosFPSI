#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <vector>

#include "common/many_to_many.hpp"

namespace ctfpsi::stage2 {

struct ExactHeMaskedScoreConfig {
  std::uint32_t plaintext_modulus = 65537;
  std::int64_t threshold = 128;
  std::size_t dimension = 8;
  std::size_t lane_count = 4;
  std::size_t candidate_replication_factor = 1;
  // Maximum concurrent workers for independent pack rounds.
  std::size_t round_parallelism = 16;
  bool compress_masked_score_ciphertext = true;
  std::uint32_t masked_score_towers_left = 1;
  bool collect_round_traces = false;
  // Circuit privacy uses fresh Enc(0) followed by BFV divide-and-round
  // compression. The bounds below are public protocol parameters.
  bool require_circuit_privacy_checks = true;
  std::uint32_t circuit_privacy_statistical_security_bits = 40;
  std::uint64_t circuit_privacy_max_decryption_queries = 65536;
  std::uint32_t circuit_privacy_error_coefficient_bound = 40;
  std::uint32_t circuit_privacy_context_depth = 5;
  std::uint32_t circuit_privacy_modulus_bits = 54;
  // Zero selects OpenFHE's one RNS digit per ciphertext tower.
  std::uint32_t circuit_privacy_key_switch_digit_bits = 0;
};

struct ExactHePackedRoundTrace {
  std::uint32_t pack_id = 0;
  std::size_t round_id = 0;
  std::vector<common::QueryId> query_ids;
  std::vector<common::CandidateId> candidate_ids;
  std::vector<common::PairToken> pair_tokens;
  std::vector<std::uint8_t> valid;
};

struct ExactHeMaskedScoreResult {
  bool ok = false;
  std::string error_message;

  std::vector<std::uint32_t> sender_masked_shares;
  std::vector<std::uint32_t> receiver_mask_shares;
  std::vector<std::uint8_t> dummy_mask;
  common::PairRelation scheduled_relation;
  std::vector<ExactHePackedRoundTrace> packed_round_traces;

  std::uint32_t plaintext_modulus = 0;
  std::uint32_t compare_bits = 0;
  std::int64_t threshold = 0;
  std::size_t dimension = 0;
  std::size_t lane_count = 0;
  std::size_t slot_count = 0;
  std::size_t masked_slot_count = 0;
  std::size_t ciphertext_count = 0;
  std::size_t candidate_ciphertext_bytes = 0;
  std::size_t masked_score_ciphertext_bytes = 0;
  std::size_t masked_score_ciphertext_bytes_before_compression = 0;
  std::size_t masked_score_towers_before_compression = 0;
  std::size_t masked_score_towers_after_compression = 0;
  bool candidate_ciphertext_bytes_estimated = false;
  bool masked_score_ciphertext_bytes_measured = false;
  bool masked_score_ciphertext_bytes_estimated = false;
  bool masked_score_ciphertext_compressed = false;
  bool evaluation_key_bytes_instrumented = false;
  bool session_reused = false;
  bool used_prepared_candidate_packs = false;
  std::size_t context_creation_count = 0;
  std::size_t key_generation_count = 0;
  std::size_t rotation_key_generation_count = 0;
  std::size_t candidate_pack_count = 0;
  std::size_t pack_round_count = 0;
  std::size_t candidate_ciphertext_reuse_count = 0;
  std::size_t pairs_using_replica = 0;
  std::size_t mixed_query_round_count = 0;
  std::size_t rotation_count = 0;
  std::size_t requested_round_parallelism = 1;
  std::size_t effective_round_parallelism = 1;
  bool parallel_round_execution_used = false;
  bool all_slots_masked = false;
  bool message_mask_uniform_mod_t = false;
  bool fresh_zero_rerandomization = false;
  bool circuit_privacy_parameter_checks_passed = false;
  bool noise_flooding_applied = false;
  bool divide_and_round_circuit_privacy_applied = false;
  std::string ciphertext_sanitization_mode;
  std::string circuit_privacy_distribution;
  std::string noise_flooding_distribution;
  bool noise_flooding_stddev_applicable = false;
  double encryption_error_stddev = 0.0;
  std::uint32_t circuit_privacy_statistical_security_bits = 0;
  std::uint64_t circuit_privacy_max_decryption_queries = 0;
  std::uint64_t circuit_privacy_ciphertext_count = 0;
  std::uint64_t circuit_privacy_cumulative_ciphertext_count = 0;
  std::uint64_t circuit_privacy_remaining_decryption_budget = 0;
  std::uint32_t circuit_privacy_error_coefficient_bound = 0;
  std::uint32_t circuit_privacy_context_depth = 0;
  std::uint32_t circuit_privacy_modulus_bits = 0;
  std::uint32_t circuit_privacy_key_switch_digit_bits = 0;
  std::size_t circuit_privacy_initial_tower_count = 0;
  double ciphertext_modulus_log2 = 0.0;
  double circuit_privacy_divisor_log2 = 0.0;
  double homomorphic_noise_bound_log2 = 0.0;
  double circuit_privacy_required_divisor_log2 = 0.0;
  double circuit_privacy_security_margin_bits = 0.0;
  double gaussian_tail_failure_log2 = 0.0;
  double circuit_privacy_boundary_failure_log2 = 0.0;
  double circuit_privacy_joint_failure_log2 = 0.0;
  double final_ciphertext_modulus_log2 = 0.0;
  double correctness_required_modulus_log2 = 0.0;
  double correctness_margin_bits = 0.0;
  bool circuit_privacy_parameter_check_passed = false;
  bool circuit_privacy_query_bound_check_passed = false;
  bool circuit_privacy_correctness_check_passed = false;
  bool stage1_pack_routing_present = false;
  bool stage1_pack_routing_verified = false;

  double setup_ms = 0.0;
  double encrypt_ms = 0.0;
  double evaluate_ms = 0.0;
  double mask_ms = 0.0;
  double decrypt_ms = 0.0;
  // Wall time covers the complete round executor. The operation-specific
  // timings above are sums over workers and may exceed wall time in parallel.
  double round_processing_wall_ms = 0.0;
  double aggregate_round_worker_ms = 0.0;
};

struct ExactHePreparedPairBatchInput {
  std::vector<std::vector<std::int64_t>> queries;
  common::PairRelation relation;
  // Authenticated Stage1 payload routing, aligned one-to-one with relation.
  // The pipeline supplies one authenticated pack reference per candidate pair.
  std::vector<common::BfvPackRef> pair_pack_refs;
};

struct ExactHeCandidatePackRef {
  std::uint32_t pack_id = std::numeric_limits<std::uint32_t>::max();
  std::uint32_t lane = 0;

  bool IsValid() const {
    return pack_id != std::numeric_limits<std::uint32_t>::max();
  }
};

class PreparedExactHeCandidatePayloads {
 public:
  PreparedExactHeCandidatePayloads();
  ~PreparedExactHeCandidatePayloads();
  PreparedExactHeCandidatePayloads(const PreparedExactHeCandidatePayloads&);
  PreparedExactHeCandidatePayloads& operator=(
      const PreparedExactHeCandidatePayloads&);
  PreparedExactHeCandidatePayloads(PreparedExactHeCandidatePayloads&&) noexcept;
  PreparedExactHeCandidatePayloads& operator=(
      PreparedExactHeCandidatePayloads&&) noexcept;

  bool ok = false;
  std::string error_message;
  std::vector<ExactHeCandidatePackRef> candidate_pack_refs;
  std::vector<std::vector<ExactHeCandidatePackRef>>
      candidate_replica_pack_refs;
  std::size_t candidate_count = 0;
  std::size_t candidates_per_pack = 0;
  std::size_t ciphertext_pack_count = 0;
  std::size_t populated_slot_count = 0;
  std::size_t replica_slot_count = 0;
  std::size_t candidate_replication_factor = 1;
  std::size_t dimension = 0;
  std::size_t slot_count = 0;
  std::uint32_t plaintext_modulus = 0;
  std::size_t ciphertext_payload_bytes = 0;
  double encrypt_ms = 0.0;

 private:
  struct Impl;
  std::shared_ptr<Impl> impl_;
  friend class ExactHeMaskedScoreSession;
};

// Reuses one BFV context, key set, rotation keys, and identical prepared
// candidate packs across a protocol session. OpenFHE types remain private to
// the implementation to keep the public interface independent of OpenFHE types.
class ExactHeMaskedScoreSession {
 public:
  explicit ExactHeMaskedScoreSession(
      const ExactHeMaskedScoreConfig& config = {});
  ~ExactHeMaskedScoreSession();

  ExactHeMaskedScoreSession(ExactHeMaskedScoreSession&&) noexcept;
  ExactHeMaskedScoreSession& operator=(ExactHeMaskedScoreSession&&) noexcept;
  ExactHeMaskedScoreSession(const ExactHeMaskedScoreSession&) = delete;
  ExactHeMaskedScoreSession& operator=(const ExactHeMaskedScoreSession&) = delete;

  void PrepareRotations(std::size_t dimension,
                        const std::vector<std::size_t>& lane_counts);
  PreparedExactHeCandidatePayloads PrepareSenderCandidatePacks(
      const std::vector<std::vector<std::int64_t>>& candidates,
      std::size_t candidates_per_pack);
  ExactHeMaskedScoreResult RunPreparedPairRelation(
      const ExactHePreparedPairBatchInput& input,
      const PreparedExactHeCandidatePayloads& prepared,
      const ExactHeMaskedScoreConfig& config);
  double InitializationMs() const;
  double RotationPreparationMs() const;
  std::size_t ContextCreationCount() const;
  std::size_t KeyGenerationCount() const;
  std::size_t SlotCount() const;
  const std::string& SetupErrorMessage() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace ctfpsi::stage2


