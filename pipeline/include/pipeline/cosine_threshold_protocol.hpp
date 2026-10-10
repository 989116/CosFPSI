#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "common/many_to_many.hpp"
#include "pipeline/many_to_many_input.hpp"
#include "stage1/stage1_index_builder.hpp"
#include "stage2/exact_he_masked_score.hpp"
#include "stage3/batched_comparison_backend.hpp"

namespace ctfpsi::pipeline {

inline constexpr const char* kProtocolExecutionMode = "global_many_to_many";
inline constexpr const char* kProtocolVersion = "tpcr-cpss-yao-v1";

struct CosineThresholdProtocolConfig {
  stage1::Stage1BuildOptions stage1_options{};
  stage2::ExactHeMaskedScoreConfig exact_he{};
  double final_threshold = 0.75;
  std::uint32_t fixed_point_scale_bits = 6;
  std::size_t candidates_per_pack = 0;
  std::size_t automatic_pack_width_limit = 128;
  std::size_t candidate_replication_factor = 1;
  // Worker count is capped by hardware concurrency and available rounds.
  std::size_t round_parallelism = 16;
  bool compress_masked_score_ciphertext = true;
  std::uint32_t masked_score_towers_left = 1;
  bool require_cross_query_batch_evidence = true;
};

struct CosineThresholdProtocolMetrics {
  std::string execution_mode = kProtocolExecutionMode;
  std::string protocol_version = kProtocolVersion;
  double setup_ms = 0.0;
  double offline_ms = 0.0;
  double stage1_ms = 0.0;
  double bfv_ms = 0.0;
  double gc_ms = 0.0;
  double online_ms = 0.0;
  double total_ms = 0.0;
  std::uint64_t stage1_communication_bytes = 0;
  std::uint64_t stage1_offline_communication_bytes = 0;
  std::uint64_t stage1_online_communication_bytes = 0;
  std::uint64_t stage1_rbokvs_table_bytes = 0;
  std::uint64_t stage1_probe_bytes = 0;
  std::uint64_t opening_oprf_request_bytes = 0;
  std::uint64_t opening_oprf_response_bytes = 0;
  std::uint64_t opening_oprf_bytes = 0;
  std::uint64_t opening_payload_bytes = 0;
  std::uint64_t bfv_offline_communication_bytes = 0;
  std::uint64_t bfv_online_communication_bytes = 0;
  std::uint64_t bfv_online_communication_bytes_before_compression = 0;
  std::uint64_t gc_communication_bytes = 0;
  std::uint64_t offline_communication_bytes = 0;
  std::uint64_t online_communication_bytes = 0;
  std::uint64_t total_communication_bytes = 0;
  std::size_t context_creation_count = 0;
  std::size_t key_generation_count = 0;
  std::size_t candidate_pack_count = 0;
  std::size_t candidate_encrypt_count = 0;
  std::size_t candidates_per_pack = 0;
  std::size_t replica_slot_count = 0;
  std::size_t candidate_replication_factor = 1;
  std::size_t pack_round_count = 0;
  std::size_t pairs_using_replica = 0;
  std::size_t requested_round_parallelism = 1;
  std::size_t effective_round_parallelism = 1;
  bool parallel_round_execution_used = false;
  double bfv_round_processing_wall_ms = 0.0;
  double bfv_aggregate_round_worker_ms = 0.0;
  std::size_t masked_score_towers_before_compression = 0;
  std::size_t masked_score_towers_after_compression = 0;
  bool masked_score_ciphertext_compressed = false;
  std::size_t valid_pair_count = 0;
  std::size_t total_lane_count = 0;
  double valid_lane_ratio = 0.0;
  std::size_t gc_ot_setup_count = 0;
  std::size_t gc_ot_count = 0;
  bool stage1_cross_query_batch = false;
  bool bfv_cross_query_round = false;
  bool score_reconstruction_used = false;
  bool threshold_contract_aligned = false;
  bool stage1_pack_routing_recovered = false;
  bool stage2_pack_routing_verified = false;
  bool circuit_privacy_parameter_checks_passed = false;
  bool noise_flooding_applied = false;
  bool divide_and_round_circuit_privacy_applied = false;
  bool circuit_privacy_parameter_check_passed = false;
  bool circuit_privacy_query_bound_check_passed = false;
  bool circuit_privacy_correctness_check_passed = false;
  std::uint32_t circuit_privacy_statistical_security_bits = 0;
  std::uint64_t circuit_privacy_max_decryption_queries = 0;
  std::uint64_t circuit_privacy_ciphertext_count = 0;
  std::uint64_t circuit_privacy_cumulative_ciphertext_count = 0;
  std::uint64_t circuit_privacy_remaining_decryption_budget = 0;
  double circuit_privacy_security_margin_bits = 0.0;
  double circuit_privacy_joint_failure_log2 = 0.0;
  double correctness_margin_bits = 0.0;
  std::string ciphertext_sanitization_mode;
  std::string circuit_privacy_distribution;
  std::size_t stage1_simhash_bits = 0;
  std::size_t stage1_hamming_threshold = 0;
  std::size_t stage1_block_radius = 0;
  double stage1_target_recall = 0.0;
  double stage1_estimated_recall = 0.0;
  std::size_t stage1_raw_probe_hits = 0;
  std::size_t stage1_raw_candidate_pairs = 0;
  std::size_t stage1_retained_pairs = 0;
  std::size_t stage1_unique_opened_handles = 0;
  double stage1_pruning_ratio = 0.0;
};

struct CosineThresholdProtocolResult {
  bool ok = false;
  std::string error_message;
  stage1::Stage1BatchQueryResult stage1;
  stage2::ExactHeMaskedScoreResult exact_he;
  stage3::BatchedCompareResult comparison;
  common::PairRelation matches;
  CosineThresholdProtocolMetrics metrics;
};

class CosineThresholdProtocol {
 public:
  static CosineThresholdProtocolResult Run(
      const ManyToManyInput& input,
      CosineThresholdProtocolConfig config = {});
};

}  // namespace ctfpsi::pipeline


