#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "adapters/rbokvs_adapter.hpp"
#include "common/config.hpp"
#include "common/many_to_many.hpp"
#include "common/types.hpp"
#include "stage1/candidate_payload.hpp"
#include "stage1/oprf_provider.hpp"
#include "stage1/query_preprocessor.hpp"
#include "stage1/threshold_parameterization.hpp"

namespace ctfpsi::stage1 {

struct Stage1BuildOptions {
  std::size_t rbokvs_value_length_blocks = common::config::stage1::kRbokvsValueLengthBlocks;
  bool verbose = false;

  double cosine_threshold = common::config::stage1::kCosineThreshold;
  std::size_t num_blocks = common::config::stage1::kNumBlocks;
  double hamming_sigma_margin = common::config::stage1::kHammingSigmaMargin;
  double target_recall = common::config::stage1::kTargetRecall;
  std::size_t min_block_radius = common::config::stage1::kMinBlockRadius;
  std::size_t max_block_radius = common::config::stage1::kMaxBlockRadius;
  std::size_t c0_cap = common::config::kCandidateCapC0;
  // Optional statistics compare TPCR output with full local Hamming distances.
  bool collect_candidate_statistics = false;
  // Ablation switch used to measure the effect of threshold-aware pruning.
  bool disable_threshold_pruning = false;
};

using CandidateBfvPackRefs = std::vector<common::BfvPackRef>;

inline Stage1BuildOptions BuildStage1DefaultBuildOptions() {
  return Stage1BuildOptions{};
}

struct Stage1BatchQueryResult {
  struct OprfBatchTrace {
    std::size_t batch_id = 0;
    std::size_t probe_count = 0;
    std::vector<common::QueryId> distinct_query_ids;
  };

  common::PairRelation c0;
  common::CandidateList recovered_candidate_ids;
  CandidateBfvPackRefs recovered_bfv_pack_refs;
  CandidateBfvPackRefs pair_bfv_pack_refs;

  std::size_t query_count = 0;
  std::size_t probe_count = 0;
  std::size_t decode_hit_count = 0;
  bool candidate_statistics_collected = false;
  bool threshold_pruning_enabled = true;
  std::size_t num_raw_probe_hits = 0;
  std::size_t num_C_hit = 0;
  std::size_t num_C0 = 0;
  std::size_t num_pruned = 0;
  double pruning_ratio = 0.0;
  double avg_hits_per_raw_candidate = 0.0;
  std::size_t num_hamming_true = 0;
  std::size_t num_hamming_true_in_C0 = 0;
  std::size_t num_hamming_false_negative = 0;
  double hamming_recall = 0.0;
  std::size_t num_C0_false_positive = 0;
  bool tpcr_opaque_opening_used = true;
  std::size_t opaque_handle_count = 0;
  std::size_t opaque_handle_collision_count = 0;
  bool opaque_handle_consistency_verified = false;
  bool prefilter_contains_candidate_id = false;
  bool prefilter_contains_opening_key = false;
  bool prefilter_contains_pack_location = false;
  std::size_t opening_oprf_point_count = 0;
  std::size_t opening_oprf_batch_count = 0;
  std::size_t num_surviving_pairs = 0;
  std::size_t num_unique_surviving_handles = 0;
  std::size_t opening_oprf_input_count = 0;
  std::uint64_t probe_oprf_request_bytes = 0;
  std::uint64_t probe_oprf_response_bytes = 0;
  std::uint64_t opening_oprf_request_bytes = 0;
  std::uint64_t opening_oprf_response_bytes = 0;
  std::uint64_t opening_oprf_bytes = 0;
  std::uint64_t opening_payload_communication_bytes = 0;
  // RB-OKVS table plus the actual serialized probe OPRF messages.
  std::uint64_t stage1_probe_bytes = 0;
  std::uint64_t stage1_total_communication_bytes = 0;
  double opaque_handle_generation_ms = 0.0;
  double opening_oprf_ms = 0.0;
  double opening_payload_lookup_ms = 0.0;
  double opening_decryption_ms = 0.0;
  double tpcr_total_ms = 0.0;
  std::size_t payload_decrypt_success_count = 0;
  std::uint64_t rbokvs_serialized_table_bytes = 0;
  bool cross_query_probe_dedup_used = false;
  std::size_t logical_oprf_session_count = 0;
  std::size_t logical_oprf_batch_count = 0;
  std::size_t oprf_session_setup_count = 0;
  std::size_t oprf_server_key_generation_count = 0;
  std::size_t oprf_batch_call_count = 0;
  std::size_t oprf_total_point_count = 0;
  std::size_t oprf_scalar_call_count = 0;
  double cosine_threshold = 0.0;
  std::size_t simhash_bits = 0;
  std::size_t num_blocks = 0;
  std::size_t hamming_threshold = 0;
  std::size_t block_radius = 0;
  double target_recall = 0.0;
  double estimated_recall_at_threshold = 0.0;
  std::string threshold_policy;
  double oprf_evaluate_ms = 0.0;
  double total_ms = 0.0;
  std::vector<OprfBatchTrace> oprf_batches;
  std::string oprf_implementation;
  std::string rbokvs_backend_used;
  std::string error_message;
};

class Stage1IndexBuilder {
 public:
  Stage1IndexBuilder(adapters::RbokvsAdapter* rbokvs_adapter,
                     std::unique_ptr<OprfProvider> oprf_provider,
                     Stage1BuildOptions options = {});

  bool Build(const std::vector<common::BinaryFingerprint>& dataset_bits,
             const common::DenseMatrix& dataset_vectors,
             const CandidateBfvPackRefs& candidate_pack_refs,
             std::string* error);

  Stage1BatchQueryResult QueryBatchAndRecover(
      const std::vector<QueryBundle>& query_bundles) const;

  bool IsReady() const;

 private:
  struct CandidateRecord {
    common::BinaryFingerprint fingerprint;
    common::ByteBlock opaque_handle{};
  };

  common::ByteBlock DeriveRbokvsKeyFromOprfKey(const common::ByteBlock& oprf_key,
                                               std::size_t bucket_slot) const;

  adapters::RbokvsAdapter* rbokvs_adapter_;
  std::unique_ptr<OprfProvider> oprf_provider_;
  std::unique_ptr<OprfProvider> opening_oprf_provider_;
  Stage1BuildOptions options_;
  PayloadCodecConfig payload_codec_config_;

  std::vector<CandidateRecord> records_;
  std::unordered_map<std::string, OpaqueEncryptedCandidatePayload>
      opaque_payload_dictionary_;
  std::vector<std::uint8_t> opaque_payload_wire_message_;
  std::vector<common::ByteBlock> opaque_handles_;
  std::vector<common::ByteBlock> opening_server_outputs_;
  double opaque_handle_generation_ms_ = 0.0;
  std::size_t opaque_handle_collision_count_ = 0;
  bool opaque_handle_consistency_verified_ = false;
  std::vector<std::vector<common::ByteBlock>> rbokvs_codewords_;
  adapters::RbokvsAdapter::BackendMode rbokvs_backend_used_ =
      adapters::RbokvsAdapter::BackendMode::Unavailable;
  std::size_t max_bucket_occupancy_ = 0;
  std::size_t rbokvs_encoded_entry_count_ = 0;
  std::uint64_t rbokvs_serialized_table_bytes_ = 0;
  Stage1ThresholdParameters threshold_params_;
  bool ready_ = false;
};

}  // namespace ctfpsi::stage1
