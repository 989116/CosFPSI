#include "pipeline/cosine_threshold_protocol.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <limits>
#include <memory>
#include <stdexcept>
#include <vector>

#include "adapters/rbokvs_adapter.hpp"
#include "stage1/oprf_provider.hpp"
#include "stage3/gc_backend_adapter.hpp"
#include "stage3/protocol_context.hpp"
#include "stage3/transcript.hpp"
#include "stage3/transport.hpp"

namespace ctfpsi::pipeline {
namespace {

using Clock = std::chrono::steady_clock;

double ElapsedMs(const Clock::time_point& start) {
  return std::chrono::duration<double, std::milli>(Clock::now() - start)
      .count();
}

std::size_t NextPowerOfTwo(std::size_t value) {
  std::size_t result = 1;
  while (result < value) {
    if (result > std::numeric_limits<std::size_t>::max() / 2) {
      throw std::overflow_error("BFV padded dimension overflow");
    }
    result <<= 1;
  }
  return result;
}

std::vector<std::vector<std::int64_t>> QuantizeAndPad(
    const common::DenseMatrix& matrix,
    std::size_t padded_dimension,
    std::int64_t scale) {
  std::vector<std::vector<std::int64_t>> result(
      matrix.size(), std::vector<std::int64_t>(padded_dimension, 0));
  for (std::size_t row = 0; row < matrix.size(); ++row) {
    if (matrix[row].size() > padded_dimension) {
      throw std::invalid_argument("BFV input exceeds padded dimension");
    }
    for (std::size_t column = 0; column < matrix[row].size(); ++column) {
      const double scaled = matrix[row][column] * static_cast<double>(scale);
      if (!std::isfinite(scaled) ||
          scaled < static_cast<double>(std::numeric_limits<std::int64_t>::min()) ||
          scaled > static_cast<double>(std::numeric_limits<std::int64_t>::max())) {
        throw std::overflow_error("BFV fixed-point quantization overflow");
      }
      result[row][column] = static_cast<std::int64_t>(std::llround(scaled));
    }
  }
  return result;
}

bool HasMixedQueries(
    const std::vector<stage1::Stage1BatchQueryResult::OprfBatchTrace>& traces) {
  return std::any_of(traces.begin(), traces.end(), [](const auto& trace) {
    return trace.distinct_query_ids.size() > 1;
  });
}

long double MaxSquaredNorm(
    const std::vector<std::vector<std::int64_t>>& matrix) {
  long double maximum = 0.0L;
  for (const auto& row : matrix) {
    long double squared_norm = 0.0L;
    for (const std::int64_t value : row) {
      const long double coordinate = static_cast<long double>(value);
      squared_norm += coordinate * coordinate;
    }
    maximum = std::max(maximum, squared_norm);
  }
  return maximum;
}

}  // namespace

CosineThresholdProtocolResult CosineThresholdProtocol::Run(
    const ManyToManyInput& input,
    CosineThresholdProtocolConfig config) {
  CosineThresholdProtocolResult out;
  const auto total_begin = Clock::now();
  try {
    if (input.sender_vectors.empty() || input.query_vectors.empty() ||
        input.sender_fingerprints.size() != input.sender_vectors.size() ||
        input.query_bundles.size() != input.query_vectors.size()) {
      out.error_message = "Protocol requires aligned non-empty sender/query inputs";
      return out;
    }
    const std::size_t dimension = input.sender_vectors.front().size();
    if (dimension == 0) {
      out.error_message = "Protocol requires non-empty vectors";
      return out;
    }
    for (const auto& vector : input.sender_vectors) {
      if (vector.size() != dimension) {
        out.error_message = "Protocol sender vectors have inconsistent dimensions";
        return out;
      }
    }
    for (const auto& vector : input.query_vectors) {
      if (vector.size() != dimension) {
        out.error_message = "Protocol query vectors have inconsistent dimensions";
        return out;
      }
    }
    if (config.fixed_point_scale_bits >= 30) {
      out.error_message = "Protocol fixed-point scale must remain below 30 bits";
      return out;
    }
    // One public predicate drives candidate over-selection and exact output.
    config.stage1_options.cosine_threshold = config.final_threshold;
    const std::size_t fingerprint_bits =
        input.sender_fingerprints.front().size();
    if (fingerprint_bits == 0) {
      out.error_message = "Protocol requires non-empty Stage1 fingerprints";
      return out;
    }
    for (const auto& fingerprint : input.sender_fingerprints) {
      if (fingerprint.size() != fingerprint_bits) {
        out.error_message =
            "Protocol sender fingerprints violate one Stage1 contract";
        return out;
      }
    }
    for (const auto& bundle : input.query_bundles) {
      if (bundle.simhash_bits.size() != fingerprint_bits) {
        out.error_message =
            "Protocol query fingerprint length differs from sender index";
        return out;
      }
    }

    const auto setup_begin = Clock::now();
    const std::size_t padded_dimension =
        std::max<std::size_t>(4, NextPowerOfTwo(dimension));
    const std::int64_t scale =
        std::int64_t{1} << config.fixed_point_scale_bits;
    const long double threshold_scaled =
        static_cast<long double>(config.final_threshold) * scale * scale;
    if (threshold_scaled < 0 ||
        threshold_scaled >= config.exact_he.plaintext_modulus / 2.0L) {
      out.error_message =
          "Protocol threshold does not fit the centered BFV plaintext modulus";
      return out;
    }
    config.exact_he.dimension = padded_dimension;
    config.exact_he.threshold =
        static_cast<std::int64_t>(std::llround(threshold_scaled));
    config.exact_he.compress_masked_score_ciphertext =
        config.compress_masked_score_ciphertext;
    config.exact_he.masked_score_towers_left =
        config.masked_score_towers_left;
    config.exact_he.candidate_replication_factor =
        config.candidate_replication_factor;
    config.exact_he.round_parallelism = config.round_parallelism;
    stage2::ExactHeMaskedScoreSession exact_session(config.exact_he);
    if (exact_session.ContextCreationCount() != 1 ||
        exact_session.KeyGenerationCount() != 1 ||
        exact_session.SlotCount() == 0) {
      out.error_message = "Protocol BFV setup failed: " +
                          exact_session.SetupErrorMessage();
      return out;
    }
    const std::size_t physical_limit =
        exact_session.SlotCount() / padded_dimension;
    const std::size_t bounded_limit = std::min(
        physical_limit,
        std::max<std::size_t>(4, config.automatic_pack_width_limit));
    std::size_t candidates_per_pack = config.candidates_per_pack;
    if (candidates_per_pack == 0) {
      // Fill available lanes subject to the configured pack-width limit.
      candidates_per_pack = bounded_limit;
    }
    if (candidates_per_pack == 0 || candidates_per_pack > physical_limit) {
      out.error_message = "Protocol candidate pack width exceeds BFV slot capacity";
      return out;
    }
    config.exact_he.lane_count = candidates_per_pack;
    out.metrics.setup_ms = ElapsedMs(setup_begin);

    const auto offline_begin = Clock::now();
    const auto integer_candidates =
        QuantizeAndPad(input.sender_vectors, padded_dimension, scale);
    const auto integer_queries =
        QuantizeAndPad(input.query_vectors, padded_dimension, scale);
    const long double score_bound = std::sqrt(
        MaxSquaredNorm(integer_candidates) * MaxSquaredNorm(integer_queries));
    if (score_bound >= config.exact_he.plaintext_modulus / 2.0L) {
      out.error_message =
          "Protocol fixed-point score bound exceeds the centered BFV modulus";
      return out;
    }
    const auto prepared = exact_session.PrepareSenderCandidatePacks(
        integer_candidates, candidates_per_pack);
    if (!prepared.ok) {
      out.error_message = "Protocol candidate preparation failed: " +
                          prepared.error_message;
      return out;
    }
    stage1::CandidateBfvPackRefs stage1_pack_refs;
    stage1_pack_refs.reserve(prepared.candidate_pack_refs.size());
    for (const auto& ref : prepared.candidate_pack_refs) {
      stage1_pack_refs.push_back(common::BfvPackRef{ref.pack_id, ref.lane});
    }

    adapters::RbokvsAdapter rbokvs_adapter;
    auto oprf = std::make_unique<stage1::EcOprfProvider>();
    stage1::Stage1IndexBuilder stage1_builder(
        &rbokvs_adapter, std::move(oprf), config.stage1_options);
    std::string stage1_error;
    if (!stage1_builder.Build(input.sender_fingerprints,
                              input.sender_vectors, stage1_pack_refs,
                              &stage1_error)) {
      out.error_message = "Protocol Stage1 build failed: " + stage1_error;
      return out;
    }
    out.metrics.offline_ms = ElapsedMs(offline_begin);

    const auto stage1_begin = Clock::now();
    out.stage1 = stage1_builder.QueryBatchAndRecover(input.query_bundles);
    out.metrics.stage1_ms = ElapsedMs(stage1_begin);
    if (!out.stage1.error_message.empty()) {
      out.error_message = "Protocol Stage1 query failed: " +
                          out.stage1.error_message;
      return out;
    }
    if (std::abs(out.stage1.cosine_threshold - config.final_threshold) >
            1e-12 ||
        out.stage1.simhash_bits != fingerprint_bits) {
      out.error_message =
          "Protocol Stage1/BFV threshold contract is not aligned";
      return out;
    }
    if (out.stage1.pair_bfv_pack_refs.size() != out.stage1.c0.pairs.size() ||
        std::any_of(out.stage1.pair_bfv_pack_refs.begin(),
                    out.stage1.pair_bfv_pack_refs.end(),
                    [](const auto& ref) { return !ref.IsValid(); })) {
      out.error_message =
          "Protocol Stage1 did not recover authenticated BFV pack routing for every pair";
      return out;
    }

    stage2::ExactHePreparedPairBatchInput exact_input;
    exact_input.queries = integer_queries;
    exact_input.relation = out.stage1.c0;
    exact_input.pair_pack_refs = out.stage1.pair_bfv_pack_refs;
    const auto bfv_begin = Clock::now();
    out.exact_he = exact_session.RunPreparedPairRelation(
        exact_input, prepared, config.exact_he);
    out.metrics.bfv_ms = ElapsedMs(bfv_begin);
    if (!out.exact_he.ok) {
      out.error_message = "Protocol BFV evaluation failed: " +
                          out.exact_he.error_message;
      return out;
    }

    stage3::BatchedYaoBackend gc;

    stage3::BatchedCompareRequest request;
    request.compare_bits = out.exact_he.compare_bits;
    request.signed_compare = true;
    request.lhs_share_modulus = out.exact_he.plaintext_modulus;
    request.evaluator_role = stage3::PartyRole::Receiver;
    request.session_tag = "cosine-threshold-fpsi";
    request.lhs_shares.party0.assign(
        out.exact_he.sender_masked_shares.begin(),
        out.exact_he.sender_masked_shares.end());
    request.lhs_shares.party1.assign(
        out.exact_he.receiver_mask_shares.begin(),
        out.exact_he.receiver_mask_shares.end());
    request.rhs_shares.party0.assign(
        out.exact_he.lane_count,
        static_cast<stage3::RingElem>(out.exact_he.threshold));
    request.rhs_shares.party1.assign(out.exact_he.lane_count, 0);
    request.dummy_mask = out.exact_he.dummy_mask;
    stage3::LoopbackTransport transport;
    stage3::InMemoryTranscript transcript;
    stage3::ProtocolContext context;
    context.session_tag = request.session_tag;
    context.party_role = stage3::PartyRole::Sender;
    context.transport = &transport;
    context.transcript = &transcript;
    context.ResetSession();
    request.protocol_context = &context;
    const auto gc_begin = Clock::now();
    out.comparison = gc.Compare(request);
    out.metrics.gc_ms = ElapsedMs(gc_begin);
    if (!out.comparison.ok) {
      out.error_message = out.comparison.error_message;
      if (out.error_message.empty()) {
        out.error_message = "Protocol Yao comparison failed";
      }
      return out;
    }

    const std::size_t count = std::min(
        out.exact_he.scheduled_relation.pairs.size(),
        out.comparison.final_match_bits.size());
    for (std::size_t index = 0; index < count; ++index) {
      const auto& pair = out.exact_he.scheduled_relation.pairs[index];
      if (pair.valid && out.comparison.final_match_bits[index] != 0) {
        out.matches.pairs.push_back(pair);
      }
    }
    out.matches.overflow = out.stage1.c0.overflow;
    out.matches.required_pair_count = out.stage1.c0.required_pair_count;
    out.matches.overflow_reason = out.stage1.c0.overflow_reason;

    out.metrics.context_creation_count = exact_session.ContextCreationCount();
    out.metrics.key_generation_count = exact_session.KeyGenerationCount();
    out.metrics.candidate_pack_count = prepared.ciphertext_pack_count;
    out.metrics.candidate_encrypt_count = prepared.ciphertext_pack_count;
    out.metrics.candidates_per_pack = prepared.candidates_per_pack;
    out.metrics.replica_slot_count = prepared.replica_slot_count;
    out.metrics.candidate_replication_factor =
        prepared.candidate_replication_factor;
    out.metrics.pack_round_count = out.exact_he.pack_round_count;
    out.metrics.pairs_using_replica = out.exact_he.pairs_using_replica;
    out.metrics.requested_round_parallelism =
        out.exact_he.requested_round_parallelism;
    out.metrics.effective_round_parallelism =
        out.exact_he.effective_round_parallelism;
    out.metrics.parallel_round_execution_used =
        out.exact_he.parallel_round_execution_used;
    out.metrics.bfv_round_processing_wall_ms =
        out.exact_he.round_processing_wall_ms;
    out.metrics.bfv_aggregate_round_worker_ms =
        out.exact_he.aggregate_round_worker_ms;
    out.metrics.masked_score_towers_before_compression =
        out.exact_he.masked_score_towers_before_compression;
    out.metrics.masked_score_towers_after_compression =
        out.exact_he.masked_score_towers_after_compression;
    out.metrics.masked_score_ciphertext_compressed =
        out.exact_he.masked_score_ciphertext_compressed;
    out.metrics.valid_pair_count = static_cast<std::size_t>(std::count(
        out.exact_he.dummy_mask.begin(), out.exact_he.dummy_mask.end(), 0));
    out.metrics.total_lane_count = out.exact_he.lane_count;
    if (out.metrics.total_lane_count != 0) {
      out.metrics.valid_lane_ratio =
          static_cast<double>(out.metrics.valid_pair_count) /
          static_cast<double>(out.metrics.total_lane_count);
    }
    out.metrics.gc_ot_setup_count = out.comparison.ot_setup_count;
    out.metrics.gc_ot_count = out.comparison.compare_ot_count;
    out.metrics.stage1_cross_query_batch = HasMixedQueries(out.stage1.oprf_batches);
    out.metrics.bfv_cross_query_round = out.exact_he.mixed_query_round_count > 0;
    out.metrics.score_reconstruction_used = false;
    out.metrics.threshold_contract_aligned = true;
    out.metrics.stage1_pack_routing_recovered =
        out.stage1.pair_bfv_pack_refs.size() == out.stage1.c0.pairs.size();
    out.metrics.stage2_pack_routing_verified =
        out.exact_he.stage1_pack_routing_verified;
    out.metrics.circuit_privacy_parameter_checks_passed =
        out.exact_he.circuit_privacy_parameter_checks_passed;
    out.metrics.noise_flooding_applied =
        out.exact_he.noise_flooding_applied;
    out.metrics.divide_and_round_circuit_privacy_applied =
        out.exact_he.divide_and_round_circuit_privacy_applied;
    out.metrics.circuit_privacy_parameter_check_passed =
        out.exact_he.circuit_privacy_parameter_check_passed;
    out.metrics.circuit_privacy_query_bound_check_passed =
        out.exact_he.circuit_privacy_query_bound_check_passed;
    out.metrics.circuit_privacy_correctness_check_passed =
        out.exact_he.circuit_privacy_correctness_check_passed;
    out.metrics.circuit_privacy_statistical_security_bits =
        out.exact_he.circuit_privacy_statistical_security_bits;
    out.metrics.circuit_privacy_max_decryption_queries =
        out.exact_he.circuit_privacy_max_decryption_queries;
    out.metrics.circuit_privacy_ciphertext_count =
        out.exact_he.circuit_privacy_ciphertext_count;
    out.metrics.circuit_privacy_cumulative_ciphertext_count =
        out.exact_he.circuit_privacy_cumulative_ciphertext_count;
    out.metrics.circuit_privacy_remaining_decryption_budget =
        out.exact_he.circuit_privacy_remaining_decryption_budget;
    out.metrics.circuit_privacy_security_margin_bits =
        out.exact_he.circuit_privacy_security_margin_bits;
    out.metrics.circuit_privacy_joint_failure_log2 =
        out.exact_he.circuit_privacy_joint_failure_log2;
    out.metrics.correctness_margin_bits =
        out.exact_he.correctness_margin_bits;
    out.metrics.ciphertext_sanitization_mode =
        out.exact_he.ciphertext_sanitization_mode;
    out.metrics.circuit_privacy_distribution =
        out.exact_he.circuit_privacy_distribution;
    out.metrics.stage1_simhash_bits = out.stage1.simhash_bits;
    out.metrics.stage1_hamming_threshold = out.stage1.hamming_threshold;
    out.metrics.stage1_block_radius = out.stage1.block_radius;
    out.metrics.stage1_target_recall = out.stage1.target_recall;
    out.metrics.stage1_estimated_recall =
        out.stage1.estimated_recall_at_threshold;
    out.metrics.stage1_rbokvs_table_bytes =
        out.stage1.rbokvs_serialized_table_bytes;
    out.metrics.stage1_probe_bytes = out.stage1.stage1_probe_bytes;
    out.metrics.opening_oprf_request_bytes =
        out.stage1.opening_oprf_request_bytes;
    out.metrics.opening_oprf_response_bytes =
        out.stage1.opening_oprf_response_bytes;
    out.metrics.opening_oprf_bytes = out.stage1.opening_oprf_bytes;
    out.metrics.opening_payload_bytes =
        out.stage1.opening_payload_communication_bytes;
    out.metrics.stage1_offline_communication_bytes =
        out.metrics.stage1_rbokvs_table_bytes +
        out.metrics.opening_payload_bytes;
    out.metrics.stage1_online_communication_bytes =
        out.stage1.probe_oprf_request_bytes +
        out.stage1.probe_oprf_response_bytes +
        out.metrics.opening_oprf_bytes;
    out.metrics.stage1_communication_bytes =
        out.stage1.stage1_total_communication_bytes;
    out.metrics.stage1_raw_probe_hits = out.stage1.num_raw_probe_hits;
    out.metrics.stage1_raw_candidate_pairs = out.stage1.num_C_hit;
    out.metrics.stage1_retained_pairs = out.stage1.num_C0;
    out.metrics.stage1_unique_opened_handles =
        out.stage1.num_unique_surviving_handles;
    out.metrics.stage1_pruning_ratio = out.stage1.pruning_ratio;
    out.metrics.bfv_offline_communication_bytes =
        static_cast<std::uint64_t>(out.exact_he.candidate_ciphertext_bytes);
    out.metrics.bfv_online_communication_bytes =
        static_cast<std::uint64_t>(
            out.exact_he.masked_score_ciphertext_bytes);
    out.metrics.bfv_online_communication_bytes_before_compression =
        static_cast<std::uint64_t>(
            out.exact_he.masked_score_ciphertext_bytes_before_compression);
    out.metrics.gc_communication_bytes =
        static_cast<std::uint64_t>(
            out.comparison.compare_garbled_table_bytes) +
        static_cast<std::uint64_t>(
            out.comparison.compare_ot_correction_bytes);
    out.metrics.offline_communication_bytes =
        out.metrics.stage1_offline_communication_bytes +
        out.metrics.bfv_offline_communication_bytes;
    out.metrics.online_communication_bytes =
        out.metrics.stage1_online_communication_bytes +
        out.metrics.bfv_online_communication_bytes +
        out.metrics.gc_communication_bytes;
    out.metrics.total_communication_bytes =
        out.metrics.offline_communication_bytes +
        out.metrics.online_communication_bytes;
    out.metrics.online_ms = out.metrics.stage1_ms + out.metrics.bfv_ms +
                            out.metrics.gc_ms;
    out.metrics.total_ms = ElapsedMs(total_begin);

    if (config.require_cross_query_batch_evidence &&
        input.query_vectors.size() > 1 &&
        (!out.metrics.stage1_cross_query_batch ||
         !out.metrics.bfv_cross_query_round)) {
      out.error_message =
          "Protocol did not produce cross-query OPRF and BFV batches";
      return out;
    }
    out.ok = true;
    return out;
  } catch (const std::exception& ex) {
    out.error_message = std::string("Protocol failed: ") + ex.what();
    return out;
  }
}

}  // namespace ctfpsi::pipeline
