#include <algorithm>
#include <filesystem>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "dataset_io.hpp"
#include "pipeline/cosine_threshold_protocol.hpp"
#include "stage1/query_preprocessor.hpp"

namespace {

struct Options {
  std::filesystem::path dataset_dir;
  std::filesystem::path output;
  std::size_t warmups = 1;
  std::size_t repeats = 1;
  std::size_t simhash_bits = 32;
  std::size_t num_blocks = 16;
  std::size_t c0_cap = 0;
  std::size_t min_block_radius = std::numeric_limits<std::size_t>::max();
  double hamming_sigma_margin = -1.0;
  double target_recall = -1.0;
  std::size_t candidate_replication_factor = 1;
  std::size_t round_parallelism = 16;
  bool compress_masked_scores = true;
  bool disable_threshold_pruning = false;
};

Options ParseArgs(int argc, char** argv) {
  Options out;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--dataset-dir" && i + 1 < argc) {
      out.dataset_dir = argv[++i];
    } else if (arg == "--output" && i + 1 < argc) {
      out.output = argv[++i];
    } else if (arg == "--warmups" && i + 1 < argc) {
      out.warmups = std::stoull(argv[++i]);
    } else if (arg == "--repeats" && i + 1 < argc) {
      out.repeats = std::stoull(argv[++i]);
    } else if (arg == "--simhash-bits" && i + 1 < argc) {
      out.simhash_bits = std::stoull(argv[++i]);
    } else if (arg == "--blocks" && i + 1 < argc) {
      out.num_blocks = std::stoull(argv[++i]);
    } else if (arg == "--c0-cap" && i + 1 < argc) {
      out.c0_cap = std::stoull(argv[++i]);
    } else if (arg == "--min-block-radius" && i + 1 < argc) {
      out.min_block_radius = std::stoull(argv[++i]);
    } else if (arg == "--hamming-sigma" && i + 1 < argc) {
      out.hamming_sigma_margin = std::stod(argv[++i]);
    } else if (arg == "--target-recall" && i + 1 < argc) {
      out.target_recall = std::stod(argv[++i]);
    } else if (arg == "--candidate-replication" && i + 1 < argc) {
      out.candidate_replication_factor = std::stoull(argv[++i]);
    } else if (arg == "--round-parallelism" && i + 1 < argc) {
      out.round_parallelism = std::stoull(argv[++i]);
    } else if (arg == "--no-score-compression") {
      out.compress_masked_scores = false;
    } else if (arg == "--disable-threshold-pruning") {
      out.disable_threshold_pruning = true;
    } else {
      throw std::invalid_argument(
          "Usage: run_dataset --dataset-dir <dir> "
          "--output <json> [--warmups 1] [--repeats 1] "
           "[--simhash-bits 32] [--blocks 16] [--c0-cap N] "
           "[--min-block-radius N] [--hamming-sigma X] "
           "[--target-recall X] "
           "[--candidate-replication 1] [--round-parallelism 16] "
           "[--no-score-compression] [--disable-threshold-pruning]");
    }
  }
  if (out.dataset_dir.empty() || out.output.empty() || out.repeats == 0 ||
      out.simhash_bits == 0 || out.num_blocks == 0 ||
      out.candidate_replication_factor == 0 ||
      out.round_parallelism == 0 ||
      out.simhash_bits % out.num_blocks != 0 ||
      out.target_recall > 1.0 ||
      (out.target_recall < 0.0 && out.target_recall != -1.0)) {
    throw std::invalid_argument("missing dataset/output or zero repeats");
  }
  return out;
}

ctfpsi::common::DenseMatrix LoadFloatCsv(
    const std::filesystem::path& path,
    std::size_t rows,
    std::size_t columns) {
  const auto lines = ctfpsi::dataset::ReadNonEmptyLines(path);
  if (lines.size() != rows) {
    throw std::runtime_error("CSV row count mismatch: " + path.string());
  }
  ctfpsi::common::DenseMatrix matrix;
  matrix.reserve(rows);
  for (const auto& line : lines) {
    const auto fields = ctfpsi::dataset::SplitCsvLine(line);
    if (fields.size() != columns) {
      throw std::runtime_error("CSV column count mismatch: " + path.string());
    }
    ctfpsi::common::DenseVector row;
    row.reserve(columns);
    for (const auto& field : fields) {
      row.push_back(std::stod(field));
    }
    matrix.push_back(std::move(row));
  }
  return matrix;
}

ctfpsi::pipeline::ManyToManyInput BuildInput(
    const ctfpsi::common::DenseMatrix& sender,
    const ctfpsi::common::DenseMatrix& receiver,
    std::size_t simhash_bits) {
  ctfpsi::pipeline::ManyToManyInput input;
  input.sender_vectors = sender;
  input.query_vectors = receiver;
  ctfpsi::stage1::QueryPreprocessor preprocessor;
  input.sender_fingerprints.reserve(sender.size());
  for (const auto& vector : sender) {
    input.sender_fingerprints.push_back(
        preprocessor.Prepare(vector, simhash_bits).simhash_bits);
  }
  input.query_bundles.reserve(receiver.size());
  for (const auto& vector : receiver) {
    input.query_bundles.push_back(preprocessor.Prepare(vector, simhash_bits));
  }
  return input;
}

std::vector<std::pair<std::size_t, std::size_t>> PredictedPairs(
    const ctfpsi::pipeline::CosineThresholdProtocolResult& result) {
  std::vector<std::pair<std::size_t, std::size_t>> pairs;
  for (const auto& pair : result.matches.pairs) {
    if (pair.valid) {
      pairs.emplace_back(pair.query_id, pair.candidate_id);
    }
  }
  std::sort(pairs.begin(), pairs.end());
  pairs.erase(std::unique(pairs.begin(), pairs.end()), pairs.end());
  return pairs;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    const auto options = ParseArgs(argc, argv);
    const auto meta = ctfpsi::dataset::LoadDatasetMeta(
        options.dataset_dir / "meta.json");
    const bool balanced = meta.N == meta.Q;
    const auto sender = LoadFloatCsv(
        options.dataset_dir / "sender_float.csv", meta.N, meta.d);
    const auto receiver = LoadFloatCsv(
        options.dataset_dir / "receiver_float.csv", meta.Q, meta.d);
    const auto input = BuildInput(sender, receiver, options.simhash_bits);

    ctfpsi::pipeline::CosineThresholdProtocolConfig config;
    config.stage1_options = ctfpsi::stage1::BuildStage1DefaultBuildOptions();
    config.stage1_options.num_blocks = options.num_blocks;
    config.stage1_options.min_block_radius =
        options.min_block_radius == std::numeric_limits<std::size_t>::max()
            ? (balanced ? 1 : 3)
            : options.min_block_radius;
    config.stage1_options.hamming_sigma_margin =
        options.hamming_sigma_margin < 0.0
            ? (balanced ? 0.0 : 1.5)
            : options.hamming_sigma_margin;
    if (options.target_recall >= 0.0) {
      config.stage1_options.target_recall = options.target_recall;
    } else if (options.hamming_sigma_margin >= 0.0) {
      // An explicit sigma request takes precedence over the default recall policy.
      config.stage1_options.target_recall = 0.0;
    }
    config.stage1_options.c0_cap = options.c0_cap;
    config.stage1_options.disable_threshold_pruning =
        options.disable_threshold_pruning;
    config.exact_he.plaintext_modulus = 65537;
    config.fixed_point_scale_bits = 6;
    config.final_threshold = meta.tau;
    config.candidates_per_pack = 0;
    config.automatic_pack_width_limit = 128;
    config.candidate_replication_factor =
        options.candidate_replication_factor;
    config.round_parallelism = options.round_parallelism;
    config.compress_masked_score_ciphertext =
        options.compress_masked_scores;
    config.exact_he.collect_round_traces = false;
    // Dense relations can legitimately align the same query across a round.
    config.require_cross_query_batch_evidence = false;

    for (std::size_t i = 0; i < options.warmups; ++i) {
      const auto warmup =
          ctfpsi::pipeline::CosineThresholdProtocol::Run(input, config);
      if (!warmup.ok) {
        throw std::runtime_error("BFV warmup failed: " + warmup.error_message);
      }
    }

    ctfpsi::pipeline::CosineThresholdProtocolResult first;
    double offline_ms = 0.0;
    double online_ms = 0.0;
    double total_ms = 0.0;
    for (std::size_t i = 0; i < options.repeats; ++i) {
      auto result =
          ctfpsi::pipeline::CosineThresholdProtocol::Run(input, config);
      if (!result.ok) {
        throw std::runtime_error("BFV measured run failed: " + result.error_message);
      }
      offline_ms += result.metrics.setup_ms + result.metrics.offline_ms;
      online_ms += result.metrics.online_ms;
      total_ms += result.metrics.total_ms;
      if (i == 0) {
        first = std::move(result);
      }
    }

    const auto predicted = PredictedPairs(first);
    const auto ground_truth = ctfpsi::dataset::LoadGtPairs(
        options.dataset_dir / "gt_pairs.json");
    const auto metrics =
        ctfpsi::dataset::ComputePairMetrics(predicted, ground_truth);
    const double divisor = static_cast<double>(options.repeats);

    ctfpsi::dataset::RunnerResult output;
    output.system_name = "Cosine-Threshold FPSI";
    output.execution_mode = first.metrics.execution_mode;
    output.protocol_version = first.metrics.protocol_version;
    output.dataset_id = meta.dataset_id;
    output.N = meta.N;
    output.Q = meta.Q;
    output.d = meta.d;
    output.tau = meta.tau;
    output.delta_l2 = meta.delta_l2;
    output.predicted_pairs = predicted;
    output.precision = metrics.precision;
    output.recall = metrics.recall;
    output.f1 = metrics.f1;
    output.offline_ms = offline_ms / divisor;
    output.online_ms = online_ms / divisor;
    output.total_ms = total_ms / divisor;
    output.communication_bytes = first.metrics.total_communication_bytes;
    output.notes = ctfpsi::dataset::JoinNotes({
        balanced ? "balanced sender/query dataset"
                 : "general non-balanced sender/query dataset",
        "BFV plaintext_modulus=65537 fixed_point_scale_bits=6 context_depth=" +
            std::to_string(first.exact_he.circuit_privacy_context_depth) +
            " modulus_bits=" +
            std::to_string(first.exact_he.circuit_privacy_modulus_bits),
        "Stage1 L=" + std::to_string(options.simhash_bits) +
            " m=" + std::to_string(options.num_blocks) +
            " sigma=" +
            std::to_string(config.stage1_options.hamming_sigma_margin) +
            " target_recall=" +
            std::to_string(config.stage1_options.target_recall) +
            " min_block_radius=" +
            std::to_string(config.stage1_options.min_block_radius) +
            " c0_cap=" + std::to_string(config.stage1_options.c0_cap),
        "automatic BFV pack width=" +
            std::to_string(first.metrics.candidates_per_pack),
        "BFV candidate replication factor=" +
            std::to_string(first.metrics.candidate_replication_factor),
        "BFV round parallelism requested=" +
            std::to_string(first.metrics.requested_round_parallelism) +
            " effective=" +
            std::to_string(first.metrics.effective_round_parallelism),
        "masked-score compression=" +
            std::string(first.metrics.masked_score_ciphertext_compressed
                            ? "one-tower"
                            : "disabled"),
        "Stage1 authenticated BFV pack routing=" +
            std::string(first.metrics.stage2_pack_routing_verified
                            ? "verified"
                            : "not verified"),
        "ciphertext sanitization=" +
            first.metrics.ciphertext_sanitization_mode,
        "circuit privacy parameter checks=" +
            std::string(first.metrics.circuit_privacy_parameter_checks_passed
                            ? "passed"
                            : "failed"),
        "circuit privacy lambda=" +
            std::to_string(
                first.metrics.circuit_privacy_statistical_security_bits) +
            " max_ciphertexts=" +
            std::to_string(
                first.metrics.circuit_privacy_max_decryption_queries) +
            " security_margin_bits=" +
            std::to_string(
                first.metrics.circuit_privacy_security_margin_bits) +
            " correctness_margin_bits=" +
            std::to_string(first.metrics.correctness_margin_bits),
        std::string("TPCR threshold pruning=") +
            (first.stage1.threshold_pruning_enabled ? "enabled" : "disabled"),
        "Stage1 candidate pairs=" +
            std::to_string(first.stage1.c0.pairs.size()),
        "TPCR raw candidate pairs=" +
            std::to_string(first.stage1.num_C_hit) +
            " pruning_pass_pairs=" + std::to_string(first.stage1.num_C0) +
            " unique_opened_handles=" +
            std::to_string(first.stage1.num_unique_surviving_handles),
        "BFV pack rounds=" +
            std::to_string(first.metrics.pack_round_count),
        "BFV valid lane ratio=" +
            std::to_string(first.metrics.valid_lane_ratio),
        "timing_ms stage1=" + std::to_string(first.metrics.stage1_ms) +
            " bfv=" + std::to_string(first.metrics.bfv_ms) +
            " gc=" + std::to_string(first.metrics.gc_ms) +
            " bfv_evaluate=" + std::to_string(first.exact_he.evaluate_ms) +
            " bfv_mask=" + std::to_string(first.exact_he.mask_ms) +
            " bfv_decrypt=" + std::to_string(first.exact_he.decrypt_ms),
        "BFV round wall_ms=" +
            std::to_string(first.exact_he.round_processing_wall_ms) +
            " aggregate_worker_ms=" +
            std::to_string(first.exact_he.aggregate_round_worker_ms),
        "communication=protocol payload bytes",
    });
    if (metrics.f1 != 1.0) {
      output.failure_reason = "BFV result did not reproduce GT";
    }
    if (!options.output.parent_path().empty()) {
      std::filesystem::create_directories(options.output.parent_path());
    }
    ctfpsi::dataset::WriteRunnerResultJson(options.output, output);
    std::cout << "[BFV] N=" << meta.N << " Q=" << meta.Q << " d=" << meta.d
              << " tau=" << meta.tau << " L=" << options.simhash_bits
              << " m=" << options.num_blocks
              << " pairs=" << predicted.size()
              << " c0_pairs=" << first.stage1.c0.pairs.size()
              << " pack_rounds=" << first.metrics.pack_round_count
              << " lane_ratio=" << first.metrics.valid_lane_ratio
              << " stage1_ms=" << first.metrics.stage1_ms
              << " bfv_ms=" << first.metrics.bfv_ms
              << " bfv_evaluate_ms=" << first.exact_he.evaluate_ms
              << " bfv_mask_ms=" << first.exact_he.mask_ms
              << " bfv_decrypt_ms=" << first.exact_he.decrypt_ms
              << " bfv_round_parallelism="
              << first.metrics.effective_round_parallelism
              << " bfv_round_wall_ms="
              << first.exact_he.round_processing_wall_ms
              << " gc_ms=" << first.metrics.gc_ms
              << " total_ms=" << output.total_ms
              << " communication_bytes=" << output.communication_bytes
              << " circuit_privacy_parameter_checks_passed="
              << first.metrics.circuit_privacy_parameter_checks_passed
              << " cp_security_margin_bits="
              << first.metrics.circuit_privacy_security_margin_bits
              << " f1=" << output.f1 << '\n';
    return output.failure_reason.empty() ? 0 : 2;
  } catch (const std::exception& ex) {
    std::cerr << "run_dataset_error=" << ex.what() << '\n';
    return 1;
  }
}

