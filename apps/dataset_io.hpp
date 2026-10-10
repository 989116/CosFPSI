#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

namespace ctfpsi::dataset {

struct DatasetMeta {
  std::string dataset_id;
  std::size_t N = 0;
  std::size_t Q = 0;
  std::size_t d = 0;
  double tau = 0.0;
  double eta = 0.0;
  std::size_t k = 1;
  std::string dataset_mode = "unconstrained";
  double delta_l2 = 0.0;
  double delta_l2_squared = 0.0;
  double quantization_scale = 0.0;
  std::int64_t integer_radius = 0;
  std::int64_t integer_threshold_value = 0;
  std::string integer_threshold_mode;
  std::string gt_semantics;
  std::string pair_semantics;
  double target_match_rate = 0.0;
  std::uint64_t seed = 0;
};

struct RunnerResult {
  std::string system_name;
  std::string execution_mode;
  std::string protocol_version;
  std::string dataset_id;
  std::size_t N = 0;
  std::size_t Q = 0;
  std::size_t d = 0;
  double tau = 0.0;
  double delta_l2 = 0.0;
  double precision = 0.0;
  double recall = 0.0;
  double f1 = 0.0;
  double offline_ms = 0.0;
  double online_ms = 0.0;
  double total_ms = 0.0;
  std::uint64_t communication_bytes = 0;
  std::string notes;
  std::string failure_reason;
  std::vector<std::pair<std::size_t, std::size_t>> predicted_pairs;
};

struct PairMetrics {
  double precision = 0.0;
  double recall = 0.0;
  double f1 = 0.0;
  std::size_t tp = 0;
  std::size_t pred = 0;
  std::size_t gt = 0;
};

std::string EscapeJson(const std::string& in);
std::string QuoteCommandArg(const std::filesystem::path& path);
std::string QuoteCommandArg(const std::string& value);

void WriteFloat64NpyMatrix(const std::filesystem::path& path,
                           std::size_t rows,
                           std::size_t cols,
                           const std::vector<double>& values);
void WriteDoubleCsvMatrix(const std::filesystem::path& path,
                          std::size_t rows,
                          std::size_t cols,
                          const std::vector<double>& values);
void WriteInt64CsvMatrix(const std::filesystem::path& path,
                         std::size_t rows,
                         std::size_t cols,
                         const std::vector<std::int64_t>& values);
void WriteDatasetMetaJson(const std::filesystem::path& path, const DatasetMeta& meta);
void WriteGtPairsJson(const std::filesystem::path& path,
                      const DatasetMeta& meta,
                      const std::vector<std::pair<std::size_t, std::size_t>>& gt_pairs);

DatasetMeta LoadDatasetMeta(const std::filesystem::path& path);
std::vector<std::pair<std::size_t, std::size_t>> LoadGtPairs(const std::filesystem::path& path);
RunnerResult LoadRunnerResult(const std::filesystem::path& path);
void WriteRunnerResultJson(const std::filesystem::path& path, const RunnerResult& result);

PairMetrics ComputePairMetrics(const std::vector<std::pair<std::size_t, std::size_t>>& predicted_pairs,
                               const std::vector<std::pair<std::size_t, std::size_t>>& gt_pairs);

std::vector<std::string> ReadNonEmptyLines(const std::filesystem::path& path);
std::vector<std::string> SplitCsvLine(const std::string& line);
std::string JoinNotes(const std::vector<std::string>& parts);

bool FileExists(const std::filesystem::path& path);
std::filesystem::path ResolveSiblingExecutable(const std::filesystem::path& argv0,
                                               const std::string& executable_name);

}  // namespace ctfpsi::dataset


