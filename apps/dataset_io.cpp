#include "dataset_io.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>

namespace ctfpsi::dataset {
namespace {

std::string LoadTextFile(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in.good()) {
    throw std::runtime_error("Cannot open file: " + path.string());
  }
  std::ostringstream buffer;
  buffer << in.rdbuf();
  return buffer.str();
}

std::string ExtractStringField(const std::string& text, const std::string& key) {
  const std::regex re("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"");
  std::smatch match;
  if (!std::regex_search(text, match, re)) {
    throw std::runtime_error("Missing string field: " + key);
  }
  return match[1].str();
}

double ExtractDoubleField(const std::string& text, const std::string& key) {
  const std::regex re("\"" + key + "\"\\s*:\\s*(-?[0-9]+(?:\\.[0-9]+)?)");
  std::smatch match;
  if (!std::regex_search(text, match, re)) {
    throw std::runtime_error("Missing numeric field: " + key);
  }
  return std::stod(match[1].str());
}

bool TryExtractDoubleField(const std::string& text, const std::string& key, double* out) {
  const std::regex re("\"" + key + "\"\\s*:\\s*(-?[0-9]+(?:\\.[0-9]+)?)");
  std::smatch match;
  if (!std::regex_search(text, match, re)) {
    return false;
  }
  *out = std::stod(match[1].str());
  return true;
}

std::uint64_t ExtractUint64Field(const std::string& text, const std::string& key) {
  const std::regex re("\"" + key + "\"\\s*:\\s*([0-9]+)");
  std::smatch match;
  if (!std::regex_search(text, match, re)) {
    throw std::runtime_error("Missing integer field: " + key);
  }
  return static_cast<std::uint64_t>(std::stoull(match[1].str()));
}

std::string Trim(std::string value) {
  const auto not_space = [](unsigned char ch) { return !std::isspace(ch); };
  value.erase(value.begin(), std::find_if(value.begin(), value.end(), not_space));
  value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(), value.end());
  return value;
}

}  // namespace

std::string EscapeJson(const std::string& in) {
  std::string out;
  out.reserve(in.size());
  for (const char ch : in) {
    switch (ch) {
      case '\\':
        out += "\\\\";
        break;
      case '"':
        out += "\\\"";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        out.push_back(ch);
        break;
    }
  }
  return out;
}

std::string QuoteCommandArg(const std::filesystem::path& path) {
  return QuoteCommandArg(path.string());
}

std::string QuoteCommandArg(const std::string& value) {
  std::string quoted = "\"";
  for (const char ch : value) {
    if (ch == '"') {
      quoted += "\\\"";
    } else {
      quoted.push_back(ch);
    }
  }
  quoted.push_back('"');
  return quoted;
}

void WriteFloat64NpyMatrix(const std::filesystem::path& path,
                           std::size_t rows,
                           std::size_t cols,
                           const std::vector<double>& values) {
  if (values.size() != rows * cols) {
    throw std::runtime_error("WriteFloat64NpyMatrix size mismatch");
  }

  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out.good()) {
    throw std::runtime_error("Cannot write npy file: " + path.string());
  }

  const std::string dict =
      "{'descr': '<f8', 'fortran_order': False, 'shape': (" + std::to_string(rows) + ", " +
      std::to_string(cols) + "), }";
  std::string header = dict;
  header.push_back('\n');

  constexpr std::size_t kPreamble = 10;
  while ((kPreamble + header.size()) % 16 != 0) {
    header.insert(header.end() - 1, ' ');
  }

  out.write("\x93NUMPY", 6);
  const char major = 1;
  const char minor = 0;
  out.put(major);
  out.put(minor);

  const std::uint16_t header_len = static_cast<std::uint16_t>(header.size());
  out.put(static_cast<char>(header_len & 0xFFu));
  out.put(static_cast<char>((header_len >> 8) & 0xFFu));
  out.write(header.data(), static_cast<std::streamsize>(header.size()));
  out.write(reinterpret_cast<const char*>(values.data()),
            static_cast<std::streamsize>(values.size() * sizeof(double)));
}

void WriteDoubleCsvMatrix(const std::filesystem::path& path,
                          std::size_t rows,
                          std::size_t cols,
                          const std::vector<double>& values) {
  if (values.size() != rows * cols) {
    throw std::runtime_error("WriteDoubleCsvMatrix size mismatch");
  }
  std::ofstream out(path, std::ios::out | std::ios::trunc);
  if (!out.good()) {
    throw std::runtime_error("Cannot write csv file: " + path.string());
  }
  out << std::setprecision(17);
  for (std::size_t r = 0; r < rows; ++r) {
    for (std::size_t c = 0; c < cols; ++c) {
      if (c != 0) {
        out << ",";
      }
      out << values[r * cols + c];
    }
    out << "\n";
  }
}

void WriteInt64CsvMatrix(const std::filesystem::path& path,
                         std::size_t rows,
                         std::size_t cols,
                         const std::vector<std::int64_t>& values) {
  if (values.size() != rows * cols) {
    throw std::runtime_error("WriteInt64CsvMatrix size mismatch");
  }
  std::ofstream out(path, std::ios::out | std::ios::trunc);
  if (!out.good()) {
    throw std::runtime_error("Cannot write csv file: " + path.string());
  }
  for (std::size_t r = 0; r < rows; ++r) {
    for (std::size_t c = 0; c < cols; ++c) {
      if (c != 0) {
        out << ",";
      }
      out << values[r * cols + c];
    }
    out << "\n";
  }
}

void WriteDatasetMetaJson(const std::filesystem::path& path, const DatasetMeta& meta) {
  std::ofstream out(path, std::ios::out | std::ios::trunc);
  if (!out.good()) {
    throw std::runtime_error("Cannot write meta json: " + path.string());
  }
  out << std::fixed << std::setprecision(12);
  out << "{\n";
  out << "  \"dataset_id\": \"" << EscapeJson(meta.dataset_id) << "\",\n";
  out << "  \"N\": " << meta.N << ",\n";
  out << "  \"Q\": " << meta.Q << ",\n";
  out << "  \"d\": " << meta.d << ",\n";
  out << "  \"tau\": " << meta.tau << ",\n";
  out << "  \"eta\": " << meta.eta << ",\n";
  out << "  \"k\": " << meta.k << ",\n";
  out << "  \"dataset_mode\": \"" << EscapeJson(meta.dataset_mode) << "\",\n";
  out << "  \"delta_l2\": " << meta.delta_l2 << ",\n";
  out << "  \"delta_l2_squared\": " << meta.delta_l2_squared << ",\n";
  out << "  \"quantization_scale\": " << meta.quantization_scale << ",\n";
  out << "  \"integer_radius\": " << meta.integer_radius << ",\n";
  out << "  \"integer_threshold_value\": " << meta.integer_threshold_value << ",\n";
  out << "  \"integer_threshold_mode\": \"" << EscapeJson(meta.integer_threshold_mode) << "\",\n";
  out << "  \"gt_semantics\": \"" << EscapeJson(meta.gt_semantics) << "\",\n";
  out << "  \"pair_semantics\": \"" << EscapeJson(meta.pair_semantics) << "\",\n";
  out << "  \"target_match_rate\": " << meta.target_match_rate << ",\n";
  out << "  \"seed\": " << meta.seed << "\n";
  out << "}\n";
}

void WriteGtPairsJson(const std::filesystem::path& path,
                      const DatasetMeta& meta,
                      const std::vector<std::pair<std::size_t, std::size_t>>& gt_pairs) {
  std::ofstream out(path, std::ios::out | std::ios::trunc);
  if (!out.good()) {
    throw std::runtime_error("Cannot write gt json: " + path.string());
  }
  out << std::fixed << std::setprecision(12);
  out << "{\n";
  out << "  \"definition\": \"" << EscapeJson(meta.gt_semantics) << "\",\n";
  out << "  \"tau\": " << meta.tau << ",\n";
  out << "  \"pair_count\": " << gt_pairs.size() << ",\n";
  out << "  \"pairs\": [\n";
  for (std::size_t i = 0; i < gt_pairs.size(); ++i) {
    out << "    [" << gt_pairs[i].first << ", " << gt_pairs[i].second << "]";
    if (i + 1 < gt_pairs.size()) {
      out << ",";
    }
    out << "\n";
  }
  out << "  ]\n";
  out << "}\n";
}

DatasetMeta LoadDatasetMeta(const std::filesystem::path& path) {
  const std::string text = LoadTextFile(path);
  DatasetMeta meta;
  meta.dataset_id = ExtractStringField(text, "dataset_id");
  meta.N = static_cast<std::size_t>(ExtractUint64Field(text, "N"));
  meta.Q = static_cast<std::size_t>(ExtractUint64Field(text, "Q"));
  meta.d = static_cast<std::size_t>(ExtractUint64Field(text, "d"));
  meta.tau = ExtractDoubleField(text, "tau");
  meta.eta = ExtractDoubleField(text, "eta");
  meta.k = static_cast<std::size_t>(ExtractUint64Field(text, "k"));
  meta.dataset_mode = ExtractStringField(text, "dataset_mode");
  meta.delta_l2 = ExtractDoubleField(text, "delta_l2");
  meta.delta_l2_squared = ExtractDoubleField(text, "delta_l2_squared");
  meta.quantization_scale = ExtractDoubleField(text, "quantization_scale");
  meta.integer_radius = static_cast<std::int64_t>(ExtractUint64Field(text, "integer_radius"));
  meta.integer_threshold_value = static_cast<std::int64_t>(ExtractUint64Field(text, "integer_threshold_value"));
  meta.integer_threshold_mode = ExtractStringField(text, "integer_threshold_mode");
  meta.gt_semantics = ExtractStringField(text, "gt_semantics");
  meta.pair_semantics = ExtractStringField(text, "pair_semantics");
  meta.target_match_rate = ExtractDoubleField(text, "target_match_rate");
  meta.seed = ExtractUint64Field(text, "seed");
  return meta;
}

std::vector<std::pair<std::size_t, std::size_t>> LoadGtPairs(const std::filesystem::path& path) {
  const std::string text = LoadTextFile(path);
  const std::regex pair_re("\\[\\s*([0-9]+)\\s*,\\s*([0-9]+)\\s*\\]");
  std::vector<std::pair<std::size_t, std::size_t>> pairs;
  for (std::sregex_iterator it(text.begin(), text.end(), pair_re), end; it != end; ++it) {
    pairs.emplace_back(static_cast<std::size_t>(std::stoull((*it)[1].str())),
                       static_cast<std::size_t>(std::stoull((*it)[2].str())));
  }
  std::sort(pairs.begin(), pairs.end());
  pairs.erase(std::unique(pairs.begin(), pairs.end()), pairs.end());
  return pairs;
}

RunnerResult LoadRunnerResult(const std::filesystem::path& path) {
  const std::string text = LoadTextFile(path);
  RunnerResult result;
  result.system_name = ExtractStringField(text, "system_name");
  try {
    result.execution_mode =
        ExtractStringField(text, "execution_mode");
    result.protocol_version =
        ExtractStringField(text, "protocol_version");
  } catch (const std::exception&) {
    result.execution_mode = "unspecified";
    result.protocol_version = "unspecified";
  }
  result.dataset_id = ExtractStringField(text, "dataset_id");
  result.N = static_cast<std::size_t>(ExtractUint64Field(text, "N"));
  result.Q = static_cast<std::size_t>(ExtractUint64Field(text, "Q"));
  result.d = static_cast<std::size_t>(ExtractUint64Field(text, "d"));
  result.tau = ExtractDoubleField(text, "tau");
  if (!TryExtractDoubleField(text, "delta_l2", &result.delta_l2)) {
    result.delta_l2 = 0.0;
  }
  result.precision = ExtractDoubleField(text, "precision");
  result.recall = ExtractDoubleField(text, "recall");
  result.f1 = ExtractDoubleField(text, "f1");
  result.offline_ms = ExtractDoubleField(text, "offline_ms");
  result.online_ms = ExtractDoubleField(text, "online_ms");
  result.total_ms = ExtractDoubleField(text, "total_ms");
  result.communication_bytes = ExtractUint64Field(text, "communication_bytes");
  result.notes = ExtractStringField(text, "notes");
  try {
    result.failure_reason = ExtractStringField(text, "failure_reason");
  } catch (const std::exception&) {
    result.failure_reason.clear();
  }
  const std::regex pair_re("\\[\\s*([0-9]+)\\s*,\\s*([0-9]+)\\s*\\]");
  const std::size_t begin = text.find("\"predicted_pairs\"");
  const std::size_t end = text.find("\"precision\"");
  if (begin != std::string::npos && end != std::string::npos && end > begin) {
    const std::string pairs_text = text.substr(begin, end - begin);
    for (std::sregex_iterator it(pairs_text.begin(), pairs_text.end(), pair_re), end_it; it != end_it; ++it) {
      result.predicted_pairs.emplace_back(static_cast<std::size_t>(std::stoull((*it)[1].str())),
                                          static_cast<std::size_t>(std::stoull((*it)[2].str())));
    }
  }
  return result;
}

void WriteRunnerResultJson(const std::filesystem::path& path, const RunnerResult& result) {
  std::ofstream out(path, std::ios::out | std::ios::trunc);
  if (!out.good()) {
    throw std::runtime_error("Cannot write result json: " + path.string());
  }
  out << std::fixed << std::setprecision(6);
  out << "{\n";
  out << "  \"system_name\": \"" << EscapeJson(result.system_name) << "\",\n";
  out << "  \"execution_mode\": \""
      << EscapeJson(result.execution_mode) << "\",\n";
  out << "  \"protocol_version\": \""
      << EscapeJson(result.protocol_version) << "\",\n";
  out << "  \"dataset_id\": \"" << EscapeJson(result.dataset_id) << "\",\n";
  out << "  \"N\": " << result.N << ",\n";
  out << "  \"Q\": " << result.Q << ",\n";
  out << "  \"d\": " << result.d << ",\n";
  out << "  \"tau\": " << result.tau << ",\n";
  out << "  \"delta_l2\": " << result.delta_l2 << ",\n";
  out << "  \"predicted_pairs\": [\n";
  for (std::size_t i = 0; i < result.predicted_pairs.size(); ++i) {
    out << "    [" << result.predicted_pairs[i].first << ", " << result.predicted_pairs[i].second << "]";
    if (i + 1 < result.predicted_pairs.size()) {
      out << ",";
    }
    out << "\n";
  }
  out << "  ],\n";
  out << "  \"precision\": " << result.precision << ",\n";
  out << "  \"recall\": " << result.recall << ",\n";
  out << "  \"f1\": " << result.f1 << ",\n";
  out << "  \"offline_ms\": " << result.offline_ms << ",\n";
  out << "  \"online_ms\": " << result.online_ms << ",\n";
  out << "  \"total_ms\": " << result.total_ms << ",\n";
  out << "  \"communication_bytes\": " << result.communication_bytes << ",\n";
  out << "  \"notes\": \"" << EscapeJson(result.notes) << "\",\n";
  out << "  \"failure_reason\": \"" << EscapeJson(result.failure_reason) << "\"\n";
  out << "}\n";
}

PairMetrics ComputePairMetrics(const std::vector<std::pair<std::size_t, std::size_t>>& predicted_pairs,
                               const std::vector<std::pair<std::size_t, std::size_t>>& gt_pairs) {
  const std::set<std::pair<std::size_t, std::size_t>> predicted(predicted_pairs.begin(), predicted_pairs.end());
  const std::set<std::pair<std::size_t, std::size_t>> gt(gt_pairs.begin(), gt_pairs.end());

  PairMetrics metrics;
  metrics.pred = predicted.size();
  metrics.gt = gt.size();
  for (const auto& pair : predicted) {
    if (gt.find(pair) != gt.end()) {
      ++metrics.tp;
    }
  }
  metrics.precision = metrics.pred == 0 ? 0.0 : static_cast<double>(metrics.tp) / static_cast<double>(metrics.pred);
  metrics.recall = metrics.gt == 0 ? 0.0 : static_cast<double>(metrics.tp) / static_cast<double>(metrics.gt);
  metrics.f1 = (metrics.precision + metrics.recall) == 0.0
                   ? 0.0
                   : (2.0 * metrics.precision * metrics.recall) / (metrics.precision + metrics.recall);
  return metrics;
}

std::vector<std::string> ReadNonEmptyLines(const std::filesystem::path& path) {
  std::ifstream in(path);
  if (!in.good()) {
    throw std::runtime_error("Cannot open file: " + path.string());
  }
  std::vector<std::string> lines;
  std::string line;
  while (std::getline(in, line)) {
    line = Trim(line);
    if (!line.empty()) {
      lines.push_back(line);
    }
  }
  return lines;
}

std::vector<std::string> SplitCsvLine(const std::string& line) {
  std::vector<std::string> fields;
  std::string field;
  bool in_quotes = false;
  for (std::size_t i = 0; i < line.size(); ++i) {
    const char ch = line[i];
    if (ch == '"') {
      in_quotes = !in_quotes;
      continue;
    }
    if (ch == ',' && !in_quotes) {
      fields.push_back(Trim(field));
      field.clear();
      continue;
    }
    field.push_back(ch);
  }
  fields.push_back(Trim(field));
  return fields;
}

std::string JoinNotes(const std::vector<std::string>& parts) {
  std::ostringstream out;
  bool first = true;
  for (const auto& part : parts) {
    if (part.empty()) {
      continue;
    }
    if (!first) {
      out << "; ";
    }
    out << part;
    first = false;
  }
  return out.str();
}

bool FileExists(const std::filesystem::path& path) {
  std::error_code ec;
  return std::filesystem::exists(path, ec);
}

std::filesystem::path ResolveSiblingExecutable(const std::filesystem::path& argv0,
                                               const std::string& executable_name) {
  std::filesystem::path base = std::filesystem::absolute(argv0).parent_path();
  return base / executable_name;
}

}  // namespace ctfpsi::dataset


