#include "adapters/rbokvs_adapter.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <vector>

#include "common/config.hpp"
#include "rb_okvs.h"

namespace ctfpsi::adapters {
namespace {
constexpr std::uint64_t kMagic = 0x4354465053494f4bULL;
constexpr std::uint32_t kVersion = 1;
constexpr std::size_t kMetadataBlocks = 5;

void WriteU32(std::uint8_t* out, std::uint32_t value) {
  for (std::size_t i = 0; i < 4; ++i) out[i] = static_cast<std::uint8_t>((value >> (8U * i)) & 0xffU);
}
void WriteU64(std::uint8_t* out, std::uint64_t value) {
  for (std::size_t i = 0; i < 8; ++i) out[i] = static_cast<std::uint8_t>((value >> (8U * i)) & 0xffU);
}
std::uint32_t ReadU32(const std::uint8_t* in) {
  std::uint32_t value = 0;
  for (std::size_t i = 0; i < 4; ++i) value |= std::uint32_t(in[i]) << (8U * i);
  return value;
}
std::uint64_t ReadU64(const std::uint8_t* in) {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < 8; ++i) value |= std::uint64_t(in[i]) << (8U * i);
  return value;
}
oc::block ToBlock(const common::ByteBlock& input) {
  static_assert(sizeof(oc::block) == 16);
  oc::block output{};
  std::memcpy(&output, input.data(), input.size());
  return output;
}
common::ByteBlock FromBlock(const oc::block& input) {
  common::ByteBlock output{};
  std::memcpy(output.data(), &input, output.size());
  return output;
}
struct Metadata {
  std::uint64_t rows = 0;
  std::uint64_t columns = 0;
  std::uint64_t value_blocks = 0;
  common::ByteBlock seed{};
};
std::vector<common::ByteBlock> EncodeMetadata(const Metadata& meta) {
  std::array<std::uint8_t, kMetadataBlocks * 16> bytes{};
  WriteU64(bytes.data(), kMagic);
  WriteU32(bytes.data() + 8, kVersion);
  WriteU64(bytes.data() + 16, meta.rows);
  WriteU64(bytes.data() + 24, meta.columns);
  WriteU64(bytes.data() + 32, meta.value_blocks);
  std::memcpy(bytes.data() + 48, meta.seed.data(), meta.seed.size());
  std::vector<common::ByteBlock> output(kMetadataBlocks);
  for (std::size_t i = 0; i < output.size(); ++i)
    std::memcpy(output[i].data(), bytes.data() + i * 16, 16);
  return output;
}
bool DecodeMetadata(const std::vector<common::ByteBlock>& row, Metadata* meta) {
  if (meta == nullptr || row.size() < kMetadataBlocks) return false;
  std::array<std::uint8_t, kMetadataBlocks * 16> bytes{};
  for (std::size_t i = 0; i < kMetadataBlocks; ++i)
    std::memcpy(bytes.data() + i * 16, row[i].data(), 16);
  if (ReadU64(bytes.data()) != kMagic || ReadU32(bytes.data() + 8) != kVersion) return false;
  meta->rows = ReadU64(bytes.data() + 16);
  meta->columns = ReadU64(bytes.data() + 24);
  meta->value_blocks = ReadU64(bytes.data() + 32);
  std::memcpy(meta->seed.data(), bytes.data() + 48, meta->seed.size());
  return true;
}
bool HasZeroPadding(const std::vector<common::ByteBlock>& value) {
  return !value.empty() && std::all_of(value.back().begin(), value.back().end(),
                                      [](std::uint8_t byte) { return byte == 0; });
}

struct DecodeContext {
  const void* table_identity = nullptr;
  std::size_t table_size = 0;
  std::uint64_t rows = 0;
  common::ByteBlock seed{};
  std::unique_ptr<RBOKVS> decoder;
  std::vector<oc::block> band;
};

DecodeContext& GetDecodeContext(
    const std::vector<std::vector<common::ByteBlock>>& codewords,
    const Metadata& meta) {
  thread_local DecodeContext context;
  if (context.table_identity == codewords.data() &&
      context.table_size == codewords.size() && context.rows == meta.rows &&
      context.seed == meta.seed && context.decoder) {
    return context;
  }
  context.table_identity = codewords.data();
  context.table_size = codewords.size();
  context.rows = meta.rows;
  context.seed = meta.seed;
  context.decoder = std::make_unique<RBOKVS>();
  const auto params = context.decoder->getParams(
      meta.rows, common::config::stage1::kRbokvsEpsilon,
      common::config::stage1::kRbokvsStatSecParam, ToBlock(meta.seed));
  context.decoder->init(params);
  context.band.assign((static_cast<std::size_t>(params.mBandWidth) + 127U) / 128U,
                      oc::ZeroBlock);
  return context;
}
}  // namespace

const char* RbokvsAdapter::BackendModeToString(BackendMode mode) {
  return mode == BackendMode::Rbokvs ? "RB-OKVS" : "Unavailable";
}
RbokvsAdapter::EncodeResponse RbokvsAdapter::Encode(const EncodeRequest& request) const {
  return EncodeWithBackend(request, BackendMode::Rbokvs);
}
RbokvsAdapter::EncodeResponse RbokvsAdapter::EncodeWithBackend(
    const EncodeRequest& request, BackendMode backend) const {
  EncodeResponse response;
  response.requested_backend = backend;
  if (backend != BackendMode::Rbokvs || request.keys.empty() ||
      request.values.size() != request.keys.size() || request.value_length_blocks == 0) {
    response.message = "Invalid RB-OKVS encode request";
    return response;
  }
  std::vector<oc::block> keys;
  std::vector<std::vector<oc::block>> values;
  keys.reserve(request.keys.size());
  values.reserve(request.values.size());
  for (std::size_t i = 0; i < request.keys.size(); ++i) {
    if (request.values[i].size() < request.value_length_blocks) {
      response.message = "RB-OKVS value row is too short";
      return response;
    }
    keys.push_back(ToBlock(request.keys[i]));
    std::vector<oc::block> row;
    for (std::size_t j = 0; j < request.value_length_blocks; ++j) row.push_back(ToBlock(request.values[i][j]));
    values.push_back(std::move(row));
  }
  constexpr std::uint64_t kStep = 0x9e3779b97f4a7c15ULL;
  for (std::size_t attempt = 0; attempt < 12; ++attempt) {
    common::ByteBlock seed{};
    WriteU64(seed.data(), common::config::stage1::kRbokvsSeedLo + attempt * kStep);
    WriteU64(seed.data() + 8, common::config::stage1::kRbokvsSeedHi ^ ((attempt + 1) * kStep));
    RBOKVS table;
    const auto params = table.getParams(keys.size(), common::config::stage1::kRbokvsEpsilon,
                                        common::config::stage1::kRbokvsStatSecParam, ToBlock(seed));
    table.init(params);
    std::vector<std::vector<oc::block>> encoded(
        params.numCols(), std::vector<oc::block>(request.value_length_blocks, oc::ZeroBlock));
    if (table.encode(keys, values, request.value_length_blocks, encoded) != oc::EncodeStatus::SUCCESS) continue;
    response.codewords.reserve(encoded.size() + 1);
    response.codewords.push_back(EncodeMetadata(
        Metadata{keys.size(), encoded.size(), request.value_length_blocks, seed}));
    for (const auto& encoded_row : encoded) {
      std::vector<common::ByteBlock> row;
      for (const auto& block : encoded_row) row.push_back(FromBlock(block));
      response.codewords.push_back(std::move(row));
    }
    response.ok = true;
    response.backend_used = BackendMode::Rbokvs;
    response.message = "RB-OKVS encoding completed";
    return response;
  }
  response.message = "RB-OKVS encoding failed after 12 seeds";
  return response;
}
RbokvsAdapter::DecodeResponse RbokvsAdapter::DecodeDetailed(
    const std::vector<std::vector<common::ByteBlock>>& codewords,
    const common::ByteBlock& key, std::size_t value_length_blocks) const {
  DecodeResponse response;
  Metadata meta;
  if (codewords.empty() || !DecodeMetadata(codewords.front(), &meta) ||
      meta.value_blocks != value_length_blocks || codewords.size() < meta.columns + 1) {
    response.message = "Invalid RB-OKVS table";
    return response;
  }
  auto& context = GetDecodeContext(codewords, meta);
  RBOKVS& table = *context.decoder;
  const oc::block encoded_key = ToBlock(key);
  const std::size_t start = static_cast<std::size_t>(table.hashPos(encoded_key));
  const std::size_t width = static_cast<std::size_t>(table.mW);
  table.hashBand(encoded_key, context.band.data());
  const auto* words = reinterpret_cast<const std::uint64_t*>(context.band.data());
  response.value_blocks.assign(value_length_blocks, common::ByteBlock{});
  for (std::size_t offset = 0; offset < width; ++offset) {
    if (((words[offset / 64U] >> (63U - offset % 64U)) & 1ULL) == 0) continue;
    const std::size_t index = 1 + start + offset;
    if (index >= codewords.size() || codewords[index].size() < value_length_blocks) {
      response.message = "RB-OKVS decode exceeded the table";
      return response;
    }
    for (std::size_t block = 0; block < value_length_blocks; ++block)
      for (std::size_t byte = 0; byte < response.value_blocks[block].size(); ++byte)
        response.value_blocks[block][byte] ^= codewords[index][block][byte];
  }
  response.hit = HasZeroPadding(response.value_blocks);
  response.backend_used = BackendMode::Rbokvs;
  response.message = response.hit ? "RB-OKVS decode accepted" : "RB-OKVS decode rejected";
  return response;
}
std::vector<common::ByteBlock> RbokvsAdapter::Decode(
    const std::vector<std::vector<common::ByteBlock>>& codewords,
    const common::ByteBlock& key, std::size_t value_length_blocks) const {
  return DecodeDetailed(codewords, key, value_length_blocks).value_blocks;
}
std::uint64_t RbokvsAdapter::SerializedTableSizeBytes(
    const std::vector<std::vector<common::ByteBlock>>& codewords) {
  std::uint64_t bytes = sizeof(std::uint64_t);
  for (const auto& row : codewords) bytes += sizeof(std::uint64_t) + row.size() * sizeof(common::ByteBlock);
  return bytes;
}
}  // namespace ctfpsi::adapters

