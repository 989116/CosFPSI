#include "stage1/stage1_index_builder.hpp"

#include <algorithm>
#include <atomic>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "common/config.hpp"
#include <openssl/rand.h>
#include <openssl/sha.h>

namespace ctfpsi::stage1 {
namespace {

using BuildClock = std::chrono::steady_clock;

double BuildMsSince(const BuildClock::time_point& start) {
  return std::chrono::duration<double, std::milli>(
             BuildClock::now() - start)
      .count();
}

common::ByteBlock ZeroBlock() {
  return common::ByteBlock{};
}

bool GenerateRandomBlock(common::ByteBlock* out) {
  return out != nullptr &&
         RAND_priv_bytes(out->data(), static_cast<int>(out->size())) == 1;
}

bool SecureRandomBelow(std::uint64_t bound, std::uint64_t* out) {
  if (bound == 0 || out == nullptr) {
    return false;
  }
  const std::uint64_t threshold = (0ULL - bound) % bound;
  std::uint64_t sample = 0;
  do {
    if (RAND_priv_bytes(reinterpret_cast<unsigned char*>(&sample),
                        static_cast<int>(sizeof(sample))) != 1) {
      return false;
    }
  } while (sample < threshold);
  *out = sample % bound;
  return true;
}

template <typename T>
bool SecureShuffle(std::vector<T>* values) {
  if (values == nullptr) {
    return false;
  }
  for (std::size_t i = values->size(); i > 1; --i) {
    std::uint64_t selected = 0;
    if (!SecureRandomBelow(static_cast<std::uint64_t>(i), &selected)) {
      return false;
    }
    std::swap((*values)[i - 1], (*values)[static_cast<std::size_t>(selected)]);
  }
  return true;
}

void WriteU32(common::ByteBlock* block, std::size_t offset, std::uint32_t value) {
  if (block == nullptr || offset + 4 > block->size()) {
    return;
  }
  (*block)[offset + 0] = static_cast<std::uint8_t>(value & 0xffU);
  (*block)[offset + 1] = static_cast<std::uint8_t>((value >> 8U) & 0xffU);
  (*block)[offset + 2] = static_cast<std::uint8_t>((value >> 16U) & 0xffU);
  (*block)[offset + 3] = static_cast<std::uint8_t>((value >> 24U) & 0xffU);
}

std::uint32_t ReadU32(const common::ByteBlock& block, std::size_t offset) {
  if (offset + 4 > block.size()) {
    return 0;
  }
  return static_cast<std::uint32_t>(block[offset + 0]) |
         (static_cast<std::uint32_t>(block[offset + 1]) << 8U) |
         (static_cast<std::uint32_t>(block[offset + 2]) << 16U) |
         (static_cast<std::uint32_t>(block[offset + 3]) << 24U);
}

common::BinaryFingerprint PrefixBlockDomain(const common::BinaryFingerprint& block_bits,
                                            std::size_t block_index,
                                            std::size_t fingerprint_bits) {
  common::BinaryFingerprint input;
  input.reserve(64 + block_bits.size());
  for (std::size_t bit = 0; bit < 32; ++bit) {
    input.push_back(((static_cast<std::uint32_t>(block_index) >> bit) & 1U) != 0);
  }
  for (std::size_t bit = 0; bit < 32; ++bit) {
    input.push_back(((static_cast<std::uint32_t>(fingerprint_bits) >> bit) & 1U) != 0);
  }
  input.insert(input.end(), block_bits.begin(), block_bits.end());
  return input;
}

common::BinaryFingerprint BuildBlockOprfInput(const common::BinaryFingerprint& fingerprint,
                                              std::size_t block_index,
                                              std::size_t num_blocks) {
  const std::size_t safe_blocks = std::max<std::size_t>(1, num_blocks);
  const std::size_t block_size = (fingerprint.size() + safe_blocks - 1) / safe_blocks;
  const std::size_t begin = std::min(fingerprint.size(), block_index * block_size);
  const std::size_t end = std::min(fingerprint.size(), begin + block_size);
  common::BinaryFingerprint block(fingerprint.begin() + static_cast<std::ptrdiff_t>(begin),
                                  fingerprint.begin() + static_cast<std::ptrdiff_t>(end));
  return PrefixBlockDomain(block, block_index, fingerprint.size());
}

void EnumerateNeighbors(const common::BinaryFingerprint& current,
                        std::size_t next_bit,
                        std::size_t flips_left,
                        std::unordered_set<std::string>* seen,
                        std::vector<common::BinaryFingerprint>* out) {
  std::string key;
  key.reserve(current.size());
  for (bool bit : current) {
    key.push_back(bit ? '1' : '0');
  }
  if (seen->insert(key).second) {
    out->push_back(current);
  }
  if (flips_left == 0) {
    return;
  }
  for (std::size_t bit = next_bit; bit < current.size(); ++bit) {
    auto next = current;
    next[bit] = !next[bit];
    EnumerateNeighbors(next, bit + 1, flips_left - 1, seen, out);
  }
}

struct BlockProbeInput {
  common::BinaryFingerprint oprf_input;
  std::size_t hamming_distance = 0;
};

std::vector<BlockProbeInput> EnumerateBlockProbeInputs(
    const common::BinaryFingerprint& fingerprint,
    std::size_t block_index,
    std::size_t num_blocks,
    std::size_t radius) {
  const std::size_t safe_blocks = std::max<std::size_t>(1, num_blocks);
  const std::size_t block_size = (fingerprint.size() + safe_blocks - 1) / safe_blocks;
  const std::size_t begin = std::min(fingerprint.size(), block_index * block_size);
  const std::size_t end = std::min(fingerprint.size(), begin + block_size);
  common::BinaryFingerprint block(fingerprint.begin() + static_cast<std::ptrdiff_t>(begin),
                                  fingerprint.begin() + static_cast<std::ptrdiff_t>(end));

  std::vector<common::BinaryFingerprint> neighbors;
  std::unordered_set<std::string> seen;
  EnumerateNeighbors(block, 0, std::min(radius, block.size()), &seen, &neighbors);
  std::vector<BlockProbeInput> probes;
  probes.reserve(neighbors.size());
  for (const auto& neighbor : neighbors) {
    std::size_t distance = 0;
    for (std::size_t bit = 0; bit < block.size(); ++bit) {
      distance += block[bit] != neighbor[bit] ? 1U : 0U;
    }
    probes.push_back(BlockProbeInput{
        PrefixBlockDomain(neighbor, block_index, fingerprint.size()),
        distance});
  }
  return probes;
}

std::string ByteBlockKey(const common::ByteBlock& block) {
  return std::string(reinterpret_cast<const char*>(block.data()), block.size());
}

struct ByteBlockHash {
  std::size_t operator()(const common::ByteBlock& block) const noexcept {
    std::size_t hash = 1469598103934665603ULL;
    for (const std::uint8_t byte : block) {
      hash ^= byte;
      hash *= 1099511628211ULL;
    }
    return hash;
  }
};

bool IsZeroBlock(const common::ByteBlock& block) {
  return std::all_of(block.begin(), block.end(),
                     [](std::uint8_t value) { return value == 0; });
}

common::BinaryFingerprint BuildOpeningOprfInput(
    const common::ByteBlock& opaque_handle) {
  static constexpr char kDomain[] = "TPCR_OPENING_OPRF_V1";
  common::BinaryFingerprint bits;
  bits.reserve((sizeof(kDomain) - 1 + opaque_handle.size()) * 8);
  auto append_byte = [&](std::uint8_t value) {
    for (std::size_t bit = 0; bit < 8; ++bit) {
      bits.push_back(((value >> bit) & 1U) != 0);
    }
  };
  for (std::size_t i = 0; i + 1 < sizeof(kDomain); ++i) {
    append_byte(static_cast<std::uint8_t>(kDomain[i]));
  }
  for (const auto value : opaque_handle) {
    append_byte(value);
  }
  return bits;
}

common::ByteBlock ComputeTpcrLookupTag(
    const common::ByteBlock& probe_oprf_key,
    const common::ByteBlock& opaque_handle) {
  static constexpr char kDomain[] = "TPCR_PREFILTER_TAG_V1";
  SHA256_CTX context;
  SHA256_Init(&context);
  SHA256_Update(&context, kDomain, sizeof(kDomain) - 1);
  SHA256_Update(&context, probe_oprf_key.data(), probe_oprf_key.size());
  SHA256_Update(&context, opaque_handle.data(), opaque_handle.size());
  std::array<std::uint8_t, SHA256_DIGEST_LENGTH> digest{};
  SHA256_Final(digest.data(), &context);
  common::ByteBlock tag{};
  std::copy_n(digest.begin(), tag.size(), tag.begin());
  return tag;
}

constexpr std::uint32_t kTpcrPayloadCollectionMagic = 0x31504354U;

void AppendWireU32(std::vector<std::uint8_t>* out, std::uint32_t value) {
  for (std::size_t byte = 0; byte < 4; ++byte) {
    out->push_back(static_cast<std::uint8_t>((value >> (8 * byte)) & 0xffU));
  }
}

void AppendWireU64(std::vector<std::uint8_t>* out, std::uint64_t value) {
  for (std::size_t byte = 0; byte < 8; ++byte) {
    out->push_back(static_cast<std::uint8_t>((value >> (8 * byte)) & 0xffU));
  }
}

bool ReadWireU32(const std::vector<std::uint8_t>& in,
                 std::size_t* offset,
                 std::uint32_t* value) {
  if (offset == nullptr || value == nullptr || *offset + 4 > in.size()) {
    return false;
  }
  *value = 0;
  for (std::size_t byte = 0; byte < 4; ++byte) {
    *value |= static_cast<std::uint32_t>(in[*offset + byte]) << (8 * byte);
  }
  *offset += 4;
  return true;
}

bool ReadWireU64(const std::vector<std::uint8_t>& in,
                 std::size_t* offset,
                 std::uint64_t* value) {
  if (offset == nullptr || value == nullptr || *offset + 8 > in.size()) {
    return false;
  }
  *value = 0;
  for (std::size_t byte = 0; byte < 8; ++byte) {
    *value |= static_cast<std::uint64_t>(in[*offset + byte]) << (8 * byte);
  }
  *offset += 8;
  return true;
}

bool SerializeOpaquePayloadCollection(
    const std::vector<common::ByteBlock>& ordered_handles,
    const std::unordered_map<std::string, OpaqueEncryptedCandidatePayload>&
        dictionary,
    std::vector<std::uint8_t>* out,
    std::string* error) {
  if (out == nullptr) {
    if (error != nullptr) {
      *error = "null TPCR payload collection output";
    }
    return false;
  }
  out->clear();
  AppendWireU32(out, kTpcrPayloadCollectionMagic);
  AppendWireU32(out, 1U);
  AppendWireU64(out, ordered_handles.size());
  for (const auto& handle : ordered_handles) {
    const auto it = dictionary.find(ByteBlockKey(handle));
    if (it == dictionary.end()) {
      if (error != nullptr) {
        *error = "TPCR payload collection is missing an opaque handle";
      }
      return false;
    }
    const auto& envelope = it->second;
    out->insert(out->end(), handle.begin(), handle.end());
    AppendWireU32(out, envelope.envelope_version);
    out->insert(out->end(), envelope.iv.begin(), envelope.iv.end());
    out->insert(out->end(), envelope.auth_tag.begin(),
                envelope.auth_tag.end());
    AppendWireU64(out, envelope.ciphertext.size());
    out->insert(out->end(), envelope.ciphertext.begin(),
                envelope.ciphertext.end());
  }
  return true;
}

bool DeserializeOpaquePayloadCollection(
    const std::vector<std::uint8_t>& bytes,
    std::unordered_map<std::string, OpaqueEncryptedCandidatePayload>*
        dictionary,
    std::string* error) {
  if (dictionary == nullptr) {
    if (error != nullptr) {
      *error = "null TPCR payload collection dictionary";
    }
    return false;
  }
  dictionary->clear();
  std::size_t offset = 0;
  std::uint32_t magic = 0;
  std::uint32_t version = 0;
  std::uint64_t count = 0;
  if (!ReadWireU32(bytes, &offset, &magic) ||
      !ReadWireU32(bytes, &offset, &version) ||
      !ReadWireU64(bytes, &offset, &count) ||
      magic != kTpcrPayloadCollectionMagic || version != 1U ||
      count > static_cast<std::uint64_t>(bytes.size())) {
    if (error != nullptr) {
      *error = "invalid TPCR payload collection header";
    }
    return false;
  }
  for (std::uint64_t entry = 0; entry < count; ++entry) {
    constexpr std::size_t kFixedEntryBytes = 16 + 4 + 12 + 16 + 8;
    if (offset + kFixedEntryBytes > bytes.size()) {
      if (error != nullptr) {
        *error = "truncated TPCR payload collection entry";
      }
      return false;
    }
    common::ByteBlock handle{};
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                handle.size(), handle.begin());
    offset += handle.size();
    OpaqueEncryptedCandidatePayload envelope;
    if (!ReadWireU32(bytes, &offset, &envelope.envelope_version)) {
      return false;
    }
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                envelope.iv.size(), envelope.iv.begin());
    offset += envelope.iv.size();
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                envelope.auth_tag.size(), envelope.auth_tag.begin());
    offset += envelope.auth_tag.size();
    std::uint64_t ciphertext_size = 0;
    if (!ReadWireU64(bytes, &offset, &ciphertext_size) ||
        ciphertext_size > bytes.size() - offset) {
      if (error != nullptr) {
        *error = "invalid TPCR payload ciphertext length";
      }
      return false;
    }
    envelope.ciphertext.assign(
        bytes.begin() + static_cast<std::ptrdiff_t>(offset),
        bytes.begin() + static_cast<std::ptrdiff_t>(
                            offset + static_cast<std::size_t>(ciphertext_size)));
    offset += static_cast<std::size_t>(ciphertext_size);
    if (!dictionary->emplace(ByteBlockKey(handle), std::move(envelope)).second) {
      if (error != nullptr) {
        *error = "duplicate opaque handle in TPCR payload collection";
      }
      return false;
    }
  }
  if (offset != bytes.size()) {
    if (error != nullptr) {
      *error = "trailing bytes in TPCR payload collection";
    }
    return false;
  }
  return true;
}

bool BlocksEqual(const common::ByteBlock& lhs, const common::ByteBlock& rhs) {
  return std::equal(lhs.begin(), lhs.end(), rhs.begin());
}

}  // namespace

Stage1IndexBuilder::Stage1IndexBuilder(adapters::RbokvsAdapter* rbokvs_adapter,
                                       std::unique_ptr<OprfProvider> oprf_provider,
                                       Stage1BuildOptions options)
    : rbokvs_adapter_(rbokvs_adapter),
      oprf_provider_(std::move(oprf_provider)),
      options_(options) {
  if (rbokvs_adapter_ == nullptr) {
    throw std::invalid_argument("Stage1IndexBuilder requires non-null RbokvsAdapter.");
  }
  if (oprf_provider_ == nullptr) {
    throw std::invalid_argument("Stage1IndexBuilder requires non-null OprfProvider.");
  }
  opening_oprf_provider_ = std::make_unique<EcOprfProvider>();

  payload_codec_config_.zero_padding_bytes = common::config::stage1::kPayloadZeroPaddingBytes;
  payload_codec_config_.payload_version = common::config::stage1::kPayloadVersion;

  if (options_.rbokvs_value_length_blocks == 0) {
    options_.rbokvs_value_length_blocks = common::config::stage1::kRbokvsValueLengthBlocks;
  }
  if (options_.num_blocks == 0) {
    options_.num_blocks = common::config::stage1::kNumBlocks;
  }
  if (options_.cosine_threshold < -1.0 || options_.cosine_threshold > 1.0) {
    options_.cosine_threshold = common::config::stage1::kCosineThreshold;
  }
  if (options_.hamming_sigma_margin < 0.0) {
    options_.hamming_sigma_margin = common::config::stage1::kHammingSigmaMargin;
  }
  if (options_.c0_cap == 0) {
    options_.c0_cap = common::config::kCandidateCapC0;
  }
}

bool Stage1IndexBuilder::Build(
    const std::vector<common::BinaryFingerprint>& dataset_bits,
    const common::DenseMatrix& dataset_vectors,
    const CandidateBfvPackRefs& candidate_pack_refs,
    std::string* error) {
  ready_ = false;
  records_.clear();
  opaque_payload_dictionary_.clear();
  opaque_payload_wire_message_.clear();
  opaque_handles_.clear();
  opening_server_outputs_.clear();
  opaque_handle_generation_ms_ = 0.0;
  opaque_handle_collision_count_ = 0;
  opaque_handle_consistency_verified_ = false;
  rbokvs_codewords_.clear();
  max_bucket_occupancy_ = 0;
  rbokvs_encoded_entry_count_ = 0;
  rbokvs_serialized_table_bytes_ = 0;
  rbokvs_backend_used_ =
      adapters::RbokvsAdapter::BackendMode::Unavailable;
  threshold_params_ = Stage1ThresholdParameters{};

  if (dataset_bits.empty()) {
    if (error != nullptr) {
      *error = "Stage1 dataset_bits is empty.";
    }
    return false;
  }
  if (dataset_bits.size() != dataset_vectors.size()) {
    if (error != nullptr) {
      *error = "Stage1 dataset_bits size must equal dataset_vectors size.";
    }
    return false;
  }
  if (candidate_pack_refs.size() != dataset_bits.size()) {
    if (error != nullptr) {
      *error = "Stage1 BFV pack reference count must equal dataset size.";
    }
    return false;
  }
  const std::size_t bit_dim = dataset_bits.front().size();
  if (bit_dim == 0) {
    if (error != nullptr) {
      *error = "Stage1 fingerprint dimension must be > 0.";
    }
    return false;
  }
  for (const auto& bits : dataset_bits) {
    if (bits.size() != bit_dim) {
      if (error != nullptr) {
        *error = "All Stage1 fingerprints must have equal bit dimension.";
      }
      return false;
    }
  }

  const std::size_t vector_dim = dataset_vectors.front().size();
  for (const auto& row : dataset_vectors) {
    if (row.size() != vector_dim) {
      if (error != nullptr) {
        *error = "All Stage1 candidate vectors must have equal dimension.";
      }
      return false;
    }
  }

  Stage1ThresholdParameterInput tp_in;
  tp_in.cosine_threshold = options_.cosine_threshold;
  tp_in.simhash_bits = bit_dim;
  tp_in.num_blocks = options_.num_blocks;
  tp_in.hamming_sigma_margin = options_.hamming_sigma_margin;
  tp_in.target_recall = options_.target_recall;
  tp_in.min_block_radius = options_.min_block_radius;
  tp_in.max_block_radius = options_.max_block_radius;

  threshold_params_ = DeriveStage1ThresholdParameters(tp_in);
  if (!threshold_params_.ok) {
    if (error != nullptr) {
      *error = "Stage1 threshold parameterization failed: " + threshold_params_.error;
    }
    return false;
  }

  records_.resize(dataset_bits.size());

  if (opening_oprf_provider_ == nullptr) {
      if (error != nullptr) {
        *error = "TPCR opening OPRF session is unavailable.";
      }
      return false;
  }
    const auto handle_begin = BuildClock::now();
    std::unordered_set<std::string> seen_handles;
    opaque_handles_.reserve(dataset_bits.size());
    std::vector<common::BinaryFingerprint> opening_inputs;
    opening_inputs.reserve(dataset_bits.size());
    while (opaque_handles_.size() < dataset_bits.size()) {
      common::ByteBlock handle{};
      if (!GenerateRandomBlock(&handle)) {
        if (error != nullptr) {
          *error = "TPCR opaque handle generation failed.";
        }
        return false;
      }
      if (IsZeroBlock(handle) ||
          !seen_handles.insert(ByteBlockKey(handle)).second) {
        ++opaque_handle_collision_count_;
        continue;
      }
      opening_inputs.push_back(BuildOpeningOprfInput(handle));
      opaque_handles_.push_back(handle);
    }
    opaque_handle_generation_ms_ = BuildMsSince(handle_begin);
    std::string opening_error;
    if (!opening_oprf_provider_->EvaluateServerBatch(
            opening_inputs, &opening_server_outputs_, &opening_error) ||
        opening_server_outputs_.size() != opaque_handles_.size()) {
      if (error != nullptr) {
        *error = "TPCR opening OPRF preprocessing failed: " + opening_error;
      }
      return false;
    }
  opaque_handle_consistency_verified_ =
      opaque_handles_.size() == dataset_bits.size();

  adapters::RbokvsAdapter::EncodeRequest req;
  req.value_length_blocks = options_.rbokvs_value_length_blocks;
  req.keys.reserve(dataset_bits.size() * threshold_params_.num_blocks);
  req.values.reserve(dataset_bits.size() * threshold_params_.num_blocks);

  struct PendingEntry {
    common::ByteBlock opaque_handle{};
    common::ByteBlock oprf_key{};
  };
  std::unordered_map<std::string, std::vector<PendingEntry>> buckets;
  std::unordered_map<std::string, std::size_t> block_input_index;
  std::vector<common::BinaryFingerprint> unique_block_inputs;
  std::vector<std::size_t> candidate_block_indices(
      dataset_bits.size() * threshold_params_.num_blocks, 0);
  for (std::size_t i = 0; i < dataset_bits.size(); ++i) {
    for (std::size_t block = 0;
         block < threshold_params_.num_blocks;
         ++block) {
      auto block_input = BuildBlockOprfInput(
          dataset_bits[i], block, threshold_params_.num_blocks);
      std::string block_input_key;
      block_input_key.reserve(block_input.size());
      for (const bool bit : block_input) {
        block_input_key.push_back(bit ? '\x01' : '\x00');
      }
      const auto [it, inserted] = block_input_index.try_emplace(
          std::move(block_input_key), unique_block_inputs.size());
      if (inserted) {
        unique_block_inputs.push_back(std::move(block_input));
      }
      candidate_block_indices[
          i * threshold_params_.num_blocks + block] = it->second;
    }
  }

  std::vector<common::ByteBlock> block_oprf_keys;
  std::string block_oprf_error;
  if (!oprf_provider_->EvaluateServerBatch(
          unique_block_inputs, &block_oprf_keys, &block_oprf_error) ||
      block_oprf_keys.size() != unique_block_inputs.size()) {
    if (error != nullptr) {
      *error = "Stage1 block OPRF batch failed: " + block_oprf_error;
    }
    return false;
  }

  const auto t_records = BuildClock::now();
  double payload_encrypt_ms = 0.0;
  double block_bucket_ms = 0.0;
  for (std::size_t i = 0; i < dataset_bits.size(); ++i) {
    const common::CandidateId cid = static_cast<common::CandidateId>(i);
    const Aes256Key tpcr_opening_key =
        DeriveTpcrOpeningKey(opening_server_outputs_[i]);

    CandidatePayload payload;
    payload.candidate_id = cid;
    payload.bfv_pack_ref = candidate_pack_refs[i];
    payload.metadata_flags = 0;

    const auto t_payload_encrypt = BuildClock::now();
    CandidateRecord record;
    record.fingerprint = dataset_bits[i];
    record.opaque_handle = opaque_handles_[i];
    auto opaque_payload = EncryptPayloadWithOpaqueHandle(
        payload, tpcr_opening_key, record.opaque_handle,
        payload_codec_config_);
    if (opaque_payload.ciphertext.empty()) {
      if (error != nullptr) {
        *error = "TPCR opaque payload encryption failed.";
      }
      return false;
    }
    opaque_payload_dictionary_.emplace(
        ByteBlockKey(record.opaque_handle), std::move(opaque_payload));
    payload_encrypt_ms += BuildMsSince(t_payload_encrypt);
    records_[i] = std::move(record);

    const auto t_block_bucket = BuildClock::now();
    for (std::size_t block = 0; block < threshold_params_.num_blocks; ++block) {
      const std::size_t block_key_index =
          candidate_block_indices[
              i * threshold_params_.num_blocks + block];
      const common::ByteBlock& block_oprf_key =
          block_oprf_keys[block_key_index];
      const std::string bucket_key(reinterpret_cast<const char*>(block_oprf_key.data()),
                                   block_oprf_key.size());
      buckets[bucket_key].push_back(
          PendingEntry{opaque_handles_[i], block_oprf_key});
    }
    block_bucket_ms += BuildMsSince(t_block_bucket);
    if (options_.verbose && (i + 1) % 256 == 0) {
      std::cout << "[Stage1-Build] records_progress=" << (i + 1)
                << "/" << dataset_bits.size()
                << " total_ms=" << BuildMsSince(t_records)
                << " payload_encrypt_ms=" << payload_encrypt_ms
                << " block_bucket_ms=" << block_bucket_ms
                << " block_cache=" << block_oprf_keys.size()
                << "\n"
                << std::flush;
    }
  }
  std::string payload_wire_error;
    if (!SerializeOpaquePayloadCollection(
            opaque_handles_, opaque_payload_dictionary_,
            &opaque_payload_wire_message_, &payload_wire_error)) {
      if (error != nullptr) {
        *error = "TPCR payload serialization failed: " + payload_wire_error;
      }
      return false;
    }
    std::unordered_map<std::string, OpaqueEncryptedCandidatePayload>
        received_payload_dictionary;
    if (!DeserializeOpaquePayloadCollection(
            opaque_payload_wire_message_, &received_payload_dictionary,
            &payload_wire_error)) {
      if (error != nullptr) {
        *error = "TPCR payload deserialization failed: " + payload_wire_error;
      }
      return false;
    }
    opaque_payload_dictionary_ = std::move(received_payload_dictionary);

    std::size_t audited_entries = 0;
    bool all_entries_consistent =
        opaque_handles_.size() == dataset_bits.size();
    for (const auto& [bucket_key, entries] : buckets) {
      (void)bucket_key;
      for (const auto& entry : entries) {
        ++audited_entries;
        if (IsZeroBlock(entry.opaque_handle) ||
            opaque_payload_dictionary_.find(ByteBlockKey(entry.opaque_handle)) ==
                opaque_payload_dictionary_.end()) {
          all_entries_consistent = false;
        }
      }
    }
  opaque_handle_consistency_verified_ =
      all_entries_consistent &&
      audited_entries == dataset_bits.size() * threshold_params_.num_blocks;
  if (options_.verbose) {
    std::cout << "[Stage1-Build] records_oprf_aes_bucket_ms="
              << BuildMsSince(t_records)
              << " buckets=" << buckets.size()
              << " block_oprf_cache=" << block_oprf_keys.size()
              << "\n"
              << std::flush;
  }

  if (options_.rbokvs_value_length_blocks < 4) {
    if (error != nullptr) {
      *error = "Stage1 private lookup requires at least four RBOKVS value blocks.";
    }
    return false;
  }

  const auto t_materialize = BuildClock::now();
  for (const auto& bucket_item : buckets) {
    const auto& entries = bucket_item.second;
    max_bucket_occupancy_ = std::max(max_bucket_occupancy_, entries.size());
    for (std::size_t slot = 0; slot < entries.size(); ++slot) {
      const auto& entry = entries[slot];
      req.keys.push_back(DeriveRbokvsKeyFromOprfKey(entry.oprf_key, slot));

      std::vector<common::ByteBlock> value_blocks(options_.rbokvs_value_length_blocks,
                                                  ZeroBlock());
      value_blocks[0] = entry.opaque_handle;
      WriteU32(&value_blocks[1], 0, 1U);
      value_blocks[2] =
          ComputeTpcrLookupTag(entry.oprf_key, entry.opaque_handle);
      req.values.push_back(std::move(value_blocks));
    }
  }
  if (options_.verbose) {
    std::cout << "[Stage1-Build] materialize_nm_keys_ms="
              << BuildMsSince(t_materialize)
              << " entries=" << req.keys.size()
              << " max_bucket=" << max_bucket_occupancy_
              << "\n"
              << std::flush;
  }

  const auto t_encode = BuildClock::now();
  const auto enc = rbokvs_adapter_->Encode(req);
  if (options_.verbose) {
    std::cout << "[Stage1-Build] rbokvs_encode_ms="
              << BuildMsSince(t_encode)
              << " actual="
              << adapters::RbokvsAdapter::BackendModeToString(
                     enc.backend_used)
              << " backend_error="
              << (enc.backend_error.empty() ? "<empty>"
                                              : enc.backend_error)
              << "\n"
              << std::flush;
  }
  if (!enc.ok) {
    if (error != nullptr) {
      *error = "RBOKVS encode failed: " + enc.message;
    }
    return false;
  }

  rbokvs_codewords_ = enc.codewords;
  rbokvs_backend_used_ = enc.backend_used;
  rbokvs_encoded_entry_count_ = req.keys.size();
  rbokvs_serialized_table_bytes_ =
      adapters::RbokvsAdapter::SerializedTableSizeBytes(
          rbokvs_codewords_);
  ready_ = true;
  if (error != nullptr) {
    error->clear();
  }
  return true;
}

Stage1BatchQueryResult Stage1IndexBuilder::QueryBatchAndRecover(
    const std::vector<QueryBundle>& query_bundles) const {
  const auto total_begin = std::chrono::steady_clock::now();
  Stage1BatchQueryResult out;
  out.query_count = query_bundles.size();
  out.cross_query_probe_dedup_used = false;
  out.oprf_implementation =
      OprfImplementationToString(oprf_provider_->Implementation());
  out.cosine_threshold = threshold_params_.cosine_threshold;
  out.simhash_bits = threshold_params_.simhash_bits;
  out.num_blocks = threshold_params_.num_blocks;
  out.hamming_threshold = threshold_params_.hamming_threshold;
  out.block_radius = threshold_params_.block_radius;
  out.target_recall = threshold_params_.target_recall;
  out.estimated_recall_at_threshold =
      threshold_params_.estimated_recall_at_threshold;
  out.threshold_policy = threshold_params_.recall_policy;
  out.rbokvs_serialized_table_bytes = rbokvs_serialized_table_bytes_;
  out.candidate_statistics_collected =
      options_.collect_candidate_statistics ||
      options_.disable_threshold_pruning;
  out.threshold_pruning_enabled = !options_.disable_threshold_pruning;
  out.tpcr_opaque_opening_used = true;
  out.opaque_handle_count = opaque_handles_.size();
  out.opaque_handle_collision_count = opaque_handle_collision_count_;
  out.opaque_handle_consistency_verified =
      opaque_handle_consistency_verified_;
  out.prefilter_contains_candidate_id = false;
  out.prefilter_contains_opening_key = false;
  out.prefilter_contains_pack_location = false;
  out.opaque_handle_generation_ms = opaque_handle_generation_ms_;

  if (!ready_) {
    out.error_message = "Stage1 index not ready.";
    return out;
  }

  struct TaggedProbe {
    common::QueryId query_id = common::kInvalidQueryId;
    std::size_t block = 0;
    BlockProbeInput probe;
  };
  std::vector<TaggedProbe> all_probes;
  for (std::size_t query = 0; query < query_bundles.size(); ++query) {
    if (query_bundles[query].simhash_bits.size() !=
        threshold_params_.simhash_bits) {
      out.error_message =
          "Stage1 batch query fingerprint length mismatch.";
      return out;
    }
    for (std::size_t block = 0;
         block < threshold_params_.num_blocks;
         ++block) {
      auto probes = EnumerateBlockProbeInputs(
          query_bundles[query].simhash_bits,
          block,
          threshold_params_.num_blocks,
          threshold_params_.block_radius);
      for (auto& probe : probes) {
        all_probes.push_back(TaggedProbe{
            static_cast<common::QueryId>(query),
            block,
            std::move(probe)});
      }
    }
  }
  out.probe_count = all_probes.size();

  // The first version intentionally does not deduplicate across queries.
  // Independent OPRF blinding is retained while one session processes the
  // globally shuffled probe stream.
  if (!SecureShuffle(&all_probes)) {
    out.error_message = "Stage1 secure probe permutation failed.";
    return out;
  }

  constexpr std::size_t kMissingDistance =
      std::numeric_limits<std::size_t>::max();
  struct RecoveredEvidence {
    common::ByteBlock opaque_handle{};
    std::vector<std::size_t> block_distances;
  };
  std::vector<std::unordered_map<common::ByteBlock,
                                 RecoveredEvidence,
                                 ByteBlockHash>>
      evidence_by_query(query_bundles.size());

  const OprfSessionStats oprf_stats_before =
      oprf_provider_->SessionStats();
  constexpr std::size_t kOprfBatchPointLimit = 16384;
  for (std::size_t batch_begin = 0;
       batch_begin < all_probes.size();
       batch_begin += kOprfBatchPointLimit) {
    const std::size_t batch_end =
        std::min(all_probes.size(), batch_begin + kOprfBatchPointLimit);
    std::vector<common::BinaryFingerprint> batch_inputs;
    batch_inputs.reserve(batch_end - batch_begin);
    std::unordered_set<common::QueryId> query_ids;
    for (std::size_t i = batch_begin; i < batch_end; ++i) {
      batch_inputs.push_back(std::move(all_probes[i].probe.oprf_input));
      query_ids.insert(all_probes[i].query_id);
    }

    std::vector<common::ByteBlock> batch_keys;
    std::string oprf_error;
    const auto oprf_begin = std::chrono::steady_clock::now();
    if (!oprf_provider_->EvaluateClientBatch(
            batch_inputs, &batch_keys, &oprf_error) ||
        batch_keys.size() != batch_inputs.size()) {
      out.error_message =
          "Stage1 batched OPRF evaluation failed: " + oprf_error;
      return out;
    }
    out.oprf_evaluate_ms +=
        std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - oprf_begin)
            .count();

    Stage1BatchQueryResult::OprfBatchTrace trace;
    trace.batch_id = out.oprf_batches.size();
    trace.probe_count = batch_inputs.size();
    trace.distinct_query_ids.assign(
        query_ids.begin(), query_ids.end());
    std::sort(
        trace.distinct_query_ids.begin(),
        trace.distinct_query_ids.end());
    out.oprf_batches.push_back(std::move(trace));

    struct DecodedProbeHit {
      common::ByteBlock opaque_handle{};
    };
    std::vector<std::vector<DecodedProbeHit>> decoded_hits(
        batch_keys.size());
    std::vector<adapters::RbokvsAdapter::BackendMode> decoded_backends(
        batch_keys.size(),
        adapters::RbokvsAdapter::BackendMode::Unavailable);

    std::atomic<std::size_t> next_probe{0};
    const std::size_t hardware_threads =
        std::max<std::size_t>(1, std::thread::hardware_concurrency());
    const bool parallel_decode =
        rbokvs_backend_used_ == adapters::RbokvsAdapter::BackendMode::Rbokvs;
    const std::size_t worker_count =
        batch_keys.size() < 8 || !parallel_decode
            ? 1
            : std::min<std::size_t>(
                  {hardware_threads, batch_keys.size(), 16});
    auto decode_worker = [&]() {
      while (true) {
        const std::size_t offset =
            next_probe.fetch_add(1, std::memory_order_relaxed);
        if (offset >= batch_keys.size()) {
          return;
        }
        const common::ByteBlock& query_oprf_key = batch_keys[offset];
        auto& probe_hits = decoded_hits[offset];
        for (std::size_t slot = 0;
             slot < max_bucket_occupancy_;
             ++slot) {
          const common::ByteBlock query_rbokvs_key =
              DeriveRbokvsKeyFromOprfKey(query_oprf_key, slot);
          const auto decoded = rbokvs_adapter_->DecodeDetailed(
              rbokvs_codewords_,
              query_rbokvs_key,
              options_.rbokvs_value_length_blocks);
          decoded_backends[offset] = decoded.backend_used;
          if (!decoded.hit || decoded.value_blocks.size() < 4 ||
              !IsAllZeroPadding(decoded.value_blocks, 3)) {
            continue;
          }

          const common::ByteBlock& opaque_handle = decoded.value_blocks[0];
          if (IsZeroBlock(opaque_handle) ||
              ReadU32(decoded.value_blocks[1], 0) != 1U) {
            continue;
          }
          const common::ByteBlock expected_tag =
              ComputeTpcrLookupTag(query_oprf_key, opaque_handle);
          if (BlocksEqual(decoded.value_blocks[2], expected_tag)) {
            probe_hits.push_back(DecodedProbeHit{
                opaque_handle});
          }
        }
      }
    };

    std::vector<std::thread> workers;
    workers.reserve(worker_count > 0 ? worker_count - 1 : 0);
    for (std::size_t worker = 1; worker < worker_count; ++worker) {
      workers.emplace_back(decode_worker);
    }
    decode_worker();
    for (auto& worker : workers) {
      worker.join();
    }

    for (std::size_t offset = 0; offset < batch_keys.size(); ++offset) {
      const auto& tagged = all_probes[batch_begin + offset];
      out.rbokvs_backend_used =
          adapters::RbokvsAdapter::BackendModeToString(
              decoded_backends[offset]);
      for (const auto& decoded_hit : decoded_hits[offset]) {
        ++out.decode_hit_count;
        auto& query_evidence = evidence_by_query[tagged.query_id];
        const common::ByteBlock evidence_key = decoded_hit.opaque_handle;
        auto [it, inserted] =
            query_evidence.try_emplace(evidence_key);
        if (inserted) {
          it->second.opaque_handle = decoded_hit.opaque_handle;
          it->second.block_distances.assign(
              threshold_params_.num_blocks, kMissingDistance);
        }
        auto& distance =
            it->second.block_distances[tagged.block];
        distance =
            std::min(distance, tagged.probe.hamming_distance);
      }
    }
  }
  const OprfSessionStats oprf_stats_after =
      oprf_provider_->SessionStats();
  out.oprf_session_setup_count =
      oprf_stats_after.session_setup_count;
  out.oprf_server_key_generation_count =
      oprf_stats_after.server_key_generation_count;
  out.oprf_batch_call_count =
      oprf_stats_after.batch_call_count -
      oprf_stats_before.batch_call_count;
  out.oprf_total_point_count =
      oprf_stats_after.total_point_count -
      oprf_stats_before.total_point_count;
  out.oprf_scalar_call_count =
      oprf_stats_after.scalar_call_count -
      oprf_stats_before.scalar_call_count;
  out.probe_oprf_request_bytes =
      oprf_stats_after.blind_request_serialized_bytes -
      oprf_stats_before.blind_request_serialized_bytes;
  out.probe_oprf_response_bytes =
      oprf_stats_after.evaluated_response_serialized_bytes -
      oprf_stats_before.evaluated_response_serialized_bytes;
  out.logical_oprf_session_count =
      out.oprf_session_setup_count;
  out.logical_oprf_batch_count = out.oprf_batches.size();
  out.num_raw_probe_hits = out.decode_hit_count;
  for (const auto& query_evidence : evidence_by_query) {
    out.num_C_hit += query_evidence.size();
  }
  if (out.num_C_hit != 0) {
    out.avg_hits_per_raw_candidate =
        static_cast<double>(out.num_raw_probe_hits) /
        static_cast<double>(out.num_C_hit);
  }

  struct SelectedEvidence {
    common::ByteBlock evidence_key{};
    std::size_t lower_bound = 0;
    CandidatePayload opened_payload;
  };
  std::vector<std::vector<SelectedEvidence>> selected_by_query(
      evidence_by_query.size());
  const std::size_t safe_blocks =
      std::max<std::size_t>(1, threshold_params_.num_blocks);
  const std::size_t block_size =
      (threshold_params_.simhash_bits + safe_blocks - 1) / safe_blocks;

  for (std::size_t query = 0; query < evidence_by_query.size(); ++query) {
    auto& selected = selected_by_query[query];
    for (const auto& [evidence_key, evidence] :
         evidence_by_query[query]) {
      std::size_t lower_bound = 0;
      for (std::size_t block = 0; block < safe_blocks; ++block) {
        const std::size_t begin =
            std::min(threshold_params_.simhash_bits,
                     block * block_size);
        const std::size_t end =
            std::min(threshold_params_.simhash_bits,
                     begin + block_size);
        const std::size_t width = end - begin;
        const std::size_t observed =
            block < evidence.block_distances.size()
                ? evidence.block_distances[block]
                : kMissingDistance;
        lower_bound +=
            observed == kMissingDistance
                ? std::min(threshold_params_.block_radius, width) + 1
                : observed;
      }
      if (options_.disable_threshold_pruning ||
          lower_bound <= threshold_params_.hamming_threshold) {
        selected.push_back(SelectedEvidence{evidence_key, lower_bound, {}});
      }
    }
    if (options_.c0_cap > 0 && selected.size() > options_.c0_cap) {
      out.c0.overflow = true;
      out.c0.overflow_reason =
          "Stage1 candidate count exceeded the configured resource guard; "
          "no candidate was silently truncated.";
    }
  }

  std::vector<common::ByteBlock> unique_handles;
    std::unordered_map<common::ByteBlock, std::size_t, ByteBlockHash>
        unique_handle_indices;
    std::vector<common::BinaryFingerprint> opening_inputs;
  for (std::size_t query = 0; query < selected_by_query.size(); ++query) {
      for (std::size_t index = 0; index < selected_by_query[query].size();
           ++index) {
        ++out.num_surviving_pairs;
        const auto evidence_it = evidence_by_query[query].find(
            selected_by_query[query][index].evidence_key);
        if (evidence_it == evidence_by_query[query].end()) {
          out.error_message = "TPCR selected opaque evidence is unavailable.";
          return out;
        }
        const auto& handle = evidence_it->second.opaque_handle;
        const auto [it, inserted] = unique_handle_indices.try_emplace(
            handle, unique_handles.size());
        if (inserted) {
          unique_handles.push_back(handle);
          opening_inputs.push_back(BuildOpeningOprfInput(handle));
        }
      }
    }
    out.num_unique_surviving_handles = unique_handles.size();
    out.opening_oprf_input_count = opening_inputs.size();
    const OprfSessionStats opening_stats_before =
        opening_oprf_provider_->SessionStats();
    const auto opening_begin = BuildClock::now();
    std::vector<common::ByteBlock> opening_outputs;
    std::string opening_error;
    if (!opening_oprf_provider_->EvaluateClientBatch(
            opening_inputs, &opening_outputs, &opening_error) ||
        opening_outputs.size() != opening_inputs.size()) {
      out.error_message = "TPCR opening OPRF failed: " + opening_error;
      return out;
    }
    out.opening_oprf_ms = BuildMsSince(opening_begin);
    out.opening_oprf_batch_count = opening_inputs.empty() ? 0 : 1;
    out.opening_oprf_point_count = opening_inputs.size();
    const OprfSessionStats opening_stats_after =
        opening_oprf_provider_->SessionStats();
    out.opening_oprf_request_bytes =
        opening_stats_after.blind_request_serialized_bytes -
        opening_stats_before.blind_request_serialized_bytes;
    out.opening_oprf_response_bytes =
        opening_stats_after.evaluated_response_serialized_bytes -
        opening_stats_before.evaluated_response_serialized_bytes;
    out.opening_oprf_bytes = out.opening_oprf_request_bytes +
                             out.opening_oprf_response_bytes;

    std::unordered_map<common::ByteBlock, CandidatePayload, ByteBlockHash>
        opened_cache;
    for (std::size_t handle_index = 0; handle_index < unique_handles.size();
         ++handle_index) {
      const auto& handle = unique_handles[handle_index];
      const std::string handle_key = ByteBlockKey(handle);
      const auto lookup_begin = BuildClock::now();
      const auto payload_it = opaque_payload_dictionary_.find(handle_key);
      out.opening_payload_lookup_ms += BuildMsSince(lookup_begin);
      if (payload_it == opaque_payload_dictionary_.end()) {
        out.error_message = "TPCR opaque payload lookup failed.";
        return out;
      }
      const Aes256Key opening_key =
          DeriveTpcrOpeningKey(opening_outputs[handle_index]);
      const auto decrypt_begin = BuildClock::now();
      const auto decrypted = DecryptPayloadWithOpaqueHandle(
          payload_it->second, opening_key, handle, payload_codec_config_);
      out.opening_decryption_ms += BuildMsSince(decrypt_begin);
      if (!decrypted.ok ||
          decrypted.payload.candidate_id >= records_.size()) {
        out.error_message = "TPCR authenticated payload opening failed.";
        return out;
      }
      opened_cache.emplace(handle, decrypted.payload);
    }
    for (std::size_t query = 0; query < selected_by_query.size(); ++query) {
      for (auto& selected : selected_by_query[query]) {
        const auto cached = opened_cache.find(selected.evidence_key);
        if (cached == opened_cache.end()) {
          out.error_message = "TPCR opened payload reuse failed.";
          return out;
        }
        selected.opened_payload = cached->second;
      }
  }

  std::unordered_map<common::CandidateId, std::size_t> recovered_index;
  std::unordered_set<std::uint64_t> filtered_pair_keys;
  std::uint64_t next_pair_token = 1;
  std::size_t required_pair_count = 0;
  for (std::size_t query = 0; query < selected_by_query.size(); ++query) {
    auto& selected = selected_by_query[query];
    std::sort(selected.begin(), selected.end(),
              [](const SelectedEvidence& lhs, const SelectedEvidence& rhs) {
                return lhs.lower_bound == rhs.lower_bound
                           ? lhs.opened_payload.candidate_id <
                                 rhs.opened_payload.candidate_id
                           : lhs.lower_bound < rhs.lower_bound;
              });
    required_pair_count += selected.size();
    for (const auto& entry : selected) {
      const common::CandidateId candidate_id =
          entry.opened_payload.candidate_id;
      if (entry.lower_bound <= threshold_params_.hamming_threshold) {
        const std::uint64_t pair_key =
            (static_cast<std::uint64_t>(query) << 32U) |
            static_cast<std::uint64_t>(candidate_id);
        filtered_pair_keys.insert(pair_key);
      }
      if (recovered_index.find(candidate_id) == recovered_index.end()) {
        recovered_index.emplace(candidate_id, out.recovered_candidate_ids.size());
        out.recovered_candidate_ids.push_back(candidate_id);
        out.recovered_bfv_pack_refs.push_back(
            entry.opened_payload.bfv_pack_ref);
        ++out.payload_decrypt_success_count;
      }

      out.c0.pairs.push_back(common::QueryCandidatePair{
          static_cast<common::QueryId>(query),
          candidate_id,
          next_pair_token++,
          static_cast<common::CandidateHandle>(candidate_id) + 1,
          true});
      out.pair_bfv_pack_refs.push_back(
          out.recovered_bfv_pack_refs[
              recovered_index.at(candidate_id)]);
    }
  }

  out.num_C0 = filtered_pair_keys.size();
  out.num_pruned = out.num_C_hit - out.num_C0;
  if (out.num_C_hit != 0) {
    out.pruning_ratio =
        1.0 - static_cast<double>(out.num_C0) /
                  static_cast<double>(out.num_C_hit);
  }

  if (out.candidate_statistics_collected) {
    for (std::size_t query = 0; query < query_bundles.size(); ++query) {
      for (std::size_t candidate = 0; candidate < records_.size(); ++candidate) {
        const auto& query_bits = query_bundles[query].simhash_bits;
        const auto& candidate_bits = records_[candidate].fingerprint;
        if (query_bits.size() != candidate_bits.size()) {
          out.error_message =
              "Stage1 benchmark fingerprint length mismatch.";
          return out;
        }
        std::size_t full_distance = 0;
        for (std::size_t bit = 0; bit < query_bits.size(); ++bit) {
          full_distance += query_bits[bit] != candidate_bits[bit] ? 1U : 0U;
        }
        const std::uint64_t pair_key =
            (static_cast<std::uint64_t>(query) << 32U) |
            static_cast<std::uint64_t>(candidate);
        const bool in_filtered_c0 =
            filtered_pair_keys.find(pair_key) != filtered_pair_keys.end();
        if (full_distance <= threshold_params_.hamming_threshold) {
          ++out.num_hamming_true;
          if (in_filtered_c0) {
            ++out.num_hamming_true_in_C0;
          }
        } else if (in_filtered_c0) {
          ++out.num_C0_false_positive;
        }
      }
    }
    out.num_hamming_false_negative =
        out.num_hamming_true - out.num_hamming_true_in_C0;
    if (out.num_hamming_true != 0) {
      out.hamming_recall =
          static_cast<double>(out.num_hamming_true_in_C0) /
          static_cast<double>(out.num_hamming_true);
    }
  }

  out.c0.required_pair_count = required_pair_count;
  out.total_ms =
      std::chrono::duration<double, std::milli>(
          std::chrono::steady_clock::now() - total_begin)
          .count();
  out.tpcr_total_ms = out.opaque_handle_generation_ms +
                      out.opening_oprf_ms +
                      out.opening_payload_lookup_ms +
                      out.opening_decryption_ms;
  out.opening_payload_communication_bytes =
      opaque_payload_wire_message_.size();
  out.stage1_probe_bytes = out.rbokvs_serialized_table_bytes +
                           out.probe_oprf_request_bytes +
                           out.probe_oprf_response_bytes;
  out.stage1_total_communication_bytes =
      out.stage1_probe_bytes + out.opening_oprf_bytes +
      out.opening_payload_communication_bytes;
  return out;
}

bool Stage1IndexBuilder::IsReady() const {
  return ready_;
}

common::ByteBlock Stage1IndexBuilder::DeriveRbokvsKeyFromOprfKey(const common::ByteBlock& oprf_key,
                                                              std::size_t bucket_slot) const {
  std::array<std::uint8_t, 64> input{};
  std::memcpy(input.data(), oprf_key.data(), oprf_key.size());
  const std::uint64_t slot = static_cast<std::uint64_t>(bucket_slot);
  for (std::size_t i = 0; i < 8; ++i) {
    input[16 + i] =
        static_cast<std::uint8_t>((slot >> (8U * i)) & 0xFFU);
  }
  static constexpr char kDomain[] =
      "CTFPSI_STAGE1_RBOKVS_BUCKET_SLOT_V2";
  std::memcpy(input.data() + 24, kDomain, sizeof(kDomain) - 1);

  std::array<std::uint8_t, SHA256_DIGEST_LENGTH> digest{};
  SHA256(input.data(), input.size(), digest.data());
  common::ByteBlock out{};
  std::copy_n(digest.begin(), out.size(), out.begin());
  return out;
}


}  // namespace ctfpsi::stage1
