#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "common/types.hpp"

namespace ctfpsi::adapters {

class RbokvsAdapter {
 public:
  enum class BackendMode { Unavailable, Rbokvs };

  struct EncodeRequest {
    std::vector<common::ByteBlock> keys;
    std::vector<std::vector<common::ByteBlock>> values;
    std::size_t value_length_blocks = 0;
  };
  struct EncodeResponse {
    bool ok = false;
    std::string message;
    std::vector<std::vector<common::ByteBlock>> codewords;
    BackendMode requested_backend = BackendMode::Rbokvs;
    BackendMode backend_used = BackendMode::Unavailable;
    std::string backend_error;
  };
  struct DecodeResponse {
    bool hit = false;
    std::string message;
    std::vector<common::ByteBlock> value_blocks;
    BackendMode requested_backend = BackendMode::Rbokvs;
    BackendMode backend_used = BackendMode::Unavailable;
    std::string backend_error;
  };

  EncodeResponse Encode(const EncodeRequest& request) const;
  EncodeResponse EncodeWithBackend(const EncodeRequest& request, BackendMode backend) const;
  std::vector<common::ByteBlock> Decode(
      const std::vector<std::vector<common::ByteBlock>>& codewords,
      const common::ByteBlock& key, std::size_t value_length_blocks) const;
  DecodeResponse DecodeDetailed(
      const std::vector<std::vector<common::ByteBlock>>& codewords,
      const common::ByteBlock& key, std::size_t value_length_blocks) const;
  static std::uint64_t SerializedTableSizeBytes(
      const std::vector<std::vector<common::ByteBlock>>& codewords);
  static const char* BackendModeToString(BackendMode mode);
};

}  // namespace ctfpsi::adapters

