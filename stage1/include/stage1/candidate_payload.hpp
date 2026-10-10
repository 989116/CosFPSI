#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "common/types.hpp"

namespace ctfpsi::stage1 {

using Aes256Key = std::array<std::uint8_t, 32>;

struct CandidatePayload {
  common::CandidateId candidate_id = 0;
  // Stage 1 recovers only a pack reference. The
  // ciphertext pack itself is stored once in the Stage2 sender material.
  common::BfvPackRef bfv_pack_ref;
  std::uint32_t metadata_flags = 0;
};

struct PayloadCodecConfig {
  std::size_t zero_padding_bytes = 32;
  std::uint32_t payload_version = 2;
};

struct OpaqueEncryptedCandidatePayload {
  std::uint32_t envelope_version = 1;
  std::array<std::uint8_t, 12> iv{};
  std::array<std::uint8_t, 16> auth_tag{};
  std::vector<std::uint8_t> ciphertext;
};

struct PayloadDecryptResult {
  bool ok = false;
  std::string error;
  CandidatePayload payload;
  bool checksum_ok = false;
  bool zero_padding_ok = false;
  bool gcm_tag_ok = false;
};

std::vector<std::uint8_t> SerializePayload(const CandidatePayload& payload, const PayloadCodecConfig& cfg);
PayloadDecryptResult DeserializePayload(const std::vector<std::uint8_t>& bytes, const PayloadCodecConfig& cfg);

OpaqueEncryptedCandidatePayload EncryptPayloadWithOpaqueHandle(
    const CandidatePayload& payload,
    const Aes256Key& key,
    const common::ByteBlock& opaque_handle,
    const PayloadCodecConfig& cfg);

PayloadDecryptResult DecryptPayloadWithOpaqueHandle(
    const OpaqueEncryptedCandidatePayload& envelope,
    const Aes256Key& key,
    const common::ByteBlock& opaque_handle,
    const PayloadCodecConfig& cfg);

Aes256Key DeriveTpcrOpeningKey(
    const common::ByteBlock& opening_oprf_output);

bool IsAllZeroPadding(const std::vector<common::ByteBlock>& blocks, std::size_t start_block_index);

}  // namespace ctfpsi::stage1
