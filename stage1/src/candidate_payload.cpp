#include "stage1/candidate_payload.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

namespace ctfpsi::stage1 {
namespace {

constexpr std::uint32_t kMagic = 0x31475043U;  // "CGP1"

void AppendU32(std::vector<std::uint8_t>* out, std::uint32_t v) {
  out->push_back(static_cast<std::uint8_t>(v & 0xFFU));
  out->push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFU));
  out->push_back(static_cast<std::uint8_t>((v >> 16) & 0xFFU));
  out->push_back(static_cast<std::uint8_t>((v >> 24) & 0xFFU));
}

std::uint32_t ReadU32(const std::vector<std::uint8_t>& in, std::size_t off) {
  return static_cast<std::uint32_t>(in[off]) |
         (static_cast<std::uint32_t>(in[off + 1]) << 8) |
         (static_cast<std::uint32_t>(in[off + 2]) << 16) |
         (static_cast<std::uint32_t>(in[off + 3]) << 24);
}

std::uint32_t Fnv1a32(const std::vector<std::uint8_t>& bytes, std::size_t len) {
  std::uint32_t hash = 2166136261u;
  for (std::size_t i = 0; i < len; ++i) {
    hash ^= bytes[i];
    hash *= 16777619u;
  }
  return hash;
}

bool BuildOpaqueAad(const common::ByteBlock& opaque_handle,
                    std::uint32_t envelope_version,
                    std::vector<std::uint8_t>* aad) {
  if (aad == nullptr) {
    return false;
  }
  static constexpr char kDomain[] = "TPCR_OPAQUE_PAYLOAD_V1";
  aad->assign(kDomain, kDomain + sizeof(kDomain) - 1);
  aad->insert(aad->end(), opaque_handle.begin(), opaque_handle.end());
  AppendU32(aad, envelope_version);
  return true;
}

bool Aes256GcmEncrypt(const std::array<std::uint8_t, 32>& key,
                      const std::array<std::uint8_t, 12>& iv,
                      const std::vector<std::uint8_t>& plaintext,
                      const std::vector<std::uint8_t>& aad,
                      std::vector<std::uint8_t>* ciphertext,
                      std::array<std::uint8_t, 16>* tag,
                      std::string* error) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr) {
    if (error != nullptr) {
      *error = "EVP_CIPHER_CTX_new failed";
    }
    return false;
  }

  bool ok = false;
  do {
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
      if (error != nullptr) {
        *error = "EVP_EncryptInit_ex(set cipher) failed";
      }
      break;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1) {
      if (error != nullptr) {
        *error = "EVP_CTRL_GCM_SET_IVLEN failed";
      }
      break;
    }
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
      if (error != nullptr) {
        *error = "EVP_EncryptInit_ex(set key/iv) failed";
      }
      break;
    }

    int out_len = 0;
    if (!aad.empty()) {
      if (EVP_EncryptUpdate(ctx, nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) != 1) {
        if (error != nullptr) {
          *error = "EVP_EncryptUpdate(aad) failed";
        }
        break;
      }
    }

    ciphertext->assign(plaintext.size(), 0);
    int ct_len = 0;
    if (!plaintext.empty()) {
      if (EVP_EncryptUpdate(ctx,
                            ciphertext->data(),
                            &ct_len,
                            plaintext.data(),
                            static_cast<int>(plaintext.size())) != 1) {
        if (error != nullptr) {
          *error = "EVP_EncryptUpdate(plaintext) failed";
        }
        break;
      }
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext->data() + ct_len, &final_len) != 1) {
      if (error != nullptr) {
        *error = "EVP_EncryptFinal_ex failed";
      }
      break;
    }
    ciphertext->resize(static_cast<std::size_t>(ct_len + final_len));

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag->size()), tag->data()) != 1) {
      if (error != nullptr) {
        *error = "EVP_CTRL_GCM_GET_TAG failed";
      }
      break;
    }

    ok = true;
  } while (false);

  EVP_CIPHER_CTX_free(ctx);
  return ok;
}

bool Aes256GcmDecrypt(const std::array<std::uint8_t, 32>& key,
                      const std::array<std::uint8_t, 12>& iv,
                      const std::vector<std::uint8_t>& ciphertext,
                      const std::vector<std::uint8_t>& aad,
                      const std::array<std::uint8_t, 16>& tag,
                      std::vector<std::uint8_t>* plaintext,
                      std::string* error) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr) {
    if (error != nullptr) {
      *error = "EVP_CIPHER_CTX_new failed";
    }
    return false;
  }

  bool ok = false;
  do {
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
      if (error != nullptr) {
        *error = "EVP_DecryptInit_ex(set cipher) failed";
      }
      break;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1) {
      if (error != nullptr) {
        *error = "EVP_CTRL_GCM_SET_IVLEN failed";
      }
      break;
    }
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
      if (error != nullptr) {
        *error = "EVP_DecryptInit_ex(set key/iv) failed";
      }
      break;
    }

    int out_len = 0;
    if (!aad.empty()) {
      if (EVP_DecryptUpdate(ctx, nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) != 1) {
        if (error != nullptr) {
          *error = "EVP_DecryptUpdate(aad) failed";
        }
        break;
      }
    }

    plaintext->assign(ciphertext.size(), 0);
    int pt_len = 0;
    if (!ciphertext.empty()) {
      if (EVP_DecryptUpdate(ctx,
                            plaintext->data(),
                            &pt_len,
                            ciphertext.data(),
                            static_cast<int>(ciphertext.size())) != 1) {
        if (error != nullptr) {
          *error = "EVP_DecryptUpdate(ciphertext) failed";
        }
        break;
      }
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), const_cast<std::uint8_t*>(tag.data())) != 1) {
      if (error != nullptr) {
        *error = "EVP_CTRL_GCM_SET_TAG failed";
      }
      break;
    }

    int final_len = 0;
    const int final_ok = EVP_DecryptFinal_ex(ctx, plaintext->data() + pt_len, &final_len);
    if (final_ok != 1) {
      if (error != nullptr) {
        *error = "EVP_DecryptFinal_ex tag verify failed";
      }
      break;
    }

    plaintext->resize(static_cast<std::size_t>(pt_len + final_len));
    ok = true;
  } while (false);

  EVP_CIPHER_CTX_free(ctx);
  return ok;
}

}  // namespace

Aes256Key DeriveTpcrOpeningKey(
    const common::ByteBlock& opening_oprf_output) {
  static constexpr char kDomain[] = "TPCR_OPEN_KEY_V1";
  Aes256Key key{};
  SHA256_CTX context;
  SHA256_Init(&context);
  SHA256_Update(&context, kDomain, sizeof(kDomain) - 1);
  SHA256_Update(&context, opening_oprf_output.data(),
                opening_oprf_output.size());
  SHA256_Final(key.data(), &context);
  return key;
}

std::vector<std::uint8_t> SerializePayload(const CandidatePayload& payload, const PayloadCodecConfig& cfg) {
  std::vector<std::uint8_t> out;
  out.reserve(36 + cfg.zero_padding_bytes);

  AppendU32(&out, kMagic);
  AppendU32(&out, cfg.payload_version);
  AppendU32(&out, static_cast<std::uint32_t>(payload.candidate_id));
  AppendU32(&out, 0);  // Reserved field.
  AppendU32(&out, payload.metadata_flags);
  AppendU32(&out, 0);  // Reserved field.
  if (cfg.payload_version >= 2) {
    AppendU32(&out, payload.bfv_pack_ref.pack_id);
    AppendU32(&out, payload.bfv_pack_ref.lane);
  }

  const std::uint32_t checksum = Fnv1a32(out, out.size());
  AppendU32(&out, checksum);
  out.resize(out.size() + cfg.zero_padding_bytes, 0);
  return out;
}

PayloadDecryptResult DeserializePayload(const std::vector<std::uint8_t>& bytes, const PayloadCodecConfig& cfg) {
  PayloadDecryptResult result;

  constexpr std::size_t kHeaderSizeV1 = 24;
  constexpr std::size_t kChecksumSize = 4;
  if (bytes.size() < kHeaderSizeV1 + kChecksumSize + cfg.zero_padding_bytes) {
    result.error = "payload too short";
    return result;
  }

  const std::uint32_t magic = ReadU32(bytes, 0);
  if (magic != kMagic) {
    result.error = "payload magic mismatch";
    return result;
  }

  const std::uint32_t version = ReadU32(bytes, 4);
  if (version != cfg.payload_version) {
    result.error = "payload version mismatch";
    return result;
  }

  const auto cid = static_cast<common::CandidateId>(ReadU32(bytes, 8));
  const std::uint32_t dim = ReadU32(bytes, 12);
  const std::uint32_t flags = ReadU32(bytes, 16);
  const std::uint32_t ciphertext_blob_size = ReadU32(bytes, 20);
  const std::size_t header_size = version >= 2 ? 32 : kHeaderSizeV1;
  if (bytes.size() < header_size + kChecksumSize + cfg.zero_padding_bytes) {
    result.error = "payload v2 header truncated";
    return result;
  }
  common::BfvPackRef pack_ref;
  if (version >= 2) {
    pack_ref.pack_id = ReadU32(bytes, 24);
    pack_ref.lane = ReadU32(bytes, 28);
  }

  if (version != 2 || dim != 0 || ciphertext_blob_size != 0) {
    result.error = "payload must contain a candidate identifier and pack reference";
    return result;
  }

  const std::size_t checksum_off = header_size;
  const std::size_t pad_off = checksum_off + kChecksumSize;

  if (bytes.size() < pad_off + cfg.zero_padding_bytes) {
    result.error = "payload truncated";
    return result;
  }

  const std::uint32_t expected_checksum = ReadU32(bytes, checksum_off);
  const std::uint32_t computed_checksum = Fnv1a32(bytes, checksum_off);
  result.checksum_ok = (expected_checksum == computed_checksum);
  if (!result.checksum_ok) {
    result.error = "payload checksum mismatch";
    return result;
  }

  result.zero_padding_ok = true;
  for (std::size_t i = pad_off; i < pad_off + cfg.zero_padding_bytes; ++i) {
    if (bytes[i] != 0) {
      result.zero_padding_ok = false;
      break;
    }
  }
  if (!result.zero_padding_ok) {
    result.error = "payload zero padding mismatch";
    return result;
  }

  CandidatePayload payload;
  payload.candidate_id = cid;
  payload.metadata_flags = flags;
  payload.bfv_pack_ref = pack_ref;
  result.ok = true;
  result.payload = std::move(payload);
  return result;
}

OpaqueEncryptedCandidatePayload EncryptPayloadWithOpaqueHandle(
    const CandidatePayload& payload,
    const Aes256Key& key,
    const common::ByteBlock& opaque_handle,
    const PayloadCodecConfig& cfg) {
  OpaqueEncryptedCandidatePayload envelope;
  envelope.envelope_version = cfg.payload_version;
  if (RAND_priv_bytes(envelope.iv.data(),
                      static_cast<int>(envelope.iv.size())) != 1) {
    return envelope;
  }
  const auto plaintext = SerializePayload(payload, cfg);
  std::vector<std::uint8_t> aad;
  BuildOpaqueAad(opaque_handle, envelope.envelope_version, &aad);
  std::string error;
  if (!Aes256GcmEncrypt(key, envelope.iv, plaintext, aad,
                        &envelope.ciphertext, &envelope.auth_tag, &error)) {
    envelope.ciphertext.clear();
  }
  return envelope;
}

PayloadDecryptResult DecryptPayloadWithOpaqueHandle(
    const OpaqueEncryptedCandidatePayload& envelope,
    const Aes256Key& key,
    const common::ByteBlock& opaque_handle,
    const PayloadCodecConfig& cfg) {
  PayloadDecryptResult result;
  std::vector<std::uint8_t> aad;
  BuildOpaqueAad(opaque_handle, envelope.envelope_version, &aad);
  std::vector<std::uint8_t> plaintext;
  std::string error;
  if (!Aes256GcmDecrypt(key, envelope.iv, envelope.ciphertext, aad,
                        envelope.auth_tag, &plaintext, &error)) {
    result.error = error.empty() ? "TPCR AES-256-GCM decrypt failed" : error;
    return result;
  }
  result = DeserializePayload(plaintext, cfg);
  result.gcm_tag_ok = result.ok;
  return result;
}

bool IsAllZeroPadding(const std::vector<common::ByteBlock>& blocks, std::size_t start_block_index) {
  for (std::size_t i = start_block_index; i < blocks.size(); ++i) {
    for (std::uint8_t byte : blocks[i]) {
      if (byte != 0) {
        return false;
      }
    }
  }
  return true;
}

}  // namespace ctfpsi::stage1
