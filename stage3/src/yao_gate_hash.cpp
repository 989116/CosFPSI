#include "stage3/yao_gate_hash.hpp"

#include <algorithm>
#include <array>
#include <memory>
#include <stdexcept>
#include <openssl/evp.h>

namespace ctfpsi::stage3 {
namespace {
struct Sha256Context {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  std::unique_ptr<EVP_MD, decltype(&EVP_MD_free)> algorithm{
      EVP_MD_fetch(nullptr, "SHA256", nullptr), EVP_MD_free};
  const EVP_MD* Algorithm() const { return algorithm.get(); }
#else
  const EVP_MD* Algorithm() const { return EVP_sha256(); }
#endif
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context{
      EVP_MD_CTX_new(), EVP_MD_CTX_free};
};
}  // namespace

YaoLabel YaoHalfGateHash(const YaoLabel& label,
                        std::uint64_t circuit_id,
                        std::uint64_t gate_id,
                        YaoHalf half) {
  if (half != YaoHalf::Garbler && half != YaoHalf::Evaluator) {
    throw std::invalid_argument("Invalid Yao half-gate domain");
  }
  // Separate tweaks for the two halves, even when input wires are identical.
  constexpr std::array<std::uint8_t, 16> domain{
      'F','P','S','I','-','Y','A','O','-','H','G','-','v','1',0,0};
  std::array<std::uint8_t, 49> input{};
  std::copy(domain.begin(), domain.end(), input.begin());
  for (std::size_t i = 0; i < 8; ++i) {
    input[16 + i] = static_cast<std::uint8_t>(circuit_id >> (56 - 8 * i));
    input[24 + i] = static_cast<std::uint8_t>(gate_id >> (56 - 8 * i));
  }
  input[32] = static_cast<std::uint8_t>(half);
  std::copy(label.bytes.begin(), label.bytes.end(), input.begin() + 33);
  // Reuse provider lookup and allocation, never hash state or pad outputs.
  // Each call starts a new digest; separate threads have separate contexts.
  thread_local Sha256Context hasher;
  std::array<std::uint8_t, 32> digest{};
  unsigned int digest_size = 0;
  if (!hasher.context || !hasher.Algorithm() ||
      EVP_DigestInit_ex(hasher.context.get(), hasher.Algorithm(), nullptr) != 1 ||
      EVP_DigestUpdate(hasher.context.get(), input.data(), input.size()) != 1 ||
      EVP_DigestFinal_ex(hasher.context.get(), digest.data(), &digest_size) != 1 ||
      digest_size != digest.size()) {
    throw std::runtime_error("SHA-256 failed for Yao gate pad");
  }
  YaoLabel pad;
  std::copy_n(digest.begin(), pad.bytes.size(), pad.bytes.begin());
  return pad;
}

}  // namespace ctfpsi::stage3
