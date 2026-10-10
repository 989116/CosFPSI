#include "stage3/yao_labels.hpp"

#include <cstring>
#include <stdexcept>
#include <string>

#include <openssl/rand.h>

namespace ctfpsi::stage3 {
YaoLabelGenerator::YaoLabelGenerator() {
  delta_ = RandomLabel();
  delta_.bytes[0] |= 0x01u;
}

const YaoLabel& YaoLabelGenerator::Delta() const {
  return delta_;
}

YaoLabel YaoLabelGenerator::RandomLabel() {
  YaoLabel out;
  if (secure_random_offset_ + out.bytes.size() >
      secure_random_buffer_.size()) {
    RefillSecureRandomBuffer();
  }
  std::memcpy(out.bytes.data(),
              secure_random_buffer_.data() + secure_random_offset_,
              out.bytes.size());
  secure_random_offset_ += out.bytes.size();
  return out;
}

void YaoLabelGenerator::RefillSecureRandomBuffer() {
  if (RAND_bytes(secure_random_buffer_.data(),
                 static_cast<int>(secure_random_buffer_.size())) != 1) {
    throw std::runtime_error("OpenSSL RAND_bytes failed for Yao labels");
  }
  secure_random_offset_ = 0;
}

YaoLabelPair YaoLabelGenerator::MakeWireLabelPair() {
  YaoLabelPair out;
  out.zero = RandomLabel();
  out.one = YaoXor(out.zero, delta_);
  return out;
}

bool YaoLabelEqual(const YaoLabel& a, const YaoLabel& b) {
  return a.bytes == b.bytes;
}

std::uint8_t YaoPermuteBit(const YaoLabel& a) {
  return static_cast<std::uint8_t>(a.bytes[0] & 0x01u);
}

YaoLabel YaoXor(const YaoLabel& a, const YaoLabel& b) {
  YaoLabel out;
  for (std::size_t i = 0; i < out.bytes.size(); ++i) {
    out.bytes[i] = static_cast<std::uint8_t>(a.bytes[i] ^ b.bytes[i]);
  }
  return out;
}

YaoLabel YaoSelect(const YaoLabelPair& pair, std::uint8_t bit) {
  return (bit == 0) ? pair.zero : pair.one;
}

}  // namespace ctfpsi::stage3


