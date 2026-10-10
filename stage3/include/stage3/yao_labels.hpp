#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace ctfpsi::stage3 {

struct YaoLabel {
  std::array<std::uint8_t, 16> bytes{};
};

struct YaoLabelPair {
  YaoLabel zero{};
  YaoLabel one{};
};

class YaoLabelGenerator {
 public:
  YaoLabelGenerator();

  [[nodiscard]] const YaoLabel& Delta() const;
  [[nodiscard]] YaoLabel RandomLabel();
  [[nodiscard]] YaoLabelPair MakeWireLabelPair();

 private:
  void RefillSecureRandomBuffer();

  std::array<std::uint8_t, 4096> secure_random_buffer_{};
  std::size_t secure_random_offset_ = secure_random_buffer_.size();
  YaoLabel delta_{};
};

[[nodiscard]] bool YaoLabelEqual(const YaoLabel& a, const YaoLabel& b);
[[nodiscard]] std::uint8_t YaoPermuteBit(const YaoLabel& a);
[[nodiscard]] YaoLabel YaoXor(const YaoLabel& a, const YaoLabel& b);
[[nodiscard]] YaoLabel YaoSelect(const YaoLabelPair& pair, std::uint8_t bit);

}  // namespace ctfpsi::stage3


