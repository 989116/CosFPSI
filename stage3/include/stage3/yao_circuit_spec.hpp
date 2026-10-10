#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace ctfpsi::stage3 {

enum class YaoGateKind {
  Xor = 1,
  And = 2,
};

struct YaoGateSpec {
  YaoGateKind kind = YaoGateKind::Xor;
  std::size_t in0 = 0;
  std::size_t in1 = 0;
  std::size_t out = 0;
};

struct YaoCompareCircuitSpec {
  std::uint32_t compare_bits = 32;
  bool signed_compare = true;

  // Generic mode: compare (lhs_a+lhs_b) >= (rhs_a+rhs_b)
  // Constant-threshold mode: compare (lhs_a+lhs_b) >= rhs_constant_word
  bool rhs_is_constant = false;
  std::uint64_t rhs_constant_word = 0;

  // Modular-share mode reconstructs (lhs_a + lhs_b) mod lhs_modulus,
  // centers the residue, and compares it against a public non-negative
  // threshold. This is used by the exact-HE masked-decryption standalone.
  bool lhs_is_modular = false;
  std::uint64_t lhs_modulus = 0;

  std::vector<std::size_t> a_lhs_wires;
  std::vector<std::size_t> a_rhs_wires;
  std::vector<std::size_t> b_lhs_wires;
  std::vector<std::size_t> b_rhs_wires;

  // The modular-share standalone carries validity through the fixed circuit so
  // padded lanes execute the same OT/GC schedule as valid lanes.
  bool has_b_valid_wire = false;
  std::size_t b_valid_wire = 0;

  std::size_t const_zero_wire = 0;
  std::size_t const_one_wire = 0;
  std::size_t output_wire = 0;
  std::size_t wire_count = 0;

  std::vector<YaoGateSpec> gates;
};

bool BuildYaoCompareCircuitSpec(std::uint32_t compare_bits,
                                     bool signed_compare,
                                     YaoCompareCircuitSpec* out,
                                     std::string* error = nullptr);

bool BuildYaoCompareAgainstConstantSpec(std::uint32_t compare_bits,
                                             bool signed_compare,
                                             std::uint64_t rhs_constant_word,
                                             YaoCompareCircuitSpec* out,
                                             std::string* error = nullptr);

bool BuildYaoCompareModuloAgainstConstantSpec(
    std::uint32_t compare_bits,
    std::uint64_t lhs_modulus,
    std::uint64_t rhs_constant_word,
    YaoCompareCircuitSpec* out,
    std::string* error = nullptr);

}  // namespace ctfpsi::stage3


