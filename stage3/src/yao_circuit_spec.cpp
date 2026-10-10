#include "stage3/yao_circuit_spec.hpp"

#include <algorithm>
#include <limits>

namespace ctfpsi::stage3 {
namespace {

void SetError(std::string* error, const std::string& message) {
  if (error != nullptr) {
    *error = message;
  }
}

std::uint64_t BitMask(std::uint32_t bits) {
  if (bits >= 64) {
    return std::numeric_limits<std::uint64_t>::max();
  }
  return (static_cast<std::uint64_t>(1) << bits) - 1;
}

std::size_t AllocWire(std::size_t* next_wire) {
  const std::size_t w = *next_wire;
  *next_wire += 1;
  return w;
}

std::size_t AddGate(YaoGateKind kind,
                    std::size_t in0,
                    std::size_t in1,
                    std::size_t* next_wire,
                    std::vector<YaoGateSpec>* gates) {
  const std::size_t out = AllocWire(next_wire);
  gates->push_back(YaoGateSpec{kind, in0, in1, out});
  return out;
}

std::size_t AddXor(std::size_t a,
                   std::size_t b,
                   std::size_t* next_wire,
                   std::vector<YaoGateSpec>* gates) {
  return AddGate(YaoGateKind::Xor, a, b, next_wire, gates);
}

std::size_t AddAnd(std::size_t a,
                   std::size_t b,
                   std::size_t* next_wire,
                   std::vector<YaoGateSpec>* gates) {
  return AddGate(YaoGateKind::And, a, b, next_wire, gates);
}

std::size_t AddNot(std::size_t a,
                   std::size_t const_one_wire,
                   std::size_t* next_wire,
                   std::vector<YaoGateSpec>* gates) {
  return AddXor(a, const_one_wire, next_wire, gates);
}

std::size_t AddOr(std::size_t a,
                  std::size_t b,
                  std::size_t* next_wire,
                  std::vector<YaoGateSpec>* gates) {
  // or(a,b) = a xor b xor (a and b)
  const std::size_t axb = AddXor(a, b, next_wire, gates);
  const std::size_t aandb = AddAnd(a, b, next_wire, gates);
  return AddXor(axb, aandb, next_wire, gates);
}

std::pair<std::size_t, std::size_t> AddFullAdder(std::size_t a,
                                                 std::size_t b,
                                                 std::size_t cin,
                                                 std::size_t* next_wire,
                                                 std::vector<YaoGateSpec>* gates) {
  // x1 = a xor b
  // sum = x1 xor cin
  // cout = (a&b) xor (cin&x1)
  // The two terms are mutually exclusive, so xor is equivalent to or here.
  const std::size_t x1 = AddXor(a, b, next_wire, gates);
  const std::size_t sum = AddXor(x1, cin, next_wire, gates);
  const std::size_t u = AddAnd(a, b, next_wire, gates);
  const std::size_t v = AddAnd(cin, x1, next_wire, gates);
  const std::size_t cout = AddXor(u, v, next_wire, gates);
  return {sum, cout};
}

std::vector<std::size_t> AddAdder(const std::vector<std::size_t>& lhs,
                                  const std::vector<std::size_t>& rhs,
                                  std::size_t carry_in_wire,
                                  std::size_t* carry_out_wire,
                                  std::size_t* next_wire,
                                  std::vector<YaoGateSpec>* gates) {
  const std::size_t bits = std::min(lhs.size(), rhs.size());
  std::vector<std::size_t> sum(bits, 0);

  std::size_t carry = carry_in_wire;
  for (std::size_t i = 0; i < bits; ++i) {
    const auto [s, c] = AddFullAdder(lhs[i], rhs[i], carry, next_wire, gates);
    sum[i] = s;
    carry = c;
  }

  if (carry_out_wire != nullptr) {
    *carry_out_wire = carry;
  }

  return sum;
}

std::size_t AddUnsignedGeConstant(
    const std::vector<std::size_t>& lhs,
    std::uint64_t rhs_constant,
    std::size_t const_one_wire,
    std::size_t const_zero_wire,
    std::size_t* next_wire,
    std::vector<YaoGateSpec>* gates) {
  std::size_t borrow = const_zero_wire;
  for (std::size_t i = 0; i < lhs.size(); ++i) {
    const bool cbit = ((rhs_constant >> i) & 0x1ULL) != 0;
    const std::size_t not_lhs =
        AddNot(lhs[i], const_one_wire, next_wire, gates);
    if (!cbit) {
      borrow = AddAnd(not_lhs, borrow, next_wire, gates);
    } else {
      borrow = AddOr(not_lhs, borrow, next_wire, gates);
    }
  }
  return AddNot(borrow, const_one_wire, next_wire, gates);
}

bool BuildGenericSpec(std::uint32_t compare_bits,
                      bool signed_compare,
                      YaoCompareCircuitSpec* out,
                      std::string* error) {
  YaoCompareCircuitSpec spec;
  spec.compare_bits = compare_bits;
  spec.signed_compare = signed_compare;
  spec.rhs_is_constant = false;

  std::size_t next_wire = 0;
  const std::size_t bits = static_cast<std::size_t>(compare_bits);

  spec.a_lhs_wires.resize(bits);
  spec.a_rhs_wires.resize(bits);
  spec.b_lhs_wires.resize(bits);
  spec.b_rhs_wires.resize(bits);

  for (std::size_t i = 0; i < bits; ++i) {
    spec.a_lhs_wires[i] = AllocWire(&next_wire);
  }
  for (std::size_t i = 0; i < bits; ++i) {
    spec.a_rhs_wires[i] = AllocWire(&next_wire);
  }
  for (std::size_t i = 0; i < bits; ++i) {
    spec.b_lhs_wires[i] = AllocWire(&next_wire);
  }
  for (std::size_t i = 0; i < bits; ++i) {
    spec.b_rhs_wires[i] = AllocWire(&next_wire);
  }

  spec.const_zero_wire = AllocWire(&next_wire);
  spec.const_one_wire = AllocWire(&next_wire);

  std::size_t carry_unused = 0;
  std::vector<std::size_t> lhs = AddAdder(spec.a_lhs_wires,
                                          spec.b_lhs_wires,
                                          spec.const_zero_wire,
                                          &carry_unused,
                                          &next_wire,
                                          &spec.gates);
  std::vector<std::size_t> rhs = AddAdder(spec.a_rhs_wires,
                                          spec.b_rhs_wires,
                                          spec.const_zero_wire,
                                          &carry_unused,
                                          &next_wire,
                                          &spec.gates);

  if (signed_compare && bits > 0) {
    const std::size_t msb = bits - 1;
    lhs[msb] = AddXor(lhs[msb], spec.const_one_wire, &next_wire, &spec.gates);
    rhs[msb] = AddXor(rhs[msb], spec.const_one_wire, &next_wire, &spec.gates);
  }

  std::vector<std::size_t> not_rhs(bits, 0);
  for (std::size_t i = 0; i < bits; ++i) {
    not_rhs[i] = AddNot(rhs[i], spec.const_one_wire, &next_wire, &spec.gates);
  }

  std::size_t carry_out = 0;
  (void)AddAdder(lhs,
                 not_rhs,
                 spec.const_one_wire,
                 &carry_out,
                 &next_wire,
                 &spec.gates);

  spec.output_wire = carry_out;
  spec.wire_count = next_wire;

  *out = std::move(spec);
  return true;
}

bool BuildConstantThresholdSpec(std::uint32_t compare_bits,
                                bool signed_compare,
                                std::uint64_t rhs_constant_word,
                                YaoCompareCircuitSpec* out,
                                std::string* error) {
  YaoCompareCircuitSpec spec;
  spec.compare_bits = compare_bits;
  spec.signed_compare = signed_compare;
  spec.rhs_is_constant = true;

  const std::uint64_t mask = BitMask(compare_bits);
  std::uint64_t rhs_const = rhs_constant_word & mask;

  std::size_t next_wire = 0;
  const std::size_t bits = static_cast<std::size_t>(compare_bits);

  spec.a_lhs_wires.resize(bits);
  spec.b_lhs_wires.resize(bits);

  for (std::size_t i = 0; i < bits; ++i) {
    spec.a_lhs_wires[i] = AllocWire(&next_wire);
  }
  for (std::size_t i = 0; i < bits; ++i) {
    spec.b_lhs_wires[i] = AllocWire(&next_wire);
  }

  spec.const_zero_wire = AllocWire(&next_wire);
  spec.const_one_wire = AllocWire(&next_wire);

  std::size_t carry_unused = 0;
  std::vector<std::size_t> lhs = AddAdder(spec.a_lhs_wires,
                                          spec.b_lhs_wires,
                                          spec.const_zero_wire,
                                          &carry_unused,
                                          &next_wire,
                                          &spec.gates);

  if (signed_compare && bits > 0) {
    const std::size_t msb = bits - 1;
    lhs[msb] = AddNot(lhs[msb], spec.const_one_wire, &next_wire, &spec.gates);
    rhs_const ^= (static_cast<std::uint64_t>(1) << msb);
    rhs_const &= mask;
  }

  // Unsigned compare lhs >= rhs_const, implemented as borrow-chain of lhs - rhs_const.
  // ge = !final_borrow
  std::size_t borrow = spec.const_zero_wire;
  for (std::size_t i = 0; i < bits; ++i) {
    const bool cbit = (((rhs_const >> i) & 0x1ULL) != 0);
    const std::size_t not_lhs = AddNot(lhs[i], spec.const_one_wire, &next_wire, &spec.gates);

    if (!cbit) {
      // borrow' = (~lhs_i) & borrow
      borrow = AddAnd(not_lhs, borrow, &next_wire, &spec.gates);
    } else {
      // borrow' = (~lhs_i) | borrow
      borrow = AddOr(not_lhs, borrow, &next_wire, &spec.gates);
    }
  }

  spec.output_wire = AddNot(borrow, spec.const_one_wire, &next_wire, &spec.gates);
  spec.wire_count = next_wire;
  spec.rhs_constant_word = rhs_const;

  *out = std::move(spec);
  return true;
}

bool BuildModuloConstantThresholdSpec(
    std::uint32_t compare_bits,
    std::uint64_t lhs_modulus,
    std::uint64_t rhs_constant_word,
    YaoCompareCircuitSpec* out,
    std::string* error) {
  const std::size_t bits = static_cast<std::size_t>(compare_bits);
  const std::uint64_t word_limit =
      static_cast<std::uint64_t>(1) << compare_bits;
  const std::uint64_t positive_end = (lhs_modulus + 1) / 2;

  if (lhs_modulus < 3 || lhs_modulus > word_limit / 2) {
    SetError(error,
             "modular compare requires 3 <= modulus <= 2^(compare_bits-1)");
    return false;
  }
  if (rhs_constant_word >= positive_end) {
    SetError(error,
             "modular compare currently requires a non-negative centered threshold");
    return false;
  }

  YaoCompareCircuitSpec spec;
  spec.compare_bits = compare_bits;
  spec.signed_compare = true;
  spec.rhs_is_constant = true;
  spec.rhs_constant_word = rhs_constant_word;
  spec.lhs_is_modular = true;
  spec.lhs_modulus = lhs_modulus;

  std::size_t next_wire = 0;
  spec.a_lhs_wires.resize(bits);
  spec.b_lhs_wires.resize(bits);
  for (std::size_t i = 0; i < bits; ++i) {
    spec.a_lhs_wires[i] = AllocWire(&next_wire);
  }
    for (std::size_t i = 0; i < bits; ++i) {
      spec.b_lhs_wires[i] = AllocWire(&next_wire);
    }
    spec.has_b_valid_wire = true;
    spec.b_valid_wire = AllocWire(&next_wire);
    spec.const_zero_wire = AllocWire(&next_wire);
  spec.const_one_wire = AllocWire(&next_wire);

  // Both shares are canonical residues in [0,t). Their sum is below 2t and
  // therefore fits compare_bits under the checked modulus bound.
  std::size_t sum_carry_unused = 0;
  const std::vector<std::size_t> sum =
      AddAdder(spec.a_lhs_wires,
               spec.b_lhs_wires,
               spec.const_zero_wire,
               &sum_carry_unused,
               &next_wire,
               &spec.gates);

  // Compute sum-t. The final carry is 1 exactly when sum >= t.
  std::vector<std::size_t> not_modulus(bits, spec.const_zero_wire);
  for (std::size_t i = 0; i < bits; ++i) {
    not_modulus[i] = ((lhs_modulus >> i) & 0x1ULL) != 0
                         ? spec.const_zero_wire
                         : spec.const_one_wire;
  }
  std::size_t sum_ge_modulus = 0;
  const std::vector<std::size_t> difference =
      AddAdder(sum,
               not_modulus,
               spec.const_one_wire,
               &sum_ge_modulus,
               &next_wire,
               &spec.gates);

  // Select sum-t on wrap, otherwise sum. This produces z in [0,t).
  std::vector<std::size_t> reduced(bits, 0);
  for (std::size_t i = 0; i < bits; ++i) {
    const std::size_t changed =
        AddXor(sum[i], difference[i], &next_wire, &spec.gates);
    const std::size_t selected =
        AddAnd(sum_ge_modulus, changed, &next_wire, &spec.gates);
    reduced[i] = AddXor(sum[i], selected, &next_wire, &spec.gates);
  }

  // For odd t, centered residues [0,(t-1)/2] are non-negative. Since the
  // public threshold is non-negative, the signed predicate is equivalent to
  // threshold <= z < (t+1)/2.
  const std::size_t ge_threshold = AddUnsignedGeConstant(
      reduced,
      rhs_constant_word,
      spec.const_one_wire,
      spec.const_zero_wire,
      &next_wire,
      &spec.gates);
  const std::size_t ge_negative_region = AddUnsignedGeConstant(
      reduced,
      positive_end,
      spec.const_one_wire,
      spec.const_zero_wire,
      &next_wire,
      &spec.gates);
  const std::size_t non_negative = AddNot(
      ge_negative_region, spec.const_one_wire, &next_wire, &spec.gates);
    const std::size_t threshold_match =
        AddAnd(ge_threshold, non_negative, &next_wire, &spec.gates);
    spec.output_wire =
        AddAnd(threshold_match, spec.b_valid_wire, &next_wire, &spec.gates);
  spec.wire_count = next_wire;

  *out = std::move(spec);
  return true;
}

}  // namespace

bool BuildYaoCompareCircuitSpec(std::uint32_t compare_bits,
                                     bool signed_compare,
                                     YaoCompareCircuitSpec* out,
                                     std::string* error) {
  if (out == nullptr) {
    SetError(error, "BuildYaoCompareCircuitSpec: out is null");
    return false;
  }

  if (compare_bits == 0 || compare_bits > 32) {
    SetError(error, "BuildYaoCompareCircuitSpec currently supports compare_bits in [1,32]");
    return false;
  }

  return BuildGenericSpec(compare_bits, signed_compare, out, error);
}

bool BuildYaoCompareAgainstConstantSpec(std::uint32_t compare_bits,
                                             bool signed_compare,
                                             std::uint64_t rhs_constant_word,
                                             YaoCompareCircuitSpec* out,
                                             std::string* error) {
  if (out == nullptr) {
    SetError(error, "BuildYaoCompareAgainstConstantSpec: out is null");
    return false;
  }

  if (compare_bits == 0 || compare_bits > 32) {
    SetError(error, "BuildYaoCompareAgainstConstantSpec currently supports compare_bits in [1,32]");
    return false;
  }

  return BuildConstantThresholdSpec(compare_bits, signed_compare, rhs_constant_word, out, error);
}

bool BuildYaoCompareModuloAgainstConstantSpec(
    std::uint32_t compare_bits,
    std::uint64_t lhs_modulus,
    std::uint64_t rhs_constant_word,
    YaoCompareCircuitSpec* out,
    std::string* error) {
  if (out == nullptr) {
    SetError(error,
             "BuildYaoCompareModuloAgainstConstantSpec: out is null");
    return false;
  }
  if (compare_bits < 2 || compare_bits > 32) {
    SetError(error,
             "modular Yao GC compare supports compare_bits in [2,32]");
    return false;
  }
  return BuildModuloConstantThresholdSpec(compare_bits,
                                          lhs_modulus,
                                          rhs_constant_word,
                                          out,
                                          error);
}

}  // namespace ctfpsi::stage3


