#pragma once

#include <cstdint>
#include "stage3/yao_labels.hpp"

namespace ctfpsi::stage3 {

struct YaoHalfGateTable {
  YaoLabel garbler;
  YaoLabel evaluator;
};
static_assert(sizeof(YaoHalfGateTable) == 32);

struct YaoGarbledHalfGate {
  YaoLabel output_zero;
  YaoHalfGateTable table;
};

// Zahur-Rosulek-Evans, EUROCRYPT 2015, Figure 2, GbAnd and Ev.
[[nodiscard]] YaoGarbledHalfGate GarbleYaoHalfGate(
    const YaoLabel& a_zero, const YaoLabel& b_zero, const YaoLabel& delta,
    std::uint64_t circuit_id, std::uint64_t gate_id);
[[nodiscard]] YaoLabel EvaluateYaoHalfGate(
    const YaoLabel& a, const YaoLabel& b, const YaoHalfGateTable& table,
    std::uint64_t circuit_id, std::uint64_t gate_id);

}  // namespace ctfpsi::stage3
