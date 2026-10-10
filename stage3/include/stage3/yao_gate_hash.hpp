#pragma once

#include <cstdint>
#include "stage3/yao_labels.hpp"

namespace ctfpsi::stage3 {

enum class YaoHalf : std::uint8_t { Garbler = 0, Evaluator = 1 };

// Tweakable single-label hash for half-gates (random-oracle instantiation).
// circuit_id is the padded batch position, not a query or candidate identifier.
[[nodiscard]] YaoLabel YaoHalfGateHash(const YaoLabel& label,
                                      std::uint64_t circuit_id,
                                      std::uint64_t gate_id,
                                      YaoHalf half);

}  // namespace ctfpsi::stage3
