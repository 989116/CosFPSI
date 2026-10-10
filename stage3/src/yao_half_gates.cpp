#include "stage3/yao_half_gates.hpp"
#include "stage3/yao_gate_hash.hpp"

namespace ctfpsi::stage3 {
namespace {
YaoLabel SelectTerm(const YaoLabel& value, std::uint8_t bit) {
  YaoLabel out;
  const auto mask = static_cast<std::uint8_t>(0U - (bit & 1U));
  for (std::size_t i = 0; i < out.bytes.size(); ++i) out.bytes[i] = value.bytes[i] & mask;
  return out;
}
}  // namespace

YaoGarbledHalfGate GarbleYaoHalfGate(
    const YaoLabel& a_zero, const YaoLabel& b_zero, const YaoLabel& delta,
    std::uint64_t circuit_id, std::uint64_t gate_id) {
  const auto ha0 = YaoHalfGateHash(a_zero, circuit_id, gate_id, YaoHalf::Garbler);
  const auto ha1 = YaoHalfGateHash(YaoXor(a_zero, delta), circuit_id, gate_id, YaoHalf::Garbler);
  const auto hb0 = YaoHalfGateHash(b_zero, circuit_id, gate_id, YaoHalf::Evaluator);
  const auto hb1 = YaoHalfGateHash(YaoXor(b_zero, delta), circuit_id, gate_id, YaoHalf::Evaluator);
  const auto pa = YaoPermuteBit(a_zero), pb = YaoPermuteBit(b_zero);
  YaoGarbledHalfGate out;
  out.table.garbler = YaoXor(YaoXor(ha0, ha1), SelectTerm(delta, pb));
  out.table.evaluator = YaoXor(YaoXor(hb0, hb1), a_zero);
  const auto wg0 = YaoXor(ha0, SelectTerm(out.table.garbler, pa));
  const auto we0 = YaoXor(hb0, SelectTerm(YaoXor(out.table.evaluator, a_zero), pb));
  out.output_zero = YaoXor(wg0, we0);
  return out;
}

YaoLabel EvaluateYaoHalfGate(
    const YaoLabel& a, const YaoLabel& b, const YaoHalfGateTable& table,
    std::uint64_t circuit_id, std::uint64_t gate_id) {
  const auto ha = YaoHalfGateHash(a, circuit_id, gate_id, YaoHalf::Garbler);
  const auto hb = YaoHalfGateHash(b, circuit_id, gate_id, YaoHalf::Evaluator);
  const auto wg = YaoXor(ha, SelectTerm(table.garbler, YaoPermuteBit(a)));
  const auto we = YaoXor(hb, SelectTerm(YaoXor(table.evaluator, a), YaoPermuteBit(b)));
  return YaoXor(wg, we);
}

}  // namespace ctfpsi::stage3
