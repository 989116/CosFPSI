#include "stage3/yao_compare.hpp"
#include "stage3/yao_half_gates.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ctfpsi::stage3 {
namespace {

struct GarbledAndGate {
  std::size_t in0 = 0;
  std::size_t in1 = 0;
  std::size_t out = 0;
  YaoHalfGateTable table{};
  std::size_t gate_id = 0;
};

struct CachedCircuitSpec {
  YaoCompareCircuitSpec spec;
  std::size_t and_gate_count = 0;
};

std::uint64_t BitMask(std::uint32_t bits) {
  if (bits >= 64) {
    return std::numeric_limits<std::uint64_t>::max();
  }
  return (static_cast<std::uint64_t>(1) << bits) - 1;
}

void FillBits(std::uint64_t value, std::uint32_t bits, std::vector<std::uint8_t>* out) {
  out->assign(static_cast<std::size_t>(bits), 0);
  for (std::size_t i = 0; i < out->size(); ++i) {
    (*out)[i] = static_cast<std::uint8_t>((value >> i) & 0x1ULL);
  }
}

bool AssignInputWireLabels(const std::vector<std::size_t>& wires,
                           const std::vector<std::uint8_t>& bits,
                           const std::vector<YaoLabelPair>& label_pairs,
                           std::vector<YaoLabel>* labels,
                           std::string* error) {
  if (wires.size() != bits.size()) {
    if (error != nullptr) {
      *error = "wire/bit size mismatch";
    }
    return false;
  }
  for (std::size_t i = 0; i < wires.size(); ++i) {
    const std::size_t w = wires[i];
    if (w >= labels->size() || w >= label_pairs.size()) {
      if (error != nullptr) {
        *error = "input wire index out of range";
      }
      return false;
    }
    (*labels)[w] = YaoSelect(label_pairs[w], bits[i]);
  }
  return true;
}

const CachedCircuitSpec* GetCachedGenericCircuitSpec(std::uint32_t compare_bits,
                                                     bool signed_compare,
                                                     std::string* error) {
  static std::mutex cache_mu;
  static std::array<std::array<bool, 33>, 2> ready{};
  static std::array<std::array<CachedCircuitSpec, 33>, 2> cache;

  const std::size_t sign_idx = signed_compare ? 1u : 0u;
  const std::size_t bit_idx = static_cast<std::size_t>(compare_bits);

  if (bit_idx >= 33) {
    if (error != nullptr) {
      *error = "compare_bits out of cache range";
    }
    return nullptr;
  }

  std::scoped_lock lk(cache_mu);
  if (!ready[sign_idx][bit_idx]) {
    CachedCircuitSpec entry;
    std::string build_error;
    if (!BuildYaoCompareCircuitSpec(compare_bits, signed_compare, &entry.spec, &build_error)) {
      if (error != nullptr) {
        *error = "Yao GC circuit build failed: " + build_error;
      }
      return nullptr;
    }

    for (const auto& g : entry.spec.gates) {
      if (g.kind == YaoGateKind::And) {
        ++entry.and_gate_count;
      }
    }

    cache[sign_idx][bit_idx] = std::move(entry);
    ready[sign_idx][bit_idx] = true;
  }

  return &cache[sign_idx][bit_idx];
}

std::uint64_t MakeConstantCacheKey(std::uint32_t compare_bits,
                                   bool signed_compare,
                                   std::uint64_t rhs_constant_word) {
  const std::uint64_t s = signed_compare ? 1ULL : 0ULL;
  return (rhs_constant_word & 0xFFFFFFFFULL) ^ (static_cast<std::uint64_t>(compare_bits) << 40) ^ (s << 63);
}

const CachedCircuitSpec* GetCachedConstantCircuitSpec(std::uint32_t compare_bits,
                                                      bool signed_compare,
                                                      std::uint64_t rhs_constant_word,
                                                      std::string* error) {
  static std::mutex cache_mu;
  static std::unordered_map<std::uint64_t, CachedCircuitSpec> cache;

  const std::uint64_t key = MakeConstantCacheKey(compare_bits, signed_compare, rhs_constant_word);

  std::scoped_lock lk(cache_mu);
  const auto it = cache.find(key);
  if (it != cache.end()) {
    return &it->second;
  }

  CachedCircuitSpec entry;
  std::string build_error;
  if (!BuildYaoCompareAgainstConstantSpec(compare_bits,
                                               signed_compare,
                                               rhs_constant_word,
                                               &entry.spec,
                                               &build_error)) {
    if (error != nullptr) {
      *error = "Yao GC constant-threshold circuit build failed: " + build_error;
    }
    return nullptr;
  }

  for (const auto& g : entry.spec.gates) {
    if (g.kind == YaoGateKind::And) {
      ++entry.and_gate_count;
    }
  }

  auto inserted = cache.emplace(key, std::move(entry));
  return &inserted.first->second;
}

const CachedCircuitSpec* GetCachedModuloConstantCircuitSpec(
    std::uint32_t compare_bits,
    std::uint64_t lhs_modulus,
    std::uint64_t rhs_constant_word,
    std::string* error) {
  static std::mutex cache_mu;
  static std::unordered_map<std::string, CachedCircuitSpec> cache;

  const std::string key = std::to_string(compare_bits) + ":" +
                          std::to_string(lhs_modulus) + ":" +
                          std::to_string(rhs_constant_word);
  std::scoped_lock lk(cache_mu);
  const auto it = cache.find(key);
  if (it != cache.end()) {
    return &it->second;
  }

  CachedCircuitSpec entry;
  std::string build_error;
  if (!BuildYaoCompareModuloAgainstConstantSpec(compare_bits,
                                                      lhs_modulus,
                                                      rhs_constant_word,
                                                      &entry.spec,
                                                      &build_error)) {
    if (error != nullptr) {
      *error = "Yao GC modular-share circuit build failed: " + build_error;
    }
    return nullptr;
  }
  for (const auto& gate : entry.spec.gates) {
    if (gate.kind == YaoGateKind::And) {
      ++entry.and_gate_count;
    }
  }
  auto inserted = cache.emplace(key, std::move(entry));
  return &inserted.first->second;
}

bool TryDerivePublicThresholdWord(const YaoCompareRequest& request,
                                  std::uint64_t mask,
                                  std::uint64_t* out_word) {
  bool has_value = false;
  std::uint64_t ref = 0;

  const std::size_t n = std::min({
      request.rhs_share_a.size(),
      request.rhs_share_b.size(),
      request.dummy_mask.size(),
  });

  for (std::size_t i = 0; i < n; ++i) {
    if (request.dummy_mask[i] != 0) {
      continue;
    }
    const std::uint64_t rhs = static_cast<std::uint64_t>(request.rhs_share_a[i] + request.rhs_share_b[i]) & mask;
    if (!has_value) {
      ref = rhs;
      has_value = true;
      continue;
    }
    if (rhs != ref) {
      return false;
    }
  }

  if (!has_value) {
    ref = 0;
  }

  if (out_word != nullptr) {
    *out_word = ref;
  }
  return true;
}

}  // namespace

YaoCompareResult RunYaoBatchedCompare(const YaoCompareRequest& request,
                                                const YaoOtFn& ot_fn) {
  YaoCompareResult out;

  const std::size_t n = std::min({
      request.lhs_share_a.size(),
      request.lhs_share_b.size(),
      request.rhs_share_a.size(),
      request.rhs_share_b.size(),
      request.dummy_mask.size(),
  });

  out.final_match_bits.assign(request.dummy_mask.size(), 0);
  out.stats.candidate_count = request.dummy_mask.size();

  if (n != request.dummy_mask.size()) {
    out.error_message = "Yao GC compare input size mismatch";
    return out;
  }

  if (request.compare_bits == 0 || request.compare_bits > 32) {
    out.error_message = "Yao GC compare currently supports compare_bits in [1,32]";
    return out;
  }

  if (request.evaluator_role != PartyRole::Receiver) {
    out.error_message = "The Yao evaluator must be the receiver";
    return out;
  }

  if (!ot_fn) {
    out.error_message = "Yao GC compare requires a valid OT callback";
    return out;
  }

  const std::uint64_t mask = BitMask(request.compare_bits);

  std::uint64_t rhs_constant_word = 0;
  bool use_constant_threshold = TryDerivePublicThresholdWord(request, mask, &rhs_constant_word);
  const bool use_modular_shares = request.lhs_share_modulus != 0;
  if (use_modular_shares && !use_constant_threshold) {
    out.error_message =
        "modular-share compare requires one public constant threshold";
    return out;
  }

  std::string cache_error;
  const CachedCircuitSpec* cached = use_modular_shares
      ? GetCachedModuloConstantCircuitSpec(request.compare_bits,
                                           request.lhs_share_modulus,
                                           rhs_constant_word,
                                           &cache_error)
      : (use_constant_threshold
             ? GetCachedConstantCircuitSpec(request.compare_bits,
                                            request.signed_compare,
                                            rhs_constant_word,
                                            &cache_error)
             : GetCachedGenericCircuitSpec(request.compare_bits,
                                           request.signed_compare,
                                           &cache_error));
  if (cached == nullptr) {
    out.error_message = cache_error.empty() ? "Yao GC circuit cache unavailable" : cache_error;
    return out;
  }

  const YaoCompareCircuitSpec& spec = cached->spec;
  out.stats.garbled_gate_count = spec.gates.size();
  out.stats.and_gate_count = cached->and_gate_count;
  out.stats.xor_gate_count =
      static_cast<std::size_t>(std::count_if(
          spec.gates.begin(), spec.gates.end(),
          [](const auto& gate) {
            return gate.kind == YaoGateKind::Xor;
          }));
  out.stats.wire_count = spec.wire_count;
  out.stats.input_bit_count =
      request.lhs_share_a.size() *
      (static_cast<std::size_t>(request.compare_bits) * 2 +
       (spec.has_b_valid_wire ? 1U : 0U));
  out.stats.output_bit_count = request.lhs_share_a.size();
  out.stats.used_constant_threshold_circuit = use_constant_threshold;
  out.stats.used_modular_share_circuit = use_modular_shares;

  struct CandidateWorkItem {
    std::size_t candidate_index = 0;
    std::size_t ot_flat_begin = 0;
    YaoLabel delta;
    std::vector<YaoLabelPair> wire_pairs;
    std::vector<YaoLabel> eval_labels;
    std::vector<GarbledAndGate> and_tables;
  };

  struct OtWireBinding {
    std::size_t work_item_index = 0;
    std::size_t wire_id = 0;
  };

  const auto now_ms = []() -> double {
    return std::chrono::duration<double, std::milli>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
  };

  const std::size_t b_input_count =
      spec.b_lhs_wires.size() +
      (use_constant_threshold ? 0 : spec.b_rhs_wires.size()) +
      (spec.has_b_valid_wire ? 1U : 0U);

  std::vector<CandidateWorkItem> work_items;
  work_items.reserve(n);

  std::vector<YaoLabelPair> all_b_wire_pairs;
  std::vector<std::uint8_t> all_b_choices;
  std::vector<OtWireBinding> all_b_wire_bindings;
  all_b_wire_pairs.reserve(n * b_input_count);
  all_b_choices.reserve(n * b_input_count);
  all_b_wire_bindings.reserve(n * b_input_count);

  std::vector<std::uint8_t> a_lhs_bits(static_cast<std::size_t>(request.compare_bits), 0);
  std::vector<std::uint8_t> a_rhs_bits(static_cast<std::size_t>(request.compare_bits), 0);
  std::vector<std::uint8_t> b_lhs_bits(static_cast<std::size_t>(request.compare_bits), 0);
  std::vector<std::uint8_t> b_rhs_bits(static_cast<std::size_t>(request.compare_bits), 0);

  const double prep_begin_ms = now_ms();

  for (std::size_t c = 0; c < n; ++c) {
    if (request.dummy_mask[c] != 0 && !spec.has_b_valid_wire) {
      out.final_match_bits[c] = 0;
      continue;
    }

    CandidateWorkItem item;
    item.candidate_index = c;
    item.ot_flat_begin = all_b_choices.size();
    item.wire_pairs.resize(spec.wire_count);
    item.eval_labels.resize(spec.wire_count);
    item.and_tables.resize(cached->and_gate_count);

    YaoLabelGenerator generator;
    item.delta = generator.Delta();
    for (std::size_t w = 0; w < spec.wire_count; ++w) {
      item.wire_pairs[w] = generator.MakeWireLabelPair();
    }

    const std::uint64_t lhs_b = static_cast<std::uint64_t>(request.lhs_share_b[c]) & mask;

    FillBits(lhs_b, request.compare_bits, &b_lhs_bits);

    for (std::size_t i = 0; i < spec.b_lhs_wires.size(); ++i) {
      all_b_wire_pairs.push_back(item.wire_pairs[spec.b_lhs_wires[i]]);
      all_b_choices.push_back(b_lhs_bits[i]);
      all_b_wire_bindings.push_back(
          OtWireBinding{work_items.size(), spec.b_lhs_wires[i]});
    }

    if (spec.has_b_valid_wire) {
      all_b_wire_pairs.push_back(item.wire_pairs[spec.b_valid_wire]);
      all_b_choices.push_back(request.dummy_mask[c] == 0 ? 1 : 0);
      all_b_wire_bindings.push_back(
          OtWireBinding{work_items.size(), spec.b_valid_wire});
    }

    if (!use_constant_threshold) {
      const std::uint64_t rhs_b = static_cast<std::uint64_t>(request.rhs_share_b[c]) & mask;

      FillBits(rhs_b, request.compare_bits, &b_rhs_bits);

      for (std::size_t i = 0; i < spec.b_rhs_wires.size(); ++i) {
        all_b_wire_pairs.push_back(item.wire_pairs[spec.b_rhs_wires[i]]);
        all_b_choices.push_back(b_rhs_bits[i]);
        all_b_wire_bindings.push_back(
            OtWireBinding{work_items.size(), spec.b_rhs_wires[i]});
      }
    }

    work_items.push_back(std::move(item));
  }

  // Count the two half-gate blocks actually allocated.
  for (const auto& item : work_items) {
    out.stats.garbled_table_bytes +=
        item.and_tables.size() * sizeof(YaoHalfGateTable);
  }
  out.stats.ot_label_count = all_b_choices.size();
  out.stats.ot_mode = request.ot_mode;
  out.stats.ot_correction_bytes =
      all_b_choices.size() * sizeof(YaoLabel) *
      ((request.ot_mode == "correlated") ? 1U : 2U);
  out.stats.ot_prepare_ms = now_ms() - prep_begin_ms;

  const double ot_begin_ms = now_ms();
  std::vector<YaoLabel> all_b_selected_labels;
  std::string ot_error;
  if (!ot_fn(&all_b_wire_pairs,
             all_b_choices,
             &all_b_selected_labels,
             &ot_error)) {
    out.error_message = "Yao GC OT failed: " + ot_error;
    return out;
  }
  out.stats.ot_transfer_ms = now_ms() - ot_begin_ms;

  if (all_b_wire_pairs.size() != all_b_wire_bindings.size()) {
    out.error_message = "Yao GC OT wire binding size mismatch";
    return out;
  }
  for (std::size_t i = 0; i < all_b_wire_bindings.size(); ++i) {
    const OtWireBinding& binding = all_b_wire_bindings[i];
    if (binding.work_item_index >= work_items.size() ||
        binding.wire_id >= work_items[binding.work_item_index].wire_pairs.size()) {
      out.error_message = "Yao GC OT wire binding index overflow";
      return out;
    }
    work_items[binding.work_item_index].wire_pairs[binding.wire_id] =
        all_b_wire_pairs[i];
  }

  const double garble_begin_ms = now_ms();
  for (CandidateWorkItem& item : work_items) {
    std::size_t gate_id = 0;
    std::size_t and_idx = 0;
    for (const auto& gate : spec.gates) {
      if (gate.kind == YaoGateKind::Xor) {
        item.wire_pairs[gate.out].zero =
            YaoXor(item.wire_pairs[gate.in0].zero,
                        item.wire_pairs[gate.in1].zero);
        item.wire_pairs[gate.out].one =
            YaoXor(item.wire_pairs[gate.out].zero, item.delta);
      } else {
        if (and_idx >= item.and_tables.size()) {
          out.error_message = "Yao GC internal AND table index overflow";
          return out;
        }

        GarbledAndGate& tbl = item.and_tables[and_idx++];
        tbl.in0 = gate.in0;
        tbl.in1 = gate.in1;
        tbl.out = gate.out;
        tbl.gate_id = gate_id;
        const auto garbled = GarbleYaoHalfGate(
            item.wire_pairs[gate.in0].zero, item.wire_pairs[gate.in1].zero,
            item.delta, item.candidate_index, gate_id);
        tbl.table = garbled.table;
        item.wire_pairs[gate.out].zero = garbled.output_zero;
        item.wire_pairs[gate.out].one = YaoXor(garbled.output_zero, item.delta);
      }
      ++gate_id;
    }

    const std::size_t c = item.candidate_index;
    FillBits(static_cast<std::uint64_t>(request.lhs_share_a[c]) & mask,
             request.compare_bits,
             &a_lhs_bits);
    std::string assign_err;
    if (!AssignInputWireLabels(spec.a_lhs_wires,
                               a_lhs_bits,
                               item.wire_pairs,
                               &item.eval_labels,
                               &assign_err)) {
      out.error_message = "Yao GC assign A labels failed: " + assign_err;
      return out;
    }
    if (!use_constant_threshold) {
      FillBits(static_cast<std::uint64_t>(request.rhs_share_a[c]) & mask,
               request.compare_bits,
               &a_rhs_bits);
      if (!AssignInputWireLabels(spec.a_rhs_wires,
                                 a_rhs_bits,
                                 item.wire_pairs,
                                 &item.eval_labels,
                                 &assign_err)) {
        out.error_message = "Yao GC assign A rhs labels failed: " + assign_err;
        return out;
      }
    }
  }
  out.stats.ot_prepare_ms += now_ms() - garble_begin_ms;

  if (all_b_selected_labels.size() != all_b_choices.size()) {
    out.error_message = "Yao GC OT returned unexpected label count";
    return out;
  }

  for (std::size_t i = 0; i < all_b_selected_labels.size(); ++i) {
    const YaoLabel expected = YaoSelect(all_b_wire_pairs[i], all_b_choices[i]);
    if (!YaoLabelEqual(all_b_selected_labels[i], expected)) {
      out.error_message = "GC OT label validation failed at index " + std::to_string(i);
      return out;
    }
  }

  const double eval_begin_ms = now_ms();

  for (std::size_t idx = 0; idx < work_items.size(); ++idx) {
    CandidateWorkItem& item = work_items[idx];

    std::size_t ot_off = item.ot_flat_begin;
    for (std::size_t i = 0; i < spec.b_lhs_wires.size(); ++i) {
      item.eval_labels[spec.b_lhs_wires[i]] = all_b_selected_labels[ot_off++];
    }
    if (spec.has_b_valid_wire) {
      item.eval_labels[spec.b_valid_wire] = all_b_selected_labels[ot_off++];
    }
    for (std::size_t i = 0; i < spec.b_rhs_wires.size(); ++i) {
      item.eval_labels[spec.b_rhs_wires[i]] = all_b_selected_labels[ot_off++];
    }

    item.eval_labels[spec.const_zero_wire] = item.wire_pairs[spec.const_zero_wire].zero;
    item.eval_labels[spec.const_one_wire] = item.wire_pairs[spec.const_one_wire].one;

    std::size_t gate_id = 0;
    std::size_t and_idx = 0;
    for (const auto& gate : spec.gates) {
      if (gate.kind == YaoGateKind::Xor) {
        item.eval_labels[gate.out] = YaoXor(item.eval_labels[gate.in0], item.eval_labels[gate.in1]);
      } else {
        if (and_idx >= item.and_tables.size()) {
          out.error_message = "Yao GC internal AND eval index overflow";
          return out;
        }
        const auto& tbl = item.and_tables[and_idx++];
        item.eval_labels[tbl.out] = EvaluateYaoHalfGate(
            item.eval_labels[tbl.in0], item.eval_labels[tbl.in1], tbl.table,
            item.candidate_index, gate_id);
      }
      ++gate_id;
    }

    const YaoLabel& out_label = item.eval_labels[spec.output_wire];
    if (YaoLabelEqual(out_label, item.wire_pairs[spec.output_wire].zero)) {
      out.final_match_bits[item.candidate_index] = 0;
    } else if (YaoLabelEqual(out_label, item.wire_pairs[spec.output_wire].one)) {
      out.final_match_bits[item.candidate_index] = 1;
    } else {
      out.error_message = "GC output label validation failed";
      return out;
    }
  }

  out.stats.ot_eval_ms = now_ms() - eval_begin_ms;

  if (request.protocol_context != nullptr) {
    request.protocol_context->LogEvent("comparison_online",
                                       "yao_compare_done",
                                       0,
                                       out.final_match_bits.size(),
                                       use_modular_shares
                                           ? "Yao comparison circuit batch complete (modular-share specialized)"
                                           : (use_constant_threshold
                                                  ? "Yao comparison circuit batch complete (const-threshold specialized)"
                                                  : "Yao comparison circuit batch complete (generic)"),
                                       PartyRole::Sender,
                                       PartyRole::Receiver);
  }

  out.ok = true;
  out.output_visible_to_evaluator_only = true;
  return out;
}

}  // namespace ctfpsi::stage3
