#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "stage3/yao_circuit_spec.hpp"
#include "stage3/yao_labels.hpp"
#include "stage3/protocol_context.hpp"
#include "stage3/score_sharing.hpp"

namespace ctfpsi::stage3 {

struct YaoCompareRequest {
  std::vector<RingElem> lhs_share_a;
  std::vector<RingElem> lhs_share_b;
  std::vector<RingElem> rhs_share_a;
  std::vector<RingElem> rhs_share_b;
  std::vector<std::uint8_t> dummy_mask;

  std::uint32_t compare_bits = 32;
  bool signed_compare = true;

  // Zero preserves the existing Z_(2^compare_bits) share semantics. A
  // nonzero value selects the fixed modular-share circuit:
  // center((lhs_share_a + lhs_share_b) mod lhs_share_modulus) >= rhs.
  std::uint64_t lhs_share_modulus = 0;

  std::string session_tag;
  ProtocolContext* protocol_context = nullptr;
  PartyRole evaluator_role = PartyRole::Receiver;
  std::string ot_mode = "chosen";
};

struct YaoCompareStats {
  std::size_t candidate_count = 0;
  std::size_t garbled_gate_count = 0;
  std::size_t and_gate_count = 0;
  std::size_t xor_gate_count = 0;
  std::size_t wire_count = 0;
  std::size_t ot_label_count = 0;
  std::size_t input_bit_count = 0;
  std::size_t output_bit_count = 0;
  std::size_t garbled_table_bytes = 0;
  std::size_t message_count = 0;
  bool used_constant_threshold_circuit = false;
  bool used_modular_share_circuit = false;
  double ot_prepare_ms = 0.0;
  double ot_transfer_ms = 0.0;
  double ot_eval_ms = 0.0;
  std::string ot_mode = "chosen";
  std::size_t ot_correction_bytes = 0;
};

struct YaoCompareResult {
  bool ok = false;
  std::string error_message;
  std::vector<std::uint8_t> final_match_bits;
  bool output_visible_to_evaluator_only = true;
  YaoCompareStats stats;
};

using YaoOtFn = std::function<bool(std::vector<YaoLabelPair>* label_pairs,
                                        const std::vector<std::uint8_t>& choices,
                                        std::vector<YaoLabel>* chosen_labels,
                                        std::string* error)>;

YaoCompareResult RunYaoBatchedCompare(const YaoCompareRequest& request,
                                                const YaoOtFn& ot_fn);

}  // namespace ctfpsi::stage3


