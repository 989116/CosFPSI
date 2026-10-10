#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "stage3/protocol_context.hpp"
#include "stage3/score_sharing.hpp"

namespace ctfpsi::stage3 {

struct BatchedCompareRequest {
  AdditiveShares lhs_shares;
  AdditiveShares rhs_shares;
  std::vector<std::uint8_t> dummy_mask;
  std::uint32_t compare_bits = 32;
  bool signed_compare = true;
  std::uint64_t lhs_share_modulus = 0;
  std::string session_tag;
  ProtocolContext* protocol_context = nullptr;
  PartyRole evaluator_role = PartyRole::Receiver;
};

struct BatchedCompareResult {
  bool ok = false;
  std::string backend_used;
  std::string error_message;
  std::vector<std::uint8_t> final_match_bits;
  bool output_visible_to_evaluator_only = false;
  std::size_t message_count_total = 0;
  std::size_t setup_message_count = 0;
  std::size_t online_message_count = 0;
  std::size_t party_a_event_count = 0;
  std::size_t party_b_event_count = 0;
  std::size_t compare_gate_count = 0;
  std::size_t compare_and_gate_count = 0;
  std::size_t compare_xor_gate_count = 0;
  std::size_t compare_wire_count = 0;
  std::size_t compare_input_bit_count = 0;
  std::size_t compare_output_bit_count = 0;
  std::size_t compare_ot_count = 0;
  std::size_t compare_garbled_table_bytes = 0;
  bool compare_used_constant_threshold_circuit = false;
  bool compare_used_modular_share_circuit = false;
  double compare_ot_prepare_ms = 0.0;
  double compare_ot_transfer_ms = 0.0;
  double compare_ot_eval_ms = 0.0;
  std::string compare_ot_mode = "correlated";
  bool compare_secure_base_ot_used = false;
  std::string compare_base_ot_backend = "unavailable";
  std::size_t compare_ot_correction_bytes = 0;
  std::size_t gc_batch_count = 0;
  std::size_t ot_setup_count = 0;
};

class BatchedComparisonBackend {
 public:
  virtual ~BatchedComparisonBackend() = default;
  virtual BatchedCompareResult Compare(const BatchedCompareRequest& request) const = 0;
};

}  // namespace ctfpsi::stage3

