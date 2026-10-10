#include "stage3/gc_backend_adapter.hpp"

#include <array>
#include <cstring>
#include <exception>
#include <string>
#include <vector>

#include "stage3/yao_compare.hpp"
#include "libOTe/config.h"
#include "libOTe/Base/BaseOT.h"
#include "libOTe/TwoChooseOne/Kos/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Kos/KosOtExtSender.h"
#include "coproto/Socket/LocalAsyncSock.h"
#include "macoro/sync_wait.h"
#include "macoro/when_all.h"

namespace ctfpsi::stage3 {
namespace {

bool IsGcCorrelatedOtEnabled() { return true; }
const char* SecureBaseOtBackendName() {
#if defined(ENABLE_SIMPLESTOT_ASM)
  return "libOTe::AsmSimplestOT";
#elif defined(ENABLE_MRR_TWIST)
  return "libOTe::McRosRoyTwist";
#elif defined(ENABLE_MR)
  return "libOTe::MasnyRindal";
#elif defined(ENABLE_MRR)
  return "libOTe::McRosRoy";
#elif defined(ENABLE_MR_KYBER)
  return "libOTe::MasnyRindalKyber";
#elif defined(ENABLE_SIMPLESTOT)
  return "libOTe::SimplestOT";
#else
  return "unavailable";
#endif
}

YaoLabel LabelFromBlock(const osuCrypto::block& b) {
  YaoLabel out;
  std::memcpy(out.bytes.data(), &b, out.bytes.size());
  return out;
}

osuCrypto::block BlockFromLabel(const YaoLabel& l) {
  osuCrypto::block out{};
  std::memcpy(&out, l.bytes.data(), l.bytes.size());
  return out;
}

bool RunLibOteKosLabelOt(std::vector<YaoLabelPair>* label_pairs,
                         const std::vector<std::uint8_t>& choices,
                         std::vector<YaoLabel>* chosen_labels,
                         std::string* error) {
#ifdef ENABLE_KOS
  if (label_pairs == nullptr || chosen_labels == nullptr) {
    if (error != nullptr) {
      *error = "GC OT input or output is null";
    }
    return false;
  }

  if (label_pairs->size() != choices.size()) {
    if (error != nullptr) {
      *error = "OT label pair size mismatch with choices";
    }
    return false;
  }

  if (label_pairs->empty()) {
    chosen_labels->clear();
    return true;
  }

  try {
    const bool correlated = IsGcCorrelatedOtEnabled();
    std::vector<osuCrypto::block> receiver_out(label_pairs->size());

    osuCrypto::BitVector choice_bits(choices.size());
    for (std::size_t i = 0; i < choices.size(); ++i) {
      choice_bits[i] = (choices[i] != 0);
    }

    osuCrypto::PRNG prng_sender(osuCrypto::sysRandomSeed());
    osuCrypto::PRNG prng_receiver(osuCrypto::sysRandomSeed());

    auto sockets = coproto::LocalAsyncSocket::makePair();
    osuCrypto::KosOtExtSender sender;
    osuCrypto::KosOtExtReceiver receiver;

#ifdef LIBOTE_HAS_BASE_OT
    // Run base OT over the two-party socket before KOS extension.
    auto receiver_base_task =
        receiver.genBaseOts(prng_receiver, sockets[0]);
    auto sender_base_task = sender.genBaseOts(prng_sender, sockets[1]);
    auto base_joined = macoro::sync_wait(macoro::when_all_ready(
        std::move(receiver_base_task), std::move(sender_base_task)));
    std::get<0>(base_joined).result();
    std::get<1>(base_joined).result();
#else
    if (error != nullptr) {
      *error =
          "libOTe KOS OT requires a secure base OT; rebuild libOTe with "
          "ENABLE_SIMPLESTOT=ON or another secure base-OT backend";
    }
    return false;
#endif

    std::vector<osuCrypto::block> correlated_zero;
    std::vector<osuCrypto::block> correlations;
    std::vector<std::array<osuCrypto::block, 2>> sender_msgs;

    if (correlated) {
      correlated_zero.resize(label_pairs->size());
      correlations.resize(label_pairs->size());
      for (std::size_t i = 0; i < label_pairs->size(); ++i) {
        correlations[i] =
            BlockFromLabel(YaoXor((*label_pairs)[i].zero,
                                       (*label_pairs)[i].one));
      }
      auto recv_task = receiver.receiveCorrelated(
          choice_bits, receiver_out, prng_receiver, sockets[0]);
      // sendCorrelated stores the callback by reference in its lazy coroutine,
      // so the callback must outlive the task and the following sync_wait.
      const auto correlation_fn =
          [&correlations](const osuCrypto::block& zero,
                          osuCrypto::u64 index) {
            return zero ^ correlations[static_cast<std::size_t>(index)];
          };
      auto send_task = sender.sendCorrelated(
          correlated_zero,
          correlation_fn,
          prng_sender,
          sockets[1]);
      auto joined = macoro::sync_wait(
          macoro::when_all_ready(std::move(recv_task), std::move(send_task)));
      std::get<0>(joined).result();
      std::get<1>(joined).result();
    } else {
      sender_msgs.resize(label_pairs->size());
      for (std::size_t i = 0; i < label_pairs->size(); ++i) {
        sender_msgs[i][0] = BlockFromLabel((*label_pairs)[i].zero);
        sender_msgs[i][1] = BlockFromLabel((*label_pairs)[i].one);
      }
      auto recv_task = receiver.receiveChosen(
          choice_bits, receiver_out, prng_receiver, sockets[0]);
      auto send_task = sender.sendChosen(
          sender_msgs, prng_sender, sockets[1]);
      auto joined = macoro::sync_wait(
          macoro::when_all_ready(std::move(recv_task), std::move(send_task)));
      std::get<0>(joined).result();
      std::get<1>(joined).result();
    }

    if (correlated) {
      for (std::size_t i = 0; i < label_pairs->size(); ++i) {
        (*label_pairs)[i].zero = LabelFromBlock(correlated_zero[i]);
        (*label_pairs)[i].one =
            LabelFromBlock(correlated_zero[i] ^ correlations[i]);
      }
    }

    chosen_labels->resize(receiver_out.size());
    for (std::size_t i = 0; i < receiver_out.size(); ++i) {
      (*chosen_labels)[i] = LabelFromBlock(receiver_out[i]);
    }

    return true;
  } catch (const std::exception& ex) {
    if (error != nullptr) {
      *error = std::string("libOTe KOS OT exception: ") + ex.what();
    }
    return false;
  }
#else
  if (error != nullptr) {
    *error = "ENABLE_KOS is not enabled in installed libOTe";
  }
  return false;
#endif
}

}  // namespace

BatchedCompareResult BatchedYaoBackend::Compare(const BatchedCompareRequest& request) const {
  YaoCompareRequest input;
  input.lhs_share_a = request.lhs_shares.party0;
  input.lhs_share_b = request.lhs_shares.party1;
  input.rhs_share_a = request.rhs_shares.party0;
  input.rhs_share_b = request.rhs_shares.party1;
  input.dummy_mask = request.dummy_mask;
  input.compare_bits = request.compare_bits;
  input.signed_compare = request.signed_compare;
  input.lhs_share_modulus = request.lhs_share_modulus;
  input.session_tag = request.session_tag;
  input.protocol_context = request.protocol_context;
  input.evaluator_role = request.evaluator_role;
  input.ot_mode = "correlated";
  const auto evaluated = RunYaoBatchedCompare(input, RunLibOteKosLabelOt);
  BatchedCompareResult output;
  output.backend_used = "Yao half-gates with libOTe";
  output.ok = evaluated.ok;
  output.error_message = evaluated.error_message;
  output.final_match_bits = evaluated.final_match_bits;
  output.output_visible_to_evaluator_only = evaluated.output_visible_to_evaluator_only;
  output.compare_gate_count = evaluated.stats.garbled_gate_count;
  output.compare_and_gate_count = evaluated.stats.and_gate_count;
  output.compare_xor_gate_count = evaluated.stats.xor_gate_count;
  output.compare_wire_count = evaluated.stats.wire_count;
  output.compare_input_bit_count = evaluated.stats.input_bit_count;
  output.compare_output_bit_count = evaluated.stats.output_bit_count;
  output.compare_ot_count = evaluated.stats.ot_label_count;
  output.compare_garbled_table_bytes = evaluated.stats.garbled_table_bytes;
  output.compare_used_constant_threshold_circuit = evaluated.stats.used_constant_threshold_circuit;
  output.compare_used_modular_share_circuit = evaluated.stats.used_modular_share_circuit;
  output.compare_ot_prepare_ms = evaluated.stats.ot_prepare_ms;
  output.compare_ot_transfer_ms = evaluated.stats.ot_transfer_ms;
  output.compare_ot_eval_ms = evaluated.stats.ot_eval_ms;
  output.compare_ot_mode = evaluated.stats.ot_mode;
  output.compare_secure_base_ot_used = evaluated.ok;
  output.compare_base_ot_backend = SecureBaseOtBackendName();
  output.compare_ot_correction_bytes = evaluated.stats.ot_correction_bytes;
  output.gc_batch_count = evaluated.ok ? 1 : 0;
  output.ot_setup_count = evaluated.ok ? 1 : 0;
  output.setup_message_count = evaluated.ok ? 1 : 0;
  output.online_message_count = evaluated.ok ? 1 : 0;
  output.message_count_total = output.setup_message_count + output.online_message_count;
  return output;
}

}  // namespace ctfpsi::stage3
