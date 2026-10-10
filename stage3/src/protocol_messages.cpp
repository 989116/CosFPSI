#include "stage3/protocol_messages.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ctfpsi::stage3 {

const char* PartyRoleToString(PartyRole role) {
  switch (role) {
    case PartyRole::Sender:
      return "Sender";
    case PartyRole::Receiver:
      return "Receiver";
    default:
      return "UnknownParty";
  }
}

PartyRole CounterpartyOf(PartyRole role) {
  return (role == PartyRole::Sender) ? PartyRole::Receiver : PartyRole::Sender;
}

const char* ProtocolPhaseToString(ProtocolPhase phase) {
  switch (phase) {
    case ProtocolPhase::Setup:
      return "setup";
    case ProtocolPhase::PreprocessSetup:
      return "preprocess_setup";
    case ProtocolPhase::OfflineMultiplication:
      return "offline_multiplication";
    case ProtocolPhase::OnlineMultiplication:
      return "online_multiplication";
    case ProtocolPhase::LocalAggregation:
      return "local_aggregation";
    case ProtocolPhase::Normalization:
      return "normalization";
    case ProtocolPhase::ComparisonSetup:
      return "comparison_setup";
    case ProtocolPhase::ComparisonOnline:
      return "comparison_online";
    case ProtocolPhase::ComparisonOutput:
      return "comparison_output";
    default:
      return "unknown_phase";
  }
}

std::string BuildTransportKey(const ProtocolMessage& message) {
  return message.session_tag + "|" +
         std::string(PartyRoleToString(message.sender)) + "->" +
         std::string(PartyRoleToString(message.receiver)) + "|" +
         std::string(ProtocolPhaseToString(message.phase)) + "|" +
         message.message_type;
}

std::vector<std::uint8_t> EncodeRingVector(const std::vector<std::uint64_t>& values) {
  std::vector<std::uint8_t> payload;
  payload.resize(values.size() * sizeof(std::uint64_t));

  std::size_t offset = 0;
  for (std::uint64_t value : values) {
    for (std::size_t b = 0; b < sizeof(std::uint64_t); ++b) {
      payload[offset + b] = static_cast<std::uint8_t>((value >> (8 * b)) & 0xFFu);
    }
    offset += sizeof(std::uint64_t);
  }

  return payload;
}

std::vector<std::uint64_t> DecodeRingVector(const std::vector<std::uint8_t>& payload) {
  if (payload.size() % sizeof(std::uint64_t) != 0) {
    return {};
  }

  const std::size_t n = payload.size() / sizeof(std::uint64_t);
  std::vector<std::uint64_t> values(n, 0);

  std::size_t offset = 0;
  for (std::size_t i = 0; i < n; ++i) {
    std::uint64_t value = 0;
    for (std::size_t b = 0; b < sizeof(std::uint64_t); ++b) {
      value |= (static_cast<std::uint64_t>(payload[offset + b]) << (8 * b));
    }
    values[i] = value;
    offset += sizeof(std::uint64_t);
  }

  return values;
}

}  // namespace ctfpsi::stage3


