#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ctfpsi::stage3 {

enum class PartyRole {
  Sender = 1,
  Receiver = 2,
};

const char* PartyRoleToString(PartyRole role);
PartyRole CounterpartyOf(PartyRole role);

enum class ProtocolPhase {
  Setup = 1,
  PreprocessSetup = 2,
  OfflineMultiplication = 3,
  OnlineMultiplication = 4,
  LocalAggregation = 5,
  Normalization = 6,
  ComparisonSetup = 7,
  ComparisonOnline = 8,
  ComparisonOutput = 9,
};

const char* ProtocolPhaseToString(ProtocolPhase phase);

struct ProtocolMessage {
  std::string session_tag;
  PartyRole sender = PartyRole::Sender;
  PartyRole receiver = PartyRole::Receiver;
  ProtocolPhase phase = ProtocolPhase::Setup;
  std::string message_type;
  std::vector<std::uint8_t> payload;
  std::size_t element_count = 0;
};

std::string BuildTransportKey(const ProtocolMessage& message);

std::vector<std::uint8_t> EncodeRingVector(const std::vector<std::uint64_t>& values);
std::vector<std::uint64_t> DecodeRingVector(const std::vector<std::uint8_t>& payload);

}  // namespace ctfpsi::stage3


