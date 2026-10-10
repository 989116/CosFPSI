#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "stage3/protocol_messages.hpp"
#include "stage3/transcript.hpp"
#include "stage3/transport.hpp"

namespace ctfpsi::stage3 {

struct ProtocolContext {
  std::string session_tag;
  PartyRole party_role = PartyRole::Sender;
  Transport* transport = nullptr;
  Transcript* transcript = nullptr;
  bool verbose = false;

  void ResetSession();

  std::string TransportBackendName() const;
  std::size_t TranscriptEventCount() const;

  void LogEvent(const std::string& phase_name,
                const std::string& message_type,
                std::size_t payload_size,
                std::size_t element_count,
                const std::string& note = "",
                PartyRole actor_role = PartyRole::Sender,
                PartyRole peer_role = PartyRole::Receiver);

  void SendMessage(const ProtocolMessage& message, const std::string& note = "");

  ProtocolMessage ReceiveMessage(const ProtocolMessage& probe,
                                 const std::string& note = "");
};

}  // namespace ctfpsi::stage3


