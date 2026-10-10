#include "stage3/protocol_context.hpp"

#include <utility>

namespace ctfpsi::stage3 {

void ProtocolContext::ResetSession() {
  if (transport != nullptr) {
    transport->ResetSession(session_tag);
  }
  if (transcript != nullptr) {
    transcript->ResetSession(session_tag);
  }
}

std::string ProtocolContext::TransportBackendName() const {
  if (transport == nullptr) {
    return "NoTransport";
  }
  return transport->Name();
}

std::size_t ProtocolContext::TranscriptEventCount() const {
  if (transcript == nullptr) {
    return 0;
  }
  return transcript->EventCount();
}

void ProtocolContext::LogEvent(const std::string& phase_name,
                               const std::string& message_type,
                               std::size_t payload_size,
                               std::size_t element_count,
                               const std::string& note,
                               PartyRole actor_role,
                               PartyRole peer_role) {
  if (transcript == nullptr) {
    return;
  }

  transcript->LogEvent(TranscriptEvent{
      0,
      0,
      session_tag,
      phase_name,
      message_type,
      note,
      payload_size,
      element_count,
      PartyRoleToString(actor_role),
      PartyRoleToString(peer_role),
  });
}

void ProtocolContext::SendMessage(const ProtocolMessage& message, const std::string& note) {
  if (transport != nullptr) {
    transport->Send(BuildTransportKey(message), message.payload);
  }
  LogEvent(ProtocolPhaseToString(message.phase),
           "send:" + message.message_type,
           message.payload.size(),
           message.element_count,
           note,
           message.sender,
           message.receiver);
}

ProtocolMessage ProtocolContext::ReceiveMessage(const ProtocolMessage& probe,
                                                const std::string& note) {
  ProtocolMessage out = probe;
  if (transport != nullptr) {
    out.payload = transport->Receive(BuildTransportKey(probe));
  }

  LogEvent(ProtocolPhaseToString(probe.phase),
           "recv:" + probe.message_type,
           out.payload.size(),
           probe.element_count,
           note,
           probe.receiver,
           probe.sender);
  return out;
}

}  // namespace ctfpsi::stage3


