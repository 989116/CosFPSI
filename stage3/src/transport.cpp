#include "stage3/transport.hpp"

#include <utility>

namespace ctfpsi::stage3 {

std::string LoopbackTransport::Name() const {
  return "LoopbackTransport";
}

void LoopbackTransport::ResetSession(const std::string& session_tag) {
  session_tag_ = session_tag;
  inbox_.clear();
}

void LoopbackTransport::Send(const std::string& message_type, const std::vector<std::uint8_t>& payload) {
  inbox_[message_type].push_back(payload);
}

std::vector<std::uint8_t> LoopbackTransport::Receive(const std::string& message_type) {
  auto it = inbox_.find(message_type);
  if (it == inbox_.end() || it->second.empty()) {
    return {};
  }

  std::vector<std::uint8_t> payload = std::move(it->second.front());
  it->second.pop_front();
  if (it->second.empty()) {
    inbox_.erase(it);
  }
  return payload;
}

std::size_t LoopbackTransport::PendingCount(const std::string& message_type) const {
  auto it = inbox_.find(message_type);
  if (it == inbox_.end()) {
    return 0;
  }
  return it->second.size();
}

}  // namespace ctfpsi::stage3


