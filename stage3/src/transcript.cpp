#include "stage3/transcript.hpp"

#include <chrono>
#include <utility>

namespace ctfpsi::stage3 {
namespace {

std::uint64_t NowMicros() {
  using clock = std::chrono::steady_clock;
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::microseconds>(clock::now().time_since_epoch()).count());
}

}  // namespace

std::string InMemoryTranscript::Name() const {
  return "InMemoryTranscript";
}

void InMemoryTranscript::ResetSession(const std::string& session_tag) {
  session_tag_ = session_tag;
  sequence_ = 0;
  events_.clear();
}

void InMemoryTranscript::LogEvent(TranscriptEvent event) {
  event.sequence = ++sequence_;
  if (event.timestamp_us == 0) {
    event.timestamp_us = NowMicros();
  }
  if (event.session_tag.empty()) {
    event.session_tag = session_tag_;
  }
  events_.push_back(std::move(event));
}

std::size_t InMemoryTranscript::EventCount() const {
  return events_.size();
}

std::vector<TranscriptEvent> InMemoryTranscript::GetEvents() const {
  return events_;
}

}  // namespace ctfpsi::stage3


