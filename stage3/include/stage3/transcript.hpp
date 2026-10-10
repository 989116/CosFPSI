#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ctfpsi::stage3 {

struct TranscriptEvent {
  std::size_t sequence = 0;
  std::uint64_t timestamp_us = 0;

  std::string session_tag;
  std::string phase_name;
  std::string message_type;
  std::string note;

  std::size_t payload_size = 0;
  std::size_t element_count = 0;

  std::string actor_role;
  std::string peer_role;
};

class Transcript {
 public:
  virtual ~Transcript() = default;

  virtual std::string Name() const = 0;
  virtual void ResetSession(const std::string& session_tag) = 0;
  virtual void LogEvent(TranscriptEvent event) = 0;
  virtual std::size_t EventCount() const = 0;
  virtual std::vector<TranscriptEvent> GetEvents() const = 0;
};

class InMemoryTranscript final : public Transcript {
 public:
  std::string Name() const override;
  void ResetSession(const std::string& session_tag) override;
  void LogEvent(TranscriptEvent event) override;
  std::size_t EventCount() const override;
  std::vector<TranscriptEvent> GetEvents() const override;

 private:
  std::string session_tag_;
  std::size_t sequence_ = 0;
  std::vector<TranscriptEvent> events_;
};

}  // namespace ctfpsi::stage3


