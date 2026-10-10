#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <string>
#include <unordered_map>
#include <vector>

namespace ctfpsi::stage3 {

class Transport {
 public:
  virtual ~Transport() = default;

  virtual std::string Name() const = 0;
  virtual void ResetSession(const std::string& session_tag) = 0;
  virtual void Send(const std::string& message_type, const std::vector<std::uint8_t>& payload) = 0;
  virtual std::vector<std::uint8_t> Receive(const std::string& message_type) = 0;
};

class LoopbackTransport final : public Transport {
 public:
  std::string Name() const override;
  void ResetSession(const std::string& session_tag) override;
  void Send(const std::string& message_type, const std::vector<std::uint8_t>& payload) override;
  std::vector<std::uint8_t> Receive(const std::string& message_type) override;

  std::size_t PendingCount(const std::string& message_type) const;

 private:
  std::string session_tag_;
  std::unordered_map<std::string, std::deque<std::vector<std::uint8_t>>> inbox_;
};

}  // namespace ctfpsi::stage3


