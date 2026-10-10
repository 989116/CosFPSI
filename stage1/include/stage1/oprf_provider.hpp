#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "common/types.hpp"

namespace ctfpsi::stage1 {

enum class OprfImplementation {
  EcOprf,
};

const char* OprfImplementationToString(OprfImplementation impl);

struct EcOprfBlindRequest {
  std::vector<std::uint8_t> blinded_point_bytes;
};

struct EcOprfBlindState {
  std::array<std::uint8_t, 32> blind_scalar_bytes{};
};

struct EcOprfEvaluatedResponse {
  std::vector<std::uint8_t> evaluated_point_bytes;
};

struct OprfSessionStats {
  std::size_t session_setup_count = 0;
  std::size_t server_key_generation_count = 0;
  std::size_t batch_call_count = 0;
  std::size_t total_point_count = 0;
  std::size_t scalar_call_count = 0;
  std::uint64_t blind_request_serialized_bytes = 0;
  std::uint64_t evaluated_response_serialized_bytes = 0;
};

class OprfProvider {
 public:
  virtual ~OprfProvider() = default;

  virtual common::ByteBlock EvaluateServer(const common::BinaryFingerprint& input_bits) const = 0;
  virtual common::ByteBlock EvaluateClient(const common::BinaryFingerprint& input_bits) const = 0;
  virtual bool EvaluateServerBatch(
      const std::vector<common::BinaryFingerprint>& inputs,
      std::vector<common::ByteBlock>* outputs,
      std::string* error) const = 0;
  virtual bool EvaluateClientBatch(
      const std::vector<common::BinaryFingerprint>& inputs,
      std::vector<common::ByteBlock>* outputs,
      std::string* error) const = 0;
  virtual OprfSessionStats SessionStats() const = 0;
  virtual OprfImplementation Implementation() const = 0;
};

class EcOprfProvider final : public OprfProvider {
 public:
  EcOprfProvider();

  common::ByteBlock EvaluateServer(const common::BinaryFingerprint& input_bits) const override;
  common::ByteBlock EvaluateClient(const common::BinaryFingerprint& input_bits) const override;
  bool EvaluateServerBatch(
      const std::vector<common::BinaryFingerprint>& inputs,
      std::vector<common::ByteBlock>* outputs,
      std::string* error) const override;
  bool EvaluateClientBatch(
      const std::vector<common::BinaryFingerprint>& inputs,
      std::vector<common::ByteBlock>* outputs,
      std::string* error) const override;
  OprfSessionStats SessionStats() const override;
  OprfImplementation Implementation() const override;
  bool ClientBlindInput(const common::BinaryFingerprint& input_bits,
                        EcOprfBlindRequest* request,
                        EcOprfBlindState* state,
                        std::string* error) const;
  bool ClientBlindBatch(
      const std::vector<common::BinaryFingerprint>& inputs,
      std::vector<EcOprfBlindRequest>* requests,
      std::vector<EcOprfBlindState>* states,
      std::string* error) const;
  bool ServerEvaluateBlindedPoint(const EcOprfBlindRequest& request,
                                  EcOprfEvaluatedResponse* response,
                                  std::string* error) const;
  bool ServerEvaluateBatch(
      const std::vector<EcOprfBlindRequest>& requests,
      std::vector<EcOprfEvaluatedResponse>* responses,
      std::string* error) const;
  bool ClientUnblindAndDeriveKey(const EcOprfBlindState& state,
                                 const EcOprfEvaluatedResponse& response,
                                 common::ByteBlock* out,
                                 std::string* error) const;
  bool ClientFinalizeBatch(
      const std::vector<EcOprfBlindState>& states,
      const std::vector<EcOprfEvaluatedResponse>& responses,
      std::vector<common::ByteBlock>* outputs,
      std::string* error) const;

 private:
  struct Session;

  std::shared_ptr<Session> session_;
};

}  // namespace ctfpsi::stage1
