#include "stage1/oprf_provider.hpp"
#include "stage1/p256_hash_to_curve.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <thread>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

namespace ctfpsi::stage1 {
namespace {

std::vector<std::uint8_t> FingerprintToBytes(const common::BinaryFingerprint& bits) {
  std::vector<std::uint8_t> out;
  out.reserve(8 + bits.size());
  const std::uint64_t n = static_cast<std::uint64_t>(bits.size());
  for (std::size_t i = 0; i < 8; ++i) {
    out.push_back(static_cast<std::uint8_t>((n >> (8 * i)) & 0xFFU));
  }
  for (bool b : bits) {
    out.push_back(static_cast<std::uint8_t>(b ? 1U : 0U));
  }
  return out;
}

bool BytesToPoint(const EC_GROUP* group,
                  const std::vector<std::uint8_t>& bytes,
                  EC_POINT* out,
                  BN_CTX* bn_ctx,
                  std::string* error) {
  if (bytes.size() != 33 || (bytes[0] != 2 && bytes[0] != 3)) {
    if (error != nullptr) {
      *error = "invalid compressed P-256 point encoding";
    }
    return false;
  }
  if (EC_POINT_oct2point(group, out, bytes.data(), bytes.size(), bn_ctx) != 1 ||
      EC_POINT_is_at_infinity(group, out) ||
      EC_POINT_is_on_curve(group, out, bn_ctx) != 1) {
    if (error != nullptr) {
      *error = "EC_POINT_oct2point failed";
    }
    return false;
  }
  return true;
}

bool PointToBytes(const EC_GROUP* group,
                  const EC_POINT* point,
                  std::vector<std::uint8_t>* out,
                  BN_CTX* bn_ctx,
                  std::string* error) {
  const size_t len = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, nullptr, 0, bn_ctx);
  if (len == 0) {
    if (error != nullptr) {
      *error = "EC_POINT_point2oct size query failed";
    }
    return false;
  }
  out->assign(len, 0);
  if (EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, out->data(), out->size(), bn_ctx) != len) {
    if (error != nullptr) {
      *error = "EC_POINT_point2oct encode failed";
    }
    return false;
  }
  return true;
}

bool MapInputToCurvePoint(const EC_GROUP* group,
                          const common::BinaryFingerprint& bits,
                          EC_POINT* out, BN_CTX* bn_ctx, std::string* error) {
  static constexpr char domain[] = "HashToGroup-OPRFV1-\x00-P256-SHA256";
  static const std::vector<std::uint8_t> dst(domain, domain + sizeof(domain) - 1);
  if (!HashToCurveP256(group, FingerprintToBytes(bits), dst, out, bn_ctx, error)) return false;
  if (EC_POINT_is_at_infinity(group, out)) {
    if (error) *error = "OPRF input maps to the identity element";
    return false;
  }
  return true;
}

common::ByteBlock DeriveOutputKeyFromPoint(const EC_GROUP* group,
                                           const EC_POINT* point,
                                           BN_CTX* bn_ctx,
                                           std::string* error) {
  common::ByteBlock out{};
  std::vector<std::uint8_t> point_bytes;

  if (!PointToBytes(group, point, &point_bytes, bn_ctx, error)) {
    return out;
  }

  std::array<std::uint8_t, 32> digest{};
  SHA256_CTX sha;
  SHA256_Init(&sha);
  SHA256_Update(&sha, point_bytes.data(), point_bytes.size());
  static const char kDomain[] = "CTFPSI_EC_OPRF_KEY_DERIVE";
  SHA256_Update(&sha, kDomain, sizeof(kDomain));
  SHA256_Final(digest.data(), &sha);

  std::copy_n(digest.begin(), out.size(), out.begin());
  return out;
}

bool GenerateRandomNonZeroScalar(const BIGNUM* order,
                                 BIGNUM* out,
                                 std::string* error) {
  if (order == nullptr || out == nullptr) {
    if (error != nullptr) {
      *error = "invalid scalar generation arguments";
    }
    return false;
  }
  do {
    if (BN_priv_rand_range(out, order) != 1) {
      if (error != nullptr) {
        *error = "BN_priv_rand_range failed";
      }
      return false;
    }
  } while (BN_is_zero(out));
  return true;
}

bool BlindOne(const EC_GROUP* group,
              BN_CTX* bn_ctx,
              const BIGNUM* order,
              const common::BinaryFingerprint& input_bits,
              EcOprfBlindRequest* request,
              EcOprfBlindState* state,
              std::string* error) {
  BIGNUM* blind = BN_new();
  EC_POINT* h_point = EC_POINT_new(group);
  EC_POINT* blinded = EC_POINT_new(group);
  bool ok =
      blind != nullptr && h_point != nullptr && blinded != nullptr;

  if (ok) {
    ok = GenerateRandomNonZeroScalar(order, blind, error) &&
         MapInputToCurvePoint(
             group, input_bits, h_point, bn_ctx, error) &&
         EC_POINT_mul(
             group, blinded, nullptr, h_point, blind, bn_ctx) == 1;
    if (!ok && error != nullptr && error->empty()) {
      *error = "client blinding EC_POINT_mul failed";
    }
  }
  if (ok) {
    ok = PointToBytes(
        group, blinded, &request->blinded_point_bytes, bn_ctx, error);
  }
  if (ok) {
    ok = BN_bn2binpad(
             blind,
             state->blind_scalar_bytes.data(),
             static_cast<int>(state->blind_scalar_bytes.size())) ==
         static_cast<int>(state->blind_scalar_bytes.size());
    if (!ok && error != nullptr) {
      *error = "BN_bn2binpad(blind) failed";
    }
  }

  EC_POINT_free(blinded);
  EC_POINT_free(h_point);
  BN_clear_free(blind);
  return ok;
}

bool EvaluateBlindedOne(const EC_GROUP* group,
                        BN_CTX* bn_ctx,
                        const BIGNUM* server_scalar,
                        const EcOprfBlindRequest& request,
                        EcOprfEvaluatedResponse* response,
                        std::string* error) {
  EC_POINT* blinded = EC_POINT_new(group);
  EC_POINT* evaluated = EC_POINT_new(group);
  bool ok = blinded != nullptr && evaluated != nullptr;
  if (ok) {
    ok = BytesToPoint(
             group, request.blinded_point_bytes, blinded, bn_ctx, error) &&
         EC_POINT_mul(
             group,
             evaluated,
             nullptr,
             blinded,
             server_scalar,
             bn_ctx) == 1;
    if (!ok && error != nullptr && error->empty()) {
      *error = "server evaluate EC_POINT_mul failed";
    }
  }
  if (ok) {
    ok = PointToBytes(
        group, evaluated, &response->evaluated_point_bytes, bn_ctx, error);
  }
  EC_POINT_free(evaluated);
  EC_POINT_free(blinded);
  return ok;
}

bool FinalizeOne(const EC_GROUP* group,
                 BN_CTX* bn_ctx,
                 const BIGNUM* order,
                 const EcOprfBlindState& state,
                 const EcOprfEvaluatedResponse& response,
                 common::ByteBlock* out,
                 std::string* error) {
  BIGNUM* blind = BN_new();
  BIGNUM* blind_inv = BN_new();
  EC_POINT* evaluated = EC_POINT_new(group);
  EC_POINT* unblinded = EC_POINT_new(group);
  bool ok = blind != nullptr && blind_inv != nullptr &&
            evaluated != nullptr && unblinded != nullptr;

  if (ok &&
      BN_bin2bn(
          state.blind_scalar_bytes.data(),
          static_cast<int>(state.blind_scalar_bytes.size()),
          blind) == nullptr) {
    ok = false;
    if (error != nullptr) {
      *error = "BN_bin2bn(blind) failed";
    }
  }
  if (ok && BN_mod_inverse(blind_inv, blind, order, bn_ctx) == nullptr) {
    ok = false;
    if (error != nullptr) {
      *error = "BN_mod_inverse failed";
    }
  }
  if (ok) {
    ok = BytesToPoint(
        group, response.evaluated_point_bytes, evaluated, bn_ctx, error);
  }
  if (ok &&
      EC_POINT_mul(
          group, unblinded, nullptr, evaluated, blind_inv, bn_ctx) != 1) {
    ok = false;
    if (error != nullptr && error->empty()) {
      *error = "client unblind EC_POINT_mul failed";
    }
  }
  if (ok) {
    *out = DeriveOutputKeyFromPoint(group, unblinded, bn_ctx, error);
  }

  EC_POINT_free(unblinded);
  EC_POINT_free(evaluated);
  BN_clear_free(blind_inv);
  BN_clear_free(blind);
  return ok;
}

bool EvaluateServerOne(const EC_GROUP* group,
                       BN_CTX* bn_ctx,
                       const BIGNUM* server_scalar,
                       const common::BinaryFingerprint& input_bits,
                       common::ByteBlock* out,
                       std::string* error) {
  EC_POINT* h_point = EC_POINT_new(group);
  EC_POINT* y_point = EC_POINT_new(group);
  bool ok = h_point != nullptr && y_point != nullptr;
  if (ok) {
    ok = MapInputToCurvePoint(
             group, input_bits, h_point, bn_ctx, error) &&
         EC_POINT_mul(
             group, y_point, nullptr, h_point, server_scalar, bn_ctx) == 1;
    if (!ok && error != nullptr && error->empty()) {
      *error = "server EC_POINT_mul failed";
    }
  }
  if (ok) {
    *out = DeriveOutputKeyFromPoint(group, y_point, bn_ctx, error);
  }
  EC_POINT_free(y_point);
  EC_POINT_free(h_point);
  return ok;
}

struct EcBatchWorkerContext {
  EcBatchWorkerContext(const EC_GROUP* base_group,
                       const BIGNUM* base_order,
                       const BIGNUM* base_server_scalar)
      : group(EC_GROUP_dup(base_group)),
        bn_ctx(BN_CTX_new()),
        order(BN_dup(base_order)),
        server_scalar(BN_dup(base_server_scalar)) {}

  ~EcBatchWorkerContext() {
    BN_clear_free(server_scalar);
    BN_free(order);
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
  }

  bool Ready() const {
    return group != nullptr && bn_ctx != nullptr && order != nullptr &&
           server_scalar != nullptr;
  }

  EC_GROUP* group = nullptr;
  BN_CTX* bn_ctx = nullptr;
  BIGNUM* order = nullptr;
  BIGNUM* server_scalar = nullptr;
};

std::size_t EcBatchWorkerCount(std::size_t point_count) {
  if (point_count < 32) return 1;
  const std::size_t hardware_threads = std::max<std::size_t>(
      1, static_cast<std::size_t>(std::thread::hardware_concurrency()));
  return std::min<std::size_t>({point_count, hardware_threads, 16});
}

template <typename PointFunction>
bool RunParallelEcBatch(std::size_t point_count,
                        const EC_GROUP* base_group,
                        const BIGNUM* base_order,
                        const BIGNUM* base_server_scalar,
                        PointFunction&& process_point,
                        std::string* error) {
  if (point_count == 0) return true;
  const std::size_t worker_count = EcBatchWorkerCount(point_count);
  std::atomic<std::size_t> next_point{0};
  std::atomic<bool> failed{false};
  std::vector<std::string> worker_errors(worker_count);

  auto worker = [&](std::size_t worker_id) {
    EcBatchWorkerContext context(
        base_group, base_order, base_server_scalar);
    if (!context.Ready()) {
      worker_errors[worker_id] = "EC-OPRF worker context allocation failed";
      failed.store(true, std::memory_order_relaxed);
      return;
    }
    while (!failed.load(std::memory_order_relaxed)) {
      const std::size_t index =
          next_point.fetch_add(1, std::memory_order_relaxed);
      if (index >= point_count) return;
      if (!process_point(context, index, &worker_errors[worker_id])) {
        failed.store(true, std::memory_order_relaxed);
        return;
      }
    }
  };

  if (worker_count == 1) {
    worker(0);
  } else {
    std::vector<std::thread> workers;
    workers.reserve(worker_count - 1);
    for (std::size_t worker_id = 1; worker_id < worker_count; ++worker_id) {
      workers.emplace_back(worker, worker_id);
    }
    worker(0);
    for (auto& thread : workers) thread.join();
  }

  if (!failed.load(std::memory_order_relaxed)) return true;
  if (error != nullptr) {
    for (const auto& worker_error : worker_errors) {
      if (!worker_error.empty()) {
        *error = worker_error;
        break;
      }
    }
    if (error->empty()) *error = "EC-OPRF parallel batch failed";
  }
  return false;
}

}  // namespace

const char* OprfImplementationToString(OprfImplementation impl) {
  switch (impl) {
    case OprfImplementation::EcOprf:
      return "EcOprf";
    default:
      return "Unknown";
  }
}

struct EcOprfProvider::Session {
  Session() {
    stats.session_setup_count = 1;
    bn_ctx = BN_CTX_new();
    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    order = BN_new();
    server_scalar = BN_new();
    if (bn_ctx == nullptr || group == nullptr || order == nullptr ||
        server_scalar == nullptr) {
      error = "EC-OPRF session allocation failed";
      return;
    }
    if (EC_GROUP_get_order(group, order, bn_ctx) != 1) {
      error = "EC-OPRF session order initialization failed";
      return;
    }
    stats.server_key_generation_count = 1;
    if (!GenerateRandomNonZeroScalar(order, server_scalar, &error)) {
      return;
    }
    ready = true;
  }

  ~Session() {
    BN_clear_free(server_scalar);
    BN_free(order);
    EC_GROUP_free(group);
    BN_CTX_free(bn_ctx);
  }

  mutable std::mutex mutex;
  BN_CTX* bn_ctx = nullptr;
  EC_GROUP* group = nullptr;
  BIGNUM* order = nullptr;
  BIGNUM* server_scalar = nullptr;
  bool ready = false;
  std::string error;
  OprfSessionStats stats;
};

EcOprfProvider::EcOprfProvider()
    : session_(std::make_shared<Session>()) {}

common::ByteBlock EcOprfProvider::EvaluateServer(
    const common::BinaryFingerprint& input_bits) const {
  {
    std::lock_guard<std::mutex> lock(session_->mutex);
    ++session_->stats.scalar_call_count;
  }
  std::vector<common::ByteBlock> outputs;
  std::string error;
  if (!EvaluateServerBatch({input_bits}, &outputs, &error) ||
      outputs.empty()) {
    return {};
  }
  return outputs.front();
}

common::ByteBlock EcOprfProvider::EvaluateClient(
    const common::BinaryFingerprint& input_bits) const {
  {
    std::lock_guard<std::mutex> lock(session_->mutex);
    ++session_->stats.scalar_call_count;
  }
  std::vector<common::ByteBlock> outputs;
  std::string error;
  if (!EvaluateClientBatch({input_bits}, &outputs, &error) ||
      outputs.empty()) {
    return {};
  }
  return outputs.front();
}

bool EcOprfProvider::EvaluateServerBatch(
    const std::vector<common::BinaryFingerprint>& inputs,
    std::vector<common::ByteBlock>* outputs,
    std::string* error) const {
  if (outputs == nullptr) {
    if (error != nullptr) {
      *error = "null EC-OPRF server batch output";
    }
    return false;
  }

  {
    std::lock_guard<std::mutex> lock(session_->mutex);
    ++session_->stats.batch_call_count;
    session_->stats.total_point_count += inputs.size();
    if (!session_->ready) {
      if (error != nullptr) {
        *error = session_->error;
      }
      return false;
    }
  }

  outputs->assign(inputs.size(), {});
  return RunParallelEcBatch(
      inputs.size(), session_->group, session_->order,
      session_->server_scalar,
      [&](EcBatchWorkerContext& context, std::size_t index,
          std::string* worker_error) {
        return EvaluateServerOne(
            context.group, context.bn_ctx, context.server_scalar,
            inputs[index], &(*outputs)[index], worker_error);
      },
      error);
}

bool EcOprfProvider::EvaluateClientBatch(
    const std::vector<common::BinaryFingerprint>& inputs,
    std::vector<common::ByteBlock>* outputs,
    std::string* error) const {
  if (outputs == nullptr) {
    if (error != nullptr) {
      *error = "null EC-OPRF client batch output";
    }
    return false;
  }
  {
    std::lock_guard<std::mutex> lock(session_->mutex);
    ++session_->stats.batch_call_count;
    session_->stats.total_point_count += inputs.size();
    if (!session_->ready) {
      if (error != nullptr) {
        *error = session_->error;
      }
      return false;
    }
  }

  std::vector<EcOprfBlindRequest> requests;
  std::vector<EcOprfBlindState> states;
  std::vector<EcOprfEvaluatedResponse> responses;
  if (!ClientBlindBatch(inputs, &requests, &states, error) ||
      !ServerEvaluateBatch(requests, &responses, error)) {
    return false;
  }
  std::uint64_t request_bytes = 0;
  for (const auto& request : requests) {
    request_bytes += request.blinded_point_bytes.size();
  }
  std::uint64_t response_bytes = 0;
  for (const auto& response : responses) {
    response_bytes += response.evaluated_point_bytes.size();
  }
  {
    std::lock_guard<std::mutex> lock(session_->mutex);
    session_->stats.blind_request_serialized_bytes += request_bytes;
    session_->stats.evaluated_response_serialized_bytes += response_bytes;
  }
  return ClientFinalizeBatch(states, responses, outputs, error);
}

OprfSessionStats EcOprfProvider::SessionStats() const {
  std::lock_guard<std::mutex> lock(session_->mutex);
  return session_->stats;
}

OprfImplementation EcOprfProvider::Implementation() const {
  return OprfImplementation::EcOprf;
}

bool EcOprfProvider::ClientBlindInput(
    const common::BinaryFingerprint& input_bits,
    EcOprfBlindRequest* request,
    EcOprfBlindState* state,
    std::string* error) const {
  if (request == nullptr || state == nullptr) {
    if (error != nullptr) {
      *error = "null output in ClientBlindInput";
    }
    return false;
  }
  std::vector<EcOprfBlindRequest> requests;
  std::vector<EcOprfBlindState> states;
  if (!ClientBlindBatch({input_bits}, &requests, &states, error)) {
    return false;
  }
  *request = std::move(requests.front());
  *state = std::move(states.front());
  return true;
}

bool EcOprfProvider::ClientBlindBatch(
    const std::vector<common::BinaryFingerprint>& inputs,
    std::vector<EcOprfBlindRequest>* requests,
    std::vector<EcOprfBlindState>* states,
    std::string* error) const {
  if (requests == nullptr || states == nullptr) {
    if (error != nullptr) {
      *error = "null output in ClientBlindBatch";
    }
    return false;
  }
  {
    std::lock_guard<std::mutex> lock(session_->mutex);
    if (!session_->ready) {
      if (error != nullptr) {
        *error = session_->error;
      }
      return false;
    }
  }
  requests->assign(inputs.size(), {});
  states->assign(inputs.size(), {});
  return RunParallelEcBatch(
      inputs.size(), session_->group, session_->order,
      session_->server_scalar,
      [&](EcBatchWorkerContext& context, std::size_t index,
          std::string* worker_error) {
        return BlindOne(
            context.group, context.bn_ctx, context.order, inputs[index],
            &(*requests)[index], &(*states)[index], worker_error);
      },
      error);
}

bool EcOprfProvider::ServerEvaluateBlindedPoint(
    const EcOprfBlindRequest& request,
    EcOprfEvaluatedResponse* response,
    std::string* error) const {
  if (response == nullptr) {
    if (error != nullptr) {
      *error = "null output in ServerEvaluateBlindedPoint";
    }
    return false;
  }
  std::vector<EcOprfEvaluatedResponse> responses;
  if (!ServerEvaluateBatch({request}, &responses, error)) {
    return false;
  }
  *response = std::move(responses.front());
  return true;
}

bool EcOprfProvider::ServerEvaluateBatch(
    const std::vector<EcOprfBlindRequest>& requests,
    std::vector<EcOprfEvaluatedResponse>* responses,
    std::string* error) const {
  if (responses == nullptr) {
    if (error != nullptr) {
      *error = "null output in ServerEvaluateBatch";
    }
    return false;
  }
  {
    std::lock_guard<std::mutex> lock(session_->mutex);
    if (!session_->ready) {
      if (error != nullptr) {
        *error = session_->error;
      }
      return false;
    }
  }
  responses->assign(requests.size(), {});
  return RunParallelEcBatch(
      requests.size(), session_->group, session_->order,
      session_->server_scalar,
      [&](EcBatchWorkerContext& context, std::size_t index,
          std::string* worker_error) {
        return EvaluateBlindedOne(
            context.group, context.bn_ctx, context.server_scalar,
            requests[index], &(*responses)[index], worker_error);
      },
      error);
}

bool EcOprfProvider::ClientUnblindAndDeriveKey(
    const EcOprfBlindState& state,
    const EcOprfEvaluatedResponse& response,
    common::ByteBlock* out,
    std::string* error) const {
  if (out == nullptr) {
    if (error != nullptr) {
      *error = "null output in ClientUnblindAndDeriveKey";
    }
    return false;
  }
  std::vector<common::ByteBlock> outputs;
  if (!ClientFinalizeBatch({state}, {response}, &outputs, error)) {
    return false;
  }
  *out = outputs.front();
  return true;
}

bool EcOprfProvider::ClientFinalizeBatch(
    const std::vector<EcOprfBlindState>& states,
    const std::vector<EcOprfEvaluatedResponse>& responses,
    std::vector<common::ByteBlock>* outputs,
    std::string* error) const {
  if (outputs == nullptr || states.size() != responses.size()) {
    if (error != nullptr) {
      *error = "EC-OPRF finalize batch size mismatch";
    }
    return false;
  }
  {
    std::lock_guard<std::mutex> lock(session_->mutex);
    if (!session_->ready) {
      if (error != nullptr) {
        *error = session_->error;
      }
      return false;
    }
  }
  outputs->assign(states.size(), {});
  return RunParallelEcBatch(
      states.size(), session_->group, session_->order,
      session_->server_scalar,
      [&](EcBatchWorkerContext& context, std::size_t index,
          std::string* worker_error) {
        return FinalizeOne(
            context.group, context.bn_ctx, context.order, states[index],
            responses[index], &(*outputs)[index], worker_error);
      },
      error);
}

}  // namespace ctfpsi::stage1
