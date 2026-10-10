#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <openssl/ec.h>

namespace ctfpsi::stage1 {

// RFC 9380 P256_XMD:SHA-256_SSWU_RO_. DST must contain 1..255 bytes.
bool HashToCurveP256(const EC_GROUP* group,
                     const std::vector<std::uint8_t>& message,
                     const std::vector<std::uint8_t>& dst,
                     EC_POINT* output, BN_CTX* context, std::string* error);

}  // namespace ctfpsi::stage1
