#include "stage1/p256_hash_to_curve.hpp"

#include <algorithm>
#include <array>
#include <memory>
#include <stdexcept>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>

namespace ctfpsi::stage1 {
namespace {

void Check(int status) {
  if (status != 1) throw std::runtime_error("P-256 hash-to-curve arithmetic failed");
}

struct BnFrame {
  explicit BnFrame(BN_CTX* value) : ctx(value) { BN_CTX_start(ctx); }
  ~BnFrame() { BN_CTX_end(ctx); }
  BIGNUM* Get() {
    BIGNUM* value = BN_CTX_get(ctx);
    if (!value) throw std::bad_alloc();
    return value;
  }
  BN_CTX* ctx;
};

std::array<std::uint8_t, 32> Hash(const std::vector<std::uint8_t>& bytes) {
  std::array<std::uint8_t, 32> output{};
  if (!SHA256(bytes.data(), bytes.size(), output.data())) {
    throw std::runtime_error("P-256 hash-to-curve SHA-256 failed");
  }
  return output;
}

std::array<std::uint8_t, 96> ExpandXmd(
    const std::vector<std::uint8_t>& message,
    const std::vector<std::uint8_t>& dst) {
  std::vector<std::uint8_t> dst_prime = dst;
  dst_prime.push_back(static_cast<std::uint8_t>(dst.size()));
  std::vector<std::uint8_t> input(64, 0);
  input.insert(input.end(), message.begin(), message.end());
  input.insert(input.end(), {0, 96, 0});
  input.insert(input.end(), dst_prime.begin(), dst_prime.end());
  const auto b0 = Hash(input);
  std::array<std::uint8_t, 32> previous{};
  std::array<std::uint8_t, 96> output{};
  for (std::uint8_t index = 1; index <= 3; ++index) {
    input.assign(b0.begin(), b0.end());
    if (index > 1) {
      for (std::size_t j = 0; j < 32; ++j) input[j] ^= previous[j];
    }
    input.push_back(index);
    input.insert(input.end(), dst_prime.begin(), dst_prime.end());
    previous = Hash(input);
    std::copy(previous.begin(), previous.end(), output.begin() + (index - 1) * 32);
  }
  return output;
}

void Select(BIGNUM* out, const BIGNUM* left, const BIGNUM* right,
            bool choose_right) {
  std::array<std::uint8_t, 32> a{}, b{};
  if (BN_bn2binpad(left, a.data(), 32) != 32 ||
      BN_bn2binpad(right, b.data(), 32) != 32) {
    throw std::runtime_error("P-256 field encoding failed");
  }
  const auto mask = static_cast<std::uint8_t>(0U - static_cast<unsigned>(choose_right));
  for (std::size_t i = 0; i < a.size(); ++i) a[i] ^= (a[i] ^ b[i]) & mask;
  if (!BN_bin2bn(a.data(), 32, out)) throw std::bad_alloc();
}

void MapSswu(const EC_GROUP* group, const BIGNUM* u, const BIGNUM* p,
             const BIGNUM* a, const BIGNUM* b, EC_POINT* output, BN_CTX* ctx) {
  BnFrame frame(ctx);
  BIGNUM *z=frame.Get(), *v=frame.Get(), *den=frame.Get(), *inv=frame.Get();
  BIGNUM *x1=frame.Get(), *x2=frame.Get(), *g1=frame.Get(), *g2=frame.Get();
  BIGNUM *y1=frame.Get(), *y2=frame.Get(), *x=frame.Get(), *y=frame.Get();
  BIGNUM *temp=frame.Get(), *exponent=frame.Get(), *factor=frame.Get();
  BIGNUM *exceptional=frame.Get(), *zero=frame.Get();
  BN_zero(zero);
  Check(BN_set_word(z, 10));
  Check(BN_mod_sub(z, zero, z, p, ctx));
  if (!BN_copy(exponent, p)) throw std::bad_alloc();
  Check(BN_sub_word(exponent, 2));

  // inv0(v^2+v), including u=0, using a fixed public exponent.
  Check(BN_mod_sqr(v, u, p, ctx));
  Check(BN_mod_mul(v, v, z, p, ctx));
  Check(BN_mod_sqr(den, v, p, ctx));
  Check(BN_mod_add(den, den, v, p, ctx));
  Check(BN_mod_exp_mont_consttime(inv, den, exponent, p, ctx, nullptr));
  Check(BN_mod_exp_mont_consttime(factor, a, exponent, p, ctx, nullptr));
  Check(BN_mod_mul(factor, factor, b, p, ctx));
  Check(BN_mod_sub(factor, zero, factor, p, ctx));
  Check(BN_mod_add(x1, inv, BN_value_one(), p, ctx));
  Check(BN_mod_mul(x1, x1, factor, p, ctx));
  Check(BN_mod_mul(temp, z, a, p, ctx));
  Check(BN_mod_exp_mont_consttime(exceptional, temp, exponent, p, ctx, nullptr));
  Check(BN_mod_mul(exceptional, exceptional, b, p, ctx));
  Select(x1, x1, exceptional, BN_is_zero(den));
  Check(BN_mod_mul(x2, v, x1, p, ctx));

  auto curve_rhs = [&](BIGNUM* rhs, const BIGNUM* coordinate) {
    Check(BN_mod_sqr(rhs, coordinate, p, ctx));
    Check(BN_mod_add(rhs, rhs, a, p, ctx));
    Check(BN_mod_mul(rhs, rhs, coordinate, p, ctx));
    Check(BN_mod_add(rhs, rhs, b, p, ctx));
  };
  curve_rhs(g1, x1);
  curve_rhs(g2, x2);
  if (!BN_copy(exponent, p)) throw std::bad_alloc();
  Check(BN_add_word(exponent, 1));
  Check(BN_rshift(exponent, exponent, 2));
  Check(BN_mod_exp_mont_consttime(y1, g1, exponent, p, ctx, nullptr));
  Check(BN_mod_exp_mont_consttime(y2, g2, exponent, p, ctx, nullptr));
  Check(BN_mod_sqr(temp, y1, p, ctx));
  const bool second = BN_cmp(temp, g1) != 0;
  Select(x, x1, x2, second);
  Select(y, y1, y2, second);
  Check(BN_mod_sub(temp, zero, y, p, ctx));
  Select(y, y, temp, BN_is_odd(u) != BN_is_odd(y));
  Check(EC_POINT_set_affine_coordinates(group, output, x, y, ctx));
}

}  // namespace

bool HashToCurveP256(const EC_GROUP* group,
                     const std::vector<std::uint8_t>& message,
                     const std::vector<std::uint8_t>& dst,
                     EC_POINT* output, BN_CTX* context, std::string* error) {
  try {
    if (!group || !output || !context || dst.empty() || dst.size() > 255 ||
        EC_GROUP_get_curve_name(group) != NID_X9_62_prime256v1) {
      throw std::invalid_argument("P-256 hash-to-curve input or domain is invalid");
    }
    BnFrame frame(context);
    BIGNUM *p=frame.Get(), *a=frame.Get(), *b=frame.Get(), *u=frame.Get();
    Check(EC_GROUP_get_curve(group, p, a, b, context));
    const auto uniform = ExpandXmd(message, dst);
    using PointPtr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;
    PointPtr q0(EC_POINT_new(group), EC_POINT_free);
    PointPtr q1(EC_POINT_new(group), EC_POINT_free);
    if (!q0 || !q1) throw std::bad_alloc();
    if (!BN_bin2bn(uniform.data(), 48, u)) throw std::bad_alloc();
    Check(BN_nnmod(u, u, p, context));
    MapSswu(group, u, p, a, b, q0.get(), context);
    if (!BN_bin2bn(uniform.data() + 48, 48, u)) throw std::bad_alloc();
    Check(BN_nnmod(u, u, p, context));
    MapSswu(group, u, p, a, b, q1.get(), context);
    // P-256 has cofactor one: adding the two maps completes hash_to_curve.
    Check(EC_POINT_add(group, output, q0.get(), q1.get(), context));
    Check(EC_POINT_is_on_curve(group, output, context));
    return true;
  } catch (const std::exception& ex) {
    if (error) *error = ex.what();
    return false;
  }
}

}  // namespace ctfpsi::stage1
